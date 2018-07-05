"""
NERD - functions to work with the main task queue (RabbitMQ)

RabbitMQ plug-in "Consistent Hash Exchange Type" must be installed
(exchange of the type 'x-consistent-hash' is used to distribute tasks to workers)

Related configuration keys and their defaults:
(should be part of global NERD config files)

rabbitmq:
  host: localhost
  port: 5672
  virtual_host: /
  username: guest
  password: guest
"""

import sys
import json
import time
import logging
import pika
from bson import json_util # Used to (de)serialize some Python objects (like datetime) into JSON

# Exchange to write messages to
WRITE_EXCHANGE_NAME = 'nerd-main-task-exchange'
READ_EXCHANGE_NAME = 'nerd-task-distributor'

# Maximum number of pending messages per worker
MAX_QUEUE_LENGTH = 100

class TaskQueue:
    def __init__(self, rabbit_config={}):
        """
        Create an object representing the queue.
        
        exchange - name of RabbitMQ exchange used
        rabbit_config - dict containing RabbitMQ configuration
            (keys: host, port, virtual_host, username, password)
        """
        self.log = logging.getLogger('TaskQueue')
        self.log.setLevel(logging.INFO)
        # Get parameters
        host = rabbit_config.get('host', 'localhost')
        port = int(rabbit_config.get('port', 5672))
        vhost = rabbit_config.get('virtual_host', '/')
        username = rabbit_config.get('username', 'guest')
        password = rabbit_config.get('password', 'guest')
        creds = pika.PlainCredentials(username, password)
        self.rabbit_params = pika.ConnectionParameters(host, port, vhost, creds)

        self.connect()

        # Disable pika warnings (which are printed when published message is refused by broker)
        logging.getLogger("pika").setLevel(logging.ERROR)
    
    def connect(self):
        """Connecto to RabbitM server and prepare a channel"""
        self.conn = pika.BlockingConnection(self.rabbit_params)
        # TODO handle possible errors (like server not running)
        self.channel = self.conn.channel()
        # Declare the exchange (type is 'x-consistent-hash', a plugin have to be installed)
        #self.channel.exchange_declare(WRITE_EXCHANGE_NAME, 'x-consistent-hash', durable=True)
        # Enable delivery confirmation (to allow detection of no consumers or full queue)
        self.channel.confirm_delivery()
        # When reading, pre-fetch only a limited amount of messages (one)
        # (because pre-fetched messages are not counted to queue length limit)
        self.channel.basic_qos(prefetch_count=1)
        
    
    def __del__(self):
        if not self.channel.connection.is_closed:
            self.channel.close()
    
    def put_update_request(self, etype, eid, requested_changes):
        """Put update request into the queue"""
        # Prepare message and routing key
        msg = {
           'etype': etype,
           'eid': eid,
           'op': requested_changes
        }
        # Use json_util from MongoDB's BSON to serialize some Python objects (like datetime) into JSON
        body = json.dumps(msg, default=json_util.default).encode('utf8')
        key = etype + ':' + str(eid)
        
        # Send the message
        # 'mandatory' flag means that we want to guarantee it's delivered to
        # someone. If it can't be delivered (no consumer or full queue),
        # wait a while and try again. Always print just one error message
        # for each unsucessful message to be send.
        err_printed = False
        while True:
            try:
                self.channel.publish(WRITE_EXCHANGE_NAME, key, body, mandatory=True)
                if err_printed == 1:
                    self.log.warning("It's OK now, the message was sucessfully sent")
                elif err_printed == 2:
                    self.log.info("It's OK now, the message was sucessfully sent")
                else:
                    self.log.debug("Message sucessfully sent")
                break
            except pika.exceptions.UnroutableError:
                if err_printed != 1:
                    self.log.warning("Can't deliver a message (no route, there's probably no worker running), will retry every 5 seconds")
                    err_printed = 1
                time.sleep(5)
            except pika.exceptions.NackError:
                if err_printed != 2:
                    self.log.info("Can't deliver a message (refused, worker queue is probably full), will retry every second")
                    err_printed = 2
                time.sleep(1)
            except pika.exceptions.ConnectionClosed:
                self.log.warning("Connection to RabbitMQ server lost, reconnecting ...")
                self.connect()


    def set_consume_callback(self, callback, process_index, thread_index):
        """
        Set function to be called upon receive of a task.
        
        callback - func with signature: func(etype, eid, update_requests)
        """
        # An auxiliary function
        def _aux_callback(channel, method, properties, body):
            # TODO check that method and properties are as expected (but what is expected?)
            # Basic check of the message body
            try:
                msg = json.loads(body.decode('utf8'), object_hook=json_util.object_hook)
                etype = msg['etype']
                eid = msg['eid']
                op = msg['op']
            except (json.decoder.JSONDecodeError, TypeError, KeyError):
                # Print error, acknowledge reception of the message and drop it
                self.log.error("Erroneous message received from main task queue: '{}'".format(body))
                self.channel.basic_ack(method.delivery_tag)
                return
            self.consume_callback(etype, eid, op)
            self.channel.basic_ack(method.delivery_tag)

        self.consume_callback = callback

        # Create a queue and bind it to the hashing exchange
        q_name = 'nerd-worker-{}-{}'.format(process_index, thread_index)
        params = {'x-max-length': MAX_QUEUE_LENGTH, 'x-overflow': 'reject-publish'}
        while True:
            try:
                self.channel.queue_declare(q_name, durable=True, arguments=params)
                self.channel.queue_bind(q_name, READ_EXCHANGE_NAME, "10") # see docs of "Consistent Hash Exchange Type" plug-in to understand that magic number
                # Set callback function to consume messages
                self.channel.basic_consume(_aux_callback, q_name, exclusive=True)
                break
            except pika.exceptions.ConnectionClosed:
                self.log.warning("Connection to RabbitMQ server lost, reconnecting ...")
                self.connect()

    def start_consuming(self):
        """Start consuming tasks (blocking call)"""
        while True:
            try:
                self.channel.start_consuming()
                break
            except pika.exceptions.ConnectionClosed:
                self.log.warning("Connection to RabbitMQ server lost, reconnecting ...")
                self.connect()

    def stop_consuming(self):
        """
        Stop consuming tasks (need to be called asynchronously)
        
        After consuming is stopped, the callback must be set up again before
        consuming can be started again
        """
        while True:
            try:
                self.channel.stop_consuming()
                break
            except pika.exceptions.ConnectionClosed:
                self.log.warning("Connection to RabbitMQ server lost, reconnecting ...")
                self.connect()

    
    def get_worker_queue_length(self, process_index, thread_index):
        """Return queue length of given worker (or None if queue doesn't exist)"""
        q_name = 'nerd-worker-{}-{}'.format(process_index, thread_index)
        # We need to re-declare the same queue (with passive=True, so it actually just check its existence),
        # the reply will contain the number of messsages queued
        params = {'x-max-length': MAX_QUEUE_LENGTH, 'x-overflow': 'reject-publish'}
        res = self.channel.queue_declare(q_name, durable=True, arguments=params, passive=True)
        return res.method.message_count
