"""
NERD - functions to work with the main task queue (RabbitMQ)

There are two queues for each worker process:
- "normal" queue for tasks added by other components, this has a limit of 100
  tasks.
- "priority" one for tasks added by workers themselves, this has no limit since
  workers mustn't be stopped by waiting for the queue.

These queues are presented as a single one by this wrapper.
The TaskQueueReader first looks into the "priority" queue and only if there
is no task waiting, it reads the normal one.

Tasks are distributed to worker processes (and threads) by hash of the entity
which is to be modified. The destination queue is decided by the message source,
so each source must know how many worker processes are there.


Exchange and queues must be declared externally! (TODO at least check their presence here - but checking presence means to attempt to declare them)


Related configuration keys and their defaults:
(should be part of global NERD config files)

rabbitmq:
  host: localhost
  port: 5672
  virtual_host: /
  username: guest
  password: guest

parallel:
  processes: 1
"""

import json
import time
import logging
import datetime
import collections
import hashlib
import threading
import amqpstorm

# This sets logging level of all components in this file
LOG_LEVEL = logging.INFO
#LOG_LEVEL = logging.DEBUG

# Exchange and queue names
# They must be pre-declared ('direct' exchange type) and binded.
# Numbers from 0 to number_of_workers-1 are used as routing/binding keys.
# TODO: are exchanges needed? Shouldn't we use default exchange and just set queue-name as the routing key?
DEFAULT_EXCHANGE = 'nerd-main-task-exchange'
DEFAULT_PRIORITY_EXCHANGE = 'nerd-priority-task-exchange'
DEFAULT_QUEUE = 'nerd-worker-{}'
DEFAULT_PRIORITY_QUEUE = 'nerd-worker-{}-pri'

# Hash function used to distribute tasks to worker processes. Takes string, returns int.
# (last 4 bytes of MD5)
HASH = lambda x: int(hashlib.md5(x.encode('utf8')).hexdigest()[-4:], 16)

# Maximum number of pending messages per worker process (TODO maybe increase)
# MAX_QUEUE_LENGTH = 100 # Should be defined externally

# When reading, pre-fetch only a limited amount of messages
# (because pre-fetched messages are not counted to queue length limit)
PREFETCH_COUNT = 50


RECONNECT_DELAYS = [1, 2, 5, 10, 30] # number of seconds to wait for the i-th attempt to reconnect after error

# Set up logging if not part of another program (i.e. when testing/debugging)
if __name__ == '__main__':
    #LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s] %(message)s"
    LOGFORMAT = "[%(levelname)s] %(name)s: %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)


# ===== Auxiliary functions =====

# Functions that allow to (de)serialize some objects we need to pass via TaskQueue.
# Inspired by bson.json_util, but for different set of types (and much simpler).
def conv_to_json(obj):
    """Convert special types to JSON (use as "default" param of json.dumps)
    
    Supported types/objects:
    - datetime
    - timedelta
    """
    if isinstance(obj, datetime.datetime):
        if obj.tzinfo:
            raise NotImplementedError("Can't serialize timezone-aware datetime object (NERD policy is to use naive datetimes in UTC everywhere)")
        return {"$datetime": obj.strftime("%Y-%m-%dT%H:%M:%S.%f")}
    if isinstance(obj, datetime.timedelta):
        return {"$timedelta": "{},{},{}".format(obj.days, obj.seconds, obj.microseconds)}
    raise TypeError("%r is not JSON serializable" % obj)


def conv_from_json(dct):
    """Convert special JSON keys created by conv_to_json back to Python objects (use as "object_hook" param of json.loads)
    
    Supported types/objects:
    - datetime
    - timedelta
    """
    if "$datetime" in dct:
        val = dct["$datetime"]
        return datetime.datetime.strptime(val, "%Y-%m-%dT%H:%M:%S.%f")
    if "$timedelta" in dct:
        days, seconds, microseconds = dct["$timedelta"].split(",")
        return datetime.timedelta(int(days), int(seconds), int(microseconds))
    return dct




class RobustAMQPConnection:
    """
    Common TaskQueue wrapper, handles connection to RabbitMQ server with automatic reconnection.
    # TaskQueueWriter and TaskQueueReader are derived from this.
    """
    def __init__(self, rabbit_config={}):
        """
        :param rabbit_config: RabbitMQ connection parameters, dict with following keys (all optional):
            host, port, virtual_host, username, password
        """
        self.log = logging.getLogger('RobustAMQPConnection')
        self.log.setLevel(LOG_LEVEL)
        self.conn_params = {
            'hostname': rabbit_config.get('host', 'localhost'),
            'port': int(rabbit_config.get('port', 5672)),
            'virtual_host': rabbit_config.get('virtual_host', '/'),
            'username': rabbit_config.get('username', 'guest'),
            'password': rabbit_config.get('password', 'guest'),
        }
        self.connection = None
        self.channel = None

    def __del__(self):
        self.disconnect()

    def connect(self):
        """Create a connection (or reconnect after error).

        If connection can't be established, try it again indefinitely.
        """
        if self.connection:
            self.connection.close()
        attempts = 0
        while True:
            attempts += 1
            try:
                self.connection = amqpstorm.Connection(**self.conn_params)
                self.log.debug("AMQP connection created, server: '{hostname}:{port}/{virtual_host}'".format_map(self.conn_params))
                if attempts > 1:
                    # This was a repeated attempt, print success message with ERROR level
                    self.log.error("... it's OK now, we're successfully connected!")

                self.channel = self.connection.channel()
                self.channel.confirm_deliveries()
                self.channel.basic.qos(PREFETCH_COUNT)
                break
            except amqpstorm.AMQPError as e:
                sleep_time = RECONNECT_DELAYS[min(attempts, len(RECONNECT_DELAYS))-1]
                self.log.error("RabbitMQ connection error (will try to reconnect in {}s): {}".format(sleep_time, e))
                time.sleep(sleep_time)
            except KeyboardInterrupt:
                break

    def disconnect(self):
        if self.connection:
            self.connection.close()
        self.connection = None
        self.channel = None


class TaskQueueWriter(RobustAMQPConnection):
    def __init__(self, workers=1, rabbit_config={}, exchange=DEFAULT_EXCHANGE, priority_exchange=DEFAULT_PRIORITY_EXCHANGE):
        """
        Create an object for writing tasks into the main Task Queue.

        :param workers: Number of worker processes in the system
        :param rabbit_config: RabbitMQ connection parameters, dict with following keys (all optional):
            host, port, virtual_host, username, password
        :param exchange: Name of the exchange to write tasks to
        :param priority_exchange: Name of the exchange to write priority tasks to
        """
        assert isinstance(workers, int) and workers >= 1
        assert isinstance(exchange, str)
        assert isinstance(priority_exchange, str)

        super().__init__(rabbit_config)

        self.log = logging.getLogger('TaskQueueWriter')
        self.log.setLevel(LOG_LEVEL)

        self.workers = workers
        self.exchange = exchange
        self.exchange_pri = priority_exchange

    def put_task(self, etype, eid, requested_changes, src, priority=False):
        """Put task (update_request) to the queue of corresponding worker"""
        if not self.channel:
            self.connect()

        # Prepare message and routing key
        msg = {
            'etype': etype,
            'eid': eid,
            'op': requested_changes,
            'src': src
        }
        body = json.dumps(msg, default=conv_to_json).encode('utf8')
        key = etype + ':' + str(eid)
        routing_key = HASH(key) % self.workers  # index of the worker to send the task to

        exchange = self.exchange_pri if priority else self.exchange

        # Send the message
        # ('mandatory' flag means that we want to guarantee it's delivered to someone. If it can't be delivered (no
        #  consumer or full queue), wait a while and try again. Always print just one error message for each
        #  unsuccessful message to be send.)
        self.log.debug("Sending a task with routing_key={} to exchange '{}'".format(routing_key, exchange))
        err_printed = 0
        while True:
            try:
                message = amqpstorm.Message.create(self.channel, body)
                success = message.publish(str(routing_key), exchange, mandatory=True)
                if success: # message ACK'd
                    if err_printed == 1:
                        self.log.debug("... it's OK now, the message was successfully sent")
                    elif err_printed == 2:
                        self.log.warning("... it's OK now, the message was successfully sent")
                    else:
                        self.log.debug("Message successfully sent")
                    break
                else: # message NACK'd
                    if err_printed != 1:
                        self.log.debug("Message rejected (queue of worker {} is probably full), will retry every 100ms".format(routing_key))
                        err_printed = 1
                    time.sleep(0.1)
            except amqpstorm.AMQPChannelError as e:
                if err_printed != 2:
                    self.log.warning("Can't deliver a message to worker {} (will retry every 5 seconds): {}".format(routing_key, e))
                    err_printed = 2
                time.sleep(5)
            except amqpstorm.AMQPConnectionError as e:
                self.log.error("RabbitMQ connection error (will try to reconnect): {}".format(e))
                self.connect()


class TaskQueueReader(RobustAMQPConnection):
    def __init__(self, callback, worker_index=0, rabbit_config={}, queue=DEFAULT_QUEUE, priority_queue=DEFAULT_PRIORITY_QUEUE):
        """
        Create an object for reading tasks from the main Task Queue.

        It consumes messages from two RabbitMQ queues (normal and priority one for given worker) and passes them to
        the given callback function. Tasks from the priority queue are passed before the normal ones.

        Each received message must be acknowledged by calling .ack(msg_tag).

        :param callback: Function called when a message is received, prototype: func(msg_tag, etype, eid, ops)
        :param worker_index: index of this worker (filled into DEFAULT_QUEUE string using .format() method)
        :param rabbit_config: RabbitMQ connection parameters, dict with following keys (all optional):
            host, port, virtual_host, username, password
        :param queue: Name of RabbitMQ queue to read from (should contain "{}" to fill in worker_index)
        :param priority_queue: Name of RabbitMQ queue to read from (priority messages) (should contain "{}" to fill in worker_index)
        """
        assert callable(callback)
        assert isinstance(worker_index, int) and worker_index >= 0
        assert isinstance(queue, str)
        assert isinstance(priority_queue, str)

        super().__init__(rabbit_config)

        self.log = logging.getLogger('TaskQueueReader')
        self.log.setLevel(LOG_LEVEL)

        self.callback = callback
        self.queue_name = queue.format(worker_index)
        self.priority_queue_name = priority_queue.format(worker_index)

        self.running = False

        self._consuming_thread = None
        self._processing_thread = None

        # Receive messages into 2 temporary queues (max length should be equal to prefetch_count set in RabbitMQReader)
        self.cache = collections.deque()
        self.cache_pri = collections.deque()
        self.cache_full = threading.Event()  # signalize there's something in the cache


    def __del__(self): #TODO is this needed?
        self.log.debug("Destructor called")
        self._stop_consuming_thread()
        self._stop_processing_thread()
        super().__del__()


    def start(self):
        """Start receiving tasks."""
        if self.running:
            raise RuntimeError("Already running")

        if not self.connection:
            self.connect()

        self.log.info("Starting TaskQueueReader")

        # Start thread for message consuming from server
        self._consuming_thread = threading.Thread(None, self._consuming_thread_func)
        self._consuming_thread.start()

        # Start thread for message processing and passing to user's callback
        self.running = True
        self._processing_thread = threading.Thread(None, self._msg_processing_thread_func)
        self._processing_thread.start()


    def stop(self):
        """Stop receiving tasks."""
        if not self.running:
            raise RuntimeError("Not running")

        self._stop_consuming_thread()
        self._stop_processing_thread()
        self.log.info("TaskQueueReader stopped")


    def ack(self, msg_tag):
        """Acknowledge processing of the message/task

        :param msg_tag: Message tag received as the first param of the callback function.
        """
        self.channel.basic.ack(delivery_tag=msg_tag)


    def _consuming_thread_func(self):
        # Register consumers and start consuming loop, reconnect on error
        while True:
            try:
                # Register consumers on both queues
                self.channel.basic.consume(self._on_message, self.queue_name, no_ack=False)
                self.channel.basic.consume(self._on_message_pri, self.priority_queue_name, no_ack=False)
                # Start consuming (this call blocks until consuming is stopped)
                self.channel.start_consuming()
                return
            except amqpstorm.AMQPConnectionError as e:
                self.log.error("RabbitMQ connection error (will try to reconnect): {}".format(e))
                self.connect()

    # These two callbacks are called when a new message is received - they only put the message into a local queue
    def _on_message(self, message):
        self.cache.append(message)
        self.cache_full.set()

    def _on_message_pri(self, message):
        self.cache_pri.append(message)
        self.cache_full.set()


    def _msg_processing_thread_func(self):
        # Reads local queues and passes tasks to the user callback.
        while self.running:
            # Get task from a local queue (try the priority one first)
            if len(self.cache_pri) > 0:
                msg = self.cache_pri.popleft()
                pri = True
            elif len(self.cache) > 0:
                msg = self.cache.popleft()
                pri = False
            else:
                self.cache_full.wait()
                self.cache_full.clear()
                continue

            body = msg.body
            tag = msg.delivery_tag

            self.log.debug("Received {}message: {} (tag: {})".format("priority " if pri else "", body, tag))

            # Parse and check validity of received message
            try:
                task = json.loads(body, object_hook=conv_from_json)
                etype = task['etype']
                eid = task['eid']
                op = task['op']
                src = task['src']
            except (ValueError, TypeError, KeyError) as e:
                # Print error, acknowledge reception of the message and drop it
                self.log.error("Erroneous message received from main task queue. Error: {} ({}), Message: '{}'".format(str(type(e)), str(e), body))
                self.ack(tag)
                continue

            # Pass message to user's callback function
            self.callback(tag, etype, eid, op, src)

    def _stop_consuming_thread(self):
        if self._consuming_thread:
            if self._consuming_thread.is_alive:
                try:
                    self.channel.stop_consuming()
                except amqpstorm.AMQPError as e:
                    pass  # not connected or error - no problem here
            self._consuming_thread.join()
        self._consuming_thread = None

    def _stop_processing_thread(self):
        if self._processing_thread:
            if self._processing_thread.is_alive:
                self.running = False  # tell processing thread to stop
                self.cache_full.set()  # break potential wait() for data
            self._processing_thread.join()
        self._processing_thread = None


