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

import pika
import pika.exceptions

# This sets logging level of all component in this file
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
PREFETCH_COUNT = 2


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


# Decorator for RabbitMQ wrappers to retry a method that may fail due to broken connection
def reconnect_and_retry_on_error(func):
    def wrapper(self, *args, **kwargs):
        sleep_time = 1
        while True:
            try:
                return func(self, *args, **kwargs)
            except (pika.exceptions.AMQPConnectionError, pika.exceptions.AMQPChannelError) as e:
                # pass Unroutable or Nack errors to upper layer, since reconnection is not needed in such case
                if isinstance(e, (pika.exceptions.UnroutableError, pika.exceptions.NackError)):
                    raise
                self.log.error("RabbitMQ connection error (will try to reconnect): {!r}\n".format(e))
                self.close_connection()
                time.sleep(sleep_time)
                sleep_time = min(sleep_time + 2, 10)
                self.connect()
                self.log.error("Successfully reconnected!\n")
    return wrapper


# ===== Writer =====

# Writer is implemented using BlockingConnection, as it's much easier.
# There is a problem with BlockingConnection that the connection can time-out
# when no message is send for a long time - but this can be easily solved
# by automatic reconnect.

class RabbitMQWriter:
    """Wrapper of pika BlockingConnection with automatic reconnect on connection error"""
    
    def __init__(self, rabbit_config={}):
        self.log = logging.getLogger('RabbitMQWriter')
        self.log.setLevel(LOG_LEVEL)

        self._connection = None
        self._channel = None

        # Get parameters
        host = rabbit_config.get('host', 'localhost')
        port = int(rabbit_config.get('port', 5672))
        vhost = rabbit_config.get('virtual_host', '/')
        username = rabbit_config.get('username', 'guest')
        password = rabbit_config.get('password', 'guest')
        creds = pika.PlainCredentials(username, password)
        self.rabbit_params = pika.ConnectionParameters(host, port, vhost, creds)
        
        self.log.debug("RabbitMQWriter created, server: '{}:{}/{}'".format(host, port, vhost))

        # Disable pika warnings (which are printed when published message is refused by broker)
        logging.getLogger("pika").setLevel(logging.ERROR)
    
    def connect(self):
        """Attempt to connect to RabbitMQ server. Retry on error with increasing delay between attempts."""
        if (self._connection is not None and self._channel is not None and
            self._connection.is_open and self._channel.is_open):
            self.log.debug("connect() called, but connection is already opened.")
            return # Already connected
        
        # Turn off logging of pika errors so they don't flood the log (comment this out if debugging a connection problem)
        logging.getLogger("pika").setLevel(logging.CRITICAL)
        
        sleep_time = 1
        while True:
            try:
                self._connection = pika.BlockingConnection(self.rabbit_params)
                self._channel = self._connection.channel()
                self._channel.confirm_delivery()
                break
            except (pika.exceptions.AMQPConnectionError, pika.exceptions.AMQPChannelError) as e:
                self.log.error("Can't connect to RabbitMQ server (will retry in {}s): {!r}\n".format(sleep_time, e))
                time.sleep(sleep_time)
                sleep_time = min(sleep_time + 2, 10)
                continue
        
        # Re-enable logging of pika errors
        logging.getLogger("pika").setLevel(logging.ERROR)
        
        if sleep_time > 1: # there was an error, report success with "error" level
            self.log.error("Connected!")
        self.log.debug("Connected to RabbitMQ server")
        
    
    def close_connection(self):
        if self._connection and not self._connection.is_closed:
            try:
                self._connection.close()
            except pika.exceptions.AMQPConnectionError: # for case it's been already closed by the server
                pass
        self._connection = None
        self._channel = None
    
    @reconnect_and_retry_on_error
    def publish(self, exchange, routing_key, body, **kwargs):
        if self._channel is None:
            self.connect()
        self._channel.basic_publish(exchange, routing_key, body, **kwargs)
    

class TaskQueueWriter:
    # Must know total number of workers
    # Not thread safe - each thread must have its own instance
    def __init__(self, rabbit_config={}, workers=1, exchange=DEFAULT_EXCHANGE, priority_exchange=DEFAULT_PRIORITY_EXCHANGE):
        self.log = logging.getLogger('TaskQueueWriter')
        self.log.setLevel(LOG_LEVEL)

        self.workers = workers # total number of worker processes in the system
        self.exchange = exchange
        self.exchange_pri = priority_exchange

        self.rmq_writer = RabbitMQWriter(rabbit_config)

    def connect(self):
        """
        Connect to the server.
        
        Can be called after init to test connection, but it's also connected 
        automatically when first trying to send message.
        """
        self.rmq_writer.connect()

    def __del__(self):
        self.rmq_writer.close_connection()

    def put_task(self, etype, eid, requested_changes, priority=False):
        """Put task (update_request) to the queue of corresponding worker"""
        # Prepare message and routing key
        msg = {
           'etype': etype,
           'eid': eid,
           'op': requested_changes
        }
        body = json.dumps(msg, default=conv_to_json).encode('utf8')
        key = etype + ':' + str(eid)
        routing_key = HASH(key) % self.workers # index of the worker to send the task to
        
        exchange = self.exchange_pri if priority else self.exchange
        
        # Send the message
        # ('mandatory' flag means that we want to guarantee it's delivered to
        #  someone. If it can't be delivered (no consumer or full queue),
        #  wait a while and try again. Always print just one error message
        #  for each unsuccessful message to be send.)
        # (connection problems are handled inside rmw_writer)
        self.log.debug("Sending a task with routing_key={} to exchange '{}'".format(routing_key, exchange))
        err_printed = 0
        while True:
            try:
                self.rmq_writer.publish(exchange, str(routing_key), body, mandatory=True)
                if err_printed == 1:
                    self.log.warning("It's OK now, the message was successfully sent")
                elif err_printed == 2:
                    self.log.info("It's OK now, the message was successfully sent")
                else:
                    self.log.debug("Message successfully sent")
                break
            except pika.exceptions.UnroutableError:
                if err_printed != 1:
                    self.log.warning("Can't deliver a message (no route, worker {} is probably not running), will retry every 5 seconds".format(routing_key))
                    err_printed = 1
                time.sleep(5)
            except pika.exceptions.NackError:
                if err_printed != 2:
                    self.log.info("Can't deliver a message (refused, queue of worker {} is probably full), will retry every second".format(routing_key))
                    err_printed = 2
                time.sleep(1)


# ===== Reader =====

class RabbitMQReader:
    """
    Wrapper around pika SelectConnection (asynchronous client).
    
    Supports consuming from multiple queues.
    Automatically reconnects on error.
    IOLoop runs in a separate thread.
    
    Public methods:
    - set_consumers() - set up which queues we should listen to and which function to call
    - start() - connect, create a channel, run ioloop thread, start consumers
    - stop() - stop all active consumers and disconnect
    """

    ##### Public methods #####

    def __init__(self, rabbit_config={}):
        self.log = logging.getLogger('RabbitMQReader')
        self.log.setLevel(LOG_LEVEL)
        
        self.autoreconnect = True
        
        self.connection_state = None
        # possible states:
        # - None (not connected)
        # - 'connecting' (creating connection and channel)
        # - 'connected' (channel created, ioloop running)
        # - 'disconnecting' (stopping channel and connection)
        # - 'error' (connection was closed unexpectedly, reconnect should be attempted)

        self._connection = None
        self._channel = None
        self._thread = None
        
        self._reconnect_counter = 0 # number of reconnection attempts since last sucessful connection

        self._event_stop_wait = threading.Event() # used to interrupt the reconnection delay by calling stop()

        # consumers set up by set_consumers method, map: queue_name->callback_function
        self.consumers = {}

        self._active_consumers = 0

        
        # Get RabbitMQ connection parameters
        host = rabbit_config.get('host', 'localhost')
        port = int(rabbit_config.get('port', 5672))
        vhost = rabbit_config.get('virtual_host', '/')
        username = rabbit_config.get('username', 'guest')
        password = rabbit_config.get('password', 'guest')
        creds = pika.PlainCredentials(username, password)
        self.rabbit_params = pika.ConnectionParameters(host, port, vhost, creds)
        
        self.log.debug("RabbitMQReader created, server: '{}:{}/{}'".format(host, port, vhost))

        # Disable pika warnings (which are printed when published message is refused by broker)
        logging.getLogger("pika").setLevel(logging.ERROR)


    def set_consumers(self, queue_callback_map):
        """
        Set which queues the reader should bind to.
        
        Pass a mapping (dict) queue_name->callback_function.
        
        Callback must have type "func(body, tag)"
        
        Must be called before start().
        """
        if self.connection_state is not None:
            self.log.warning("set_consumers() called while reader is running, it won't take effect until next re-connection.")
        # TODO check types
        self.consumers = queue_callback_map


    def start(self, autoreconnect=True):
        """
        Connect to RabbitMQ server and start message processing.
        
        All processing runs asynchronously in a new thread.
        Automatically reconnects on error.
        """
        # Create connection and channel (run IOLoop in a separate thread)
        if self._thread is not None: #self.connection_state != None:
            self.log.warning('start() called, but connection already established (state: {})'.format(self.connection_state))
            return        
        
        self.autoreconnect = autoreconnect
        
        self.log.debug("Starting separate thread")
        self._thread = threading.Thread(None, self._reconnecting_ioloop, daemon=True)
        self._thread.start()


    def stop(self):
        """Stop communication and disconnect from RabbitMQ server"""
        if self._thread is None:
            self.log.warning('stop() called, but the ioloop thread is not running')
            return

        if self.connection_state == 'error':
            # We're in error state, which means connection is closed and we are trying to reconnect.
            # Reset the state to signal that no more reconnect should be attempted.
            self.connection_state = None
            # interrupt waiting in the reconnection routine
            self._event_stop_wait.set()
        else:
            # Normal shutdown from 'connected' (or 'connecting'/'disconnecting') state
            # -> signal this is intended close and close the connection
            self.connection_state = 'disconnecting'

            self.log.debug("Disconnecting")
            if self._connection.is_open:
                self._connection.close()
            else:
                self.log.debug('stop(): connection already closed (unexpectedly)')
        
        # Wait for the thread to finish
        #self._connection.ioloop.stop() # it should already be stopped by _on_connection_close callback
        self._thread.join()
        self._reset()

    
    def ack(self, tag):
        """Acknowledge processing of message with given delivery tag"""
        if self._channel:
            self._channel.basic_ack(tag)
    
    def _reset(self):
        """Reset object state"""
        self._thread = None
        self._connection = None
        self._channel = None
        self.connection_state = None
        self._reconnect_counter = 0
        self._event_stop_wait = threading.Event()
        self._active_consumers = 0


    ##### Auxiliary methods and callbacks related to *connection* #####

    def _reconnecting_ioloop(self):
        while True:
            self.connection_state = 'connecting'
            if self._reconnect_counter == 0:
                self.log.debug("Connecting ...")
            else:
                self.log.info("Reconnecting ...")
            
            self._connection = pika.SelectConnection(
                parameters=self.rabbit_params,
                on_open_callback=self._on_connection_open,
                on_open_error_callback=self._on_connection_open_error,
                on_close_callback=self._on_connection_closed
            )
            self._connection.ioloop.start() # this blocks here and calls various callback functions below

            self.log.debug("ioloop exited (status: {})".format(self.connection_state))

            if self.connection_state == 'error' and self.autoreconnect:
                # unwanted exit -> reconnect
                delay = RECONNECT_DELAYS[min(self._reconnect_counter, len(RECONNECT_DELAYS)-1)]
                self._reconnect_counter += 1
                
                self.log.info("Will try to reconnect in {} seconds".format(delay))
                # Wait for 'delay' seconds or until stop() is called (which sets the _event_stop_wait Event)
                self._event_stop_wait.wait(delay)
                
                # check if disconnect was requested while waiting
                if self.connection_state is None:
                    self.log.info("stop() called - reconnection cancelled, exiting.")
                    break
                continue
            else:
                self._reset()
                break


    def _on_connection_open(self, _unused_connection):
        """Called once the connection to RabbitMQ has been established. Creates a channel."""
        self.log.debug('Connection opened, creating a channel')
        self._connection.channel(on_open_callback=self._on_channel_open)

    def _on_connection_open_error(self, _unused_connection, err):
        """Called if the connection to RabbitMQ can't be established."""
        self.log.error("RabbitMQ connection failed: {}".format(err))
        self.connection_state = 'error'
        self._connection.ioloop.stop() # reconnect will be attempted automatically if state is 'error'


    def _on_channel_open(self, channel):
        """Called when the channel has been opened."""
        self.log.debug('Channel opened')
        self._channel = channel
        self._channel.add_on_close_callback(self._on_channel_closed)
        self._channel.basic_qos(prefetch_count=PREFETCH_COUNT)
        self.connection_state = 'connected'
        # Register previously defined consumers and start consuming
        if self.consumers:
            self._register_consumers()
        else:
            self._reconnect_counter = 0 
            self.log.info('Successfully connected to RabbitMQ (no consumers registered!)')
        
    def _on_channel_closed(self, _unused_channel, reason):
        """Called when RabbitMQ unexpectedly closes the channel.
        Channels are usually closed if you attempt to do something that
        violates the protocol, such as re-declare an exchange or queue with
        different parameters. In this case, we'll close the connection
        to shutdown the object.
        """
        if self.connection_state == 'disconnecting':
            self.log.debug('Channel closed')
        else:
            self.log.error('Channel closed unexpectedly: %s', reason)
            if not (self._connection.is_closed or self._connection.is_closing):
                # close connection if it isn't closed/closing as well
                self._connection.close()


    def _on_connection_closed(self, _unused_connection, reason):
        """Called when the connection to RabbitMQ is closed unexpectedly.
        Since it is unexpected, we will reconnect to RabbitMQ if it disconnects.
        
        connection: the closed connection obj
        reason: exception representing reason for loss of connection.
        """
        if self.connection_state == 'disconnecting':
            # intended close invoked by stop()
            self.log.debug('Connection closed')
            self.connection_state = None
            self._reconnect_counter = 0
        else:
            # disconnected due to an error or force-close -> automatic reconnect should be attempted
            self.log.error('Connection closed unexpectedly: %s', reason)
            self.connection_state = 'error'
        
        self._connection.ioloop.stop()
        self._connection = None
        self._channel = None


    ##### Methods related to message *consuming* #####

    def _register_consumers(self):
        # Add callback for case RabbitMQ cancels the consumer
        self._channel.add_on_cancel_callback(self._on_consumer_cancelled)
        
        # Register all consumers as defined previously by set_consumers method
        self._active_consumers = 0
        for queue, callback in self.consumers.items():
            self.log.debug("Starting consuming from RabbitMQ queue '{}'".format(queue))
            self._channel.basic_consume(queue, self._wrap_callback(callback), exclusive=True, callback=self._consume_ok)

    # Note: _cancel_consumers(self) not needed, they're cancelled automatically when connection is closed
            
    def _wrap_callback(self, callback):
        def on_message(_unused_channel, basic_deliver, properties, body):
            self.log.debug('Received message # %s from %s: %s', basic_deliver.delivery_tag, properties.app_id, body)
            callback(body, basic_deliver.delivery_tag)
        return on_message

    def _consume_ok(self,_unused_frame):
        self._active_consumers += 1
        # If the last consumer was ack'd, mark connection as successful
        if self._active_consumers == len(self.consumers):
            self._reconnect_counter = 0 
            self.log.info('Successfully connected to RabbitMQ and registered {} consumer{}'.format(self._active_consumers, 's' if self._active_consumers != 1 else ''))


    def _on_consumer_cancelled(self, _unused_method_frame):
        self.log.error("Consumer was cancelled remotely, will try to reset ...")
        # Close connection (automatic reconnection should be attempted automatically)
        if not (self._connection.is_closed or self._connection.is_closing):
            self.connection_state = 'error'
            self._connection.close()



class TaskQueueReader:
    def __init__(self, callback, worker_index=0, rabbit_config={}, queue=DEFAULT_QUEUE, priority_queue=DEFAULT_PRIORITY_QUEUE, auto_acknowledge=False):
        """
        Helper object for reading from the main TaskQueue (RabbitMQ).
        
        :param callback: Function called when a message is received, prototype: func(msg_id, etype, eid, ops)
        :param worker_index: index of this worker (filled into DEFAULT_QUEUE string using .format() method)
        :param rabbit_config: dict containing RabbitMQ configuration
            (keys: host, port, virtual_host, username, password)
        :param queue: Name of RabbitMQ queue to read from (should contain "{}" to fill in worker_index)
        :param priority_queue: Name of RabbitMQ queue to read from (priority messages) (should contain "{}" to fill in worker_index)
        """
        self.log = logging.getLogger('TaskQueueReader')
        self.log.setLevel(LOG_LEVEL)
        
        self.callback = callback
        self.running = False

        self.auto_ack = auto_acknowledge

        self.queue = queue.format(worker_index)
        self.queuep = priority_queue.format(worker_index)

        # Receive messages into a temporary queue (max length should be equal to prefetch_count set in RabbitMQReader)
        self.cache = collections.deque()
        self.cachep = collections.deque()
        self.cache_full = threading.Event() # signalize there's something in the cache
        
        # Initialize RabbitMQReader connection 
        self.rmqr = RabbitMQReader(rabbit_config)
        self.rmqr.set_consumers({
            self.queue: self._on_message,
            self.queuep: self._on_message_pri,
        })


    def start(self):
        """
        Start consuming messages. Calls given callback every time a message is received.
        
        If there is a task in the priority queue, it's passed to the callback,
        only if there's none, a task from normal queue is read and passed.
        """
        if self.running:
            raise RuntimeError("TaskQueueReader already running")
        self.running = True
        self._thread = threading.Thread(None, self._select_message_thread)
        self._thread.start()
        self.rmqr.start()
        self.log.info("TaskQueueReader started")

    def ack_msg(self, msg_id):
        """
        Acknowledge processing of message with given ID.

        :param msg_id: ID of the message, as received in the registered callback
        """
        if self.auto_ack:
            raise RuntimeError("TaskQueueReader: You can't call ack_msg() when auto_acknowledge is enabled.")
        # Signalize to RabbitMQ that the message was processed
        self.rmqr.ack(msg_id)


    def stop(self):
        """Stop consuming messages"""
        # first stop select-message thread; it's OK if rmqr pre-fetch some more events, but they won't be acked
        # (rmqr must remain running so the currently processed message can be acked)
        if not self.running:
            raise RuntimeError("TaskQueueReader not running")
        self.running = False # tell the thread to stop
        self.cache_full.set() # break waiting in the thread if needed
        self._thread.join() # wait until the thread finishes
        self.rmqr.stop()
        self.cache.clear()
        self.cachep.clear()
        self.log.info("TaskQueueReader stopped")


    # These two callbacks are called by RabbitMQReader's thread when a new message is received
    def _on_message(self, body, tag):
        self.cache.append((body, tag))
        self.cache_full.set()

    def _on_message_pri(self, body, tag):
        self.cachep.append((body, tag))
        self.cache_full.set()


    # This runs in a separate thread
    # Reads messages from caches, calls the user's callback and then acks the message to RMQ
    def _select_message_thread(self):
        while self.running:
            # Get task from a queue
            if len(self.cachep) > 0:
                msg,tag = self.cachep.popleft()
                pri = True
            elif len(self.cache) > 0:
                msg,tag = self.cache.popleft()
                pri = False
            else:
                self.cache_full.wait()
                self.cache_full.clear()
                continue
        
            self.log.debug("Received {}message: {}".format("priority " if pri else "", msg))

            # Parse and check validity of received message
            try:
                msg = json.loads(msg.decode('utf8'), object_hook=conv_from_json)
                etype = msg['etype']
                eid = msg['eid']
                op = msg['op']
            except (ValueError, TypeError, KeyError) as e:
                # Print error, acknowledge reception of the message and drop it
                self.log.error("Erroneous message received from main task queue. Error: {}, Message: '{}'".format(str(e), msg))
                self.rmqr.ack(tag)
                return
            # Pass message to user's callback function
            self.callback(tag, etype, eid, op)
            # If automatic acknowledge is enabled, signalize it was processed immediately after callback returns
            if self.auto_ack:
                self.rmqr.ack(tag)

