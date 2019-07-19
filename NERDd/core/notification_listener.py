"""
NotificationListener can be used in modules for listening in channels for certain notifications. For subscribing
in some channel for notifications just initialize NotificationListener and call .start()

Example, which can be called in module's __init__():
    notification_settings = {
            'log': (self.notification_job, {'arg': "Hello world!"})
    }
    listener = NotificationListener("test", notification_settings, self.logger)
    listener.start()

This example subscribes module to channel called "test" and if channel receives message equal to "log", module will
call self.notification_job() method with argument equal to {'arg': "Hello world!"}. Last argument self.logger is
module's logger for logging purposes of listener.

Notification can be send by typing 'redis-cli PUBLISH <channel> <message>' in terminal or executed as bash script.
To send correct notification to module's example above, just use 'redis-cli PUBLISH test log'
"""

import threading
import redis


class NotificationListener(threading.Thread):
    def __init__(self, channel, trigger_work, module_logger):
        """
        Initialize module's notification listener
        :param channel: Channel, which will module subscribe to
        :param trigger_work: Dictionary of trigger (key) and work settings (value) pairs. Trigger is string, which when
                             received in subscribed channel, will start certain work/job, which is paired to the trigger
                             (it's key's value). Job setting is 2-tuple, specifying:
                             (work function, function argument).
                             Multiple arguments to function can be passed as array or dictionary (example above).
        :param module_logger: Logger of module, which calls the listener
        """
        threading.Thread.__init__(self)
        self.logger = module_logger
        self.redis = redis.Redis()
        self.pubsub = self.redis.pubsub()
        # subscribe to channel
        self.pubsub.subscribe([channel])
        # save notification triggers and desired functions
        self.trigger_work = trigger_work
        self.logger.info("Subscribed to channels: " + channel)

    def run(self):
        """
        Listener method, which listens for messages flowing through channel and waits for the trigger to start certain
        job or work
        :return: None
        """
        for message in self.pubsub.listen():
            try:
                received_message = message['data'].decode("utf-8")
                # if received "unsub" message in subscribed channel, module will unsubscribe from notifications
                if received_message == "unsub":
                    self.logger.info("Unsubscribed from channel!")
                    self.pubsub.unsubscribe()
                    break
                # if some registered trigger received, call it's function
                elif received_message in self.trigger_work.keys():
                    # get function, which should be called, with it's arguments
                    function_call, args = self.trigger_work[received_message]
                    function_call(args)
            except AttributeError:
                # First message in channel is 1, which is subscription notification, and it cannot be decoded
                pass
