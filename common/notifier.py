"""
Simple module using redis for cross-process notifying.
"""

import redis
import common.config as config
from threading import Thread, currentThread
from time import sleep
import logging


class Notifier:
    def __init__(self, config_file="../etc/nerdd.yml"):
        self.logger = logging.getLogger("Notifier")
        config_file = config.read_config(config_file)
        redis_config = config_file.get("redis")
        self.r = redis.StrictRedis(**redis_config)
        self.publisher = self.r.pubsub()
        self.all_threads = []

    def subscribe(self, channel, callback, call_with_message=False):
        """
        This method will create a thread and will call callback when the channel receives new message.
        :param channel:
        :param callback:
        :param call_with_message:
        :return:
        """
        self.logger.info("Subscribing for channel {}".format(channel))
        self.publisher.subscribe(channel)
        t = Thread(target=self._wait_for_message, args=(channel, callback, call_with_message))
        t.daemon = True
        t.start()
        self.all_threads.append(t)

    def publish(self, channel, message=""):
        """
        Use this method to notify all subscribers.
        :param channel:
        :param message:
        :return:
        """
        self.logger.info("Publishing on channel {}".format(channel))
        self.r.publish(channel, message)

    def unsubscribe_all(self):
        """
        Use this to stop waiting for all kinds of messages.
        :return:
        """
        for t in self.all_threads:
            t.do_run = False
            t.join()

    def _wait_for_message(self, channel, callback, call_with_message):
        t = currentThread()
        while getattr(t, "do_run", True):
            msg = self.publisher.get_message()
            if msg:
                msg_type = msg["type"]
                msg_channel = msg["channel"].decode("utf-8")
                if msg_type == "message" and msg_channel == channel:
                    if call_with_message:
                        callback(msg["data"])
                    else:
                        callback()
            sleep(0.5)



#### TEST START #######
#
# from multiprocessing import Process
#
#
# class ThisTester:
#     def __init__(self, num):
#         self.i = num
#         self.running = False
#
#     def stop(self):
#         self.running = False
#
#     def run(self):
#         ps = Notifier()
#         ps.subscribe("stop_all", self.stop)
#         if self.i == 0:
#             ps.unsubscribe_all()
#         self.running = True
#         while self.running:
#             print(" {} ...".format(self.i))
#             sleep(2)
#
#         print("Process {} is stopping".format(self.i))
#
#
#
# def processs(i):
#     tester = ThisTester(i)
#     tester.run()
#
#
# def test_this():
#     for i in range(3):
#         p = Process(target=processs, args=(i,))
#         p.start()
#
#     sleep(2.5)
#     ps = Notifier()
#     print("publishing stop_all")
#     ps.publish("stop_all")
#
#
# if __name__ == "__main__":
#      test_this()

#### TEST END #######
