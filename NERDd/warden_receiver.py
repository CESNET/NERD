#!/usr/bin/env python3

"""
NERD standalone script for receiving IDEA messages about detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity
records accordingly.
"""

import time
import os
import socket
import json
import logging
import pika  # RabbitMQ client
import signal

import sys
sys.path.append("../")
import g
from common.utils import parse_rfc_time
import common.config
import common.eventdb_psql
import core.update_manager
import core.mongodb
import core.scheduler

running_flag = True  # read_dir function terminates when this is set to False
logger = logging.getLogger('EventReceiver')

# Configuration files paths
cfg_file = "../etc/nerdd.yml"
common_cfg_file = "../etc/nerd.yml"

g.config = common.config.read_config(cfg_file)
g.config.update(common.config.read_config(common_cfg_file))
g.db = core.mongodb.MongoEntityDatabase(g.config)
g.eventdb = common.eventdb_psql.PSQLEventDatabase(g.config)
g.scheduler = core.scheduler.Scheduler()
g.um = core.update_manager.UpdateManager(g.config, g.db)


def read_dir(path):
    """
    Indefinitely watches given directory for new files. Each incoming file is
    read, parsed as JSON, and yield to caller (function behaves as a generator).
    """

    class NamedFile(object):
        """ Wrapper class for file objects, which allows and tracks filename
            changes.
        """

        def __init__(self, pth, name, fd=None):
            self.name = name
            self.path = pth
            if fd:
                self.f = os.fdopen(fd, "w+b")
            else:
                self.f = None

        def __str__(self):
            return "%s(%s, %s)" % (type(self).__name__, self.path, self.name)

        def get_path(self, basepath=None, name=None):
            return os.path.join(basepath or self.path, name or self.name)

        def open(self, mode):
            return open(self.get_path(), mode)

        def moveto(self, destpath):
            os.rename(self.get_path(), self.get_path(basepath=destpath))
            self.path = destpath

        def rename(self, newname):
            os.rename(self.get_path(), self.get_path(name=newname))
            self.name = newname

        def remove(self):
            os.remove(self.get_path())

    class SafeDir(object):
        """ Maildir like directory for safe file exchange.
            - Producers are expected to drop files into "temp" under globally unique
              filename and rename it into "incoming" atomically (newfile method)
            - Workers pick files in "incoming", rename them into "temp",
              do whatever they want, and either discard them or move into
              "errors" directory
        """

        def __init__(self, p):
            self.path = self._ensure_path(p)
            self.incoming = self._ensure_path(os.path.join(self.path, "incoming"))
            self.errors = self._ensure_path(os.path.join(self.path, "errors-worker"))
            self.temp = self._ensure_path(os.path.join(self.path, "temp-worker"))
            self.hostname = socket.gethostname()
            self.pid = os.getpid()

        def __str__(self):
            return "%s(%s)" % (type(self).__name__, self.path)

        def _ensure_path(self, p):
            try:
                os.mkdir(p)
            except OSError:
                if not os.path.isdir(p):
                    raise
            return p

        def get_incoming(self):
            return [NamedFile(self.incoming, n) for n in os.listdir(self.incoming)]

    def get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk):
        nflist = sdir.get_incoming()
        timeout = time.time() + owait_timeout
        while len(nflist) < nfchunk and time.time() < timeout and running_flag:
            time.sleep(owait_poll_time)
            nflist = sdir.get_incoming()
        return nflist

    #######
    # End of definitions of auxiliary classes and functions.
    # Body of read_dir function follows ...

    sdir = SafeDir(path)
    poll_time = 1  # config.get("poll_time", 5)
    owait_poll_time = 1  # config.get("owait_poll_time", 1)
    owait_timeout = poll_time  # config.get("owait_timeout", poll_time)
    done_dir = None  # config.get("done_dir", None)
    nfchunk = 100  # min number of files read at once by get_dir_list
    oneshot = False

    while running_flag:
        nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)
        while running_flag and not nflist:
            # No new files, wait and try again
            time.sleep(poll_time)
            nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)

        # nfindex = 0
        # count_ok = count_err = count_local = 0
        for nf in nflist:
            if not running_flag:
                break
            # prepare event array from files
            try:
                nf.moveto(sdir.temp)
            except Exception:
                continue  # Silently go to next filename, somebody else might have interfered
            try:
                # Read file and yield record
                with nf.open("r") as fd:
                    data = fd.read()
                event = json.loads(data)
                yield (data, event)
                # Cleanup
                if done_dir:
                    nf.moveto(done_dir)
                else:
                    nf.remove()
            except Exception as e:
                logger.exception("Exception during loading event, file={}".format(str(nf)))
                nf.moveto(sdir.errors)
                # count_local += 1


##############################################################################
# Test of read_dir

def read_dir_test():
    path = "./drop_events_here"
    print("Watching for files in {}".format(os.path.join(path, "incoming")))
    for event in read_dir(path):
        print("------------------------------------------------------------")
        print(json.dumps(event, indent=2))


##############################################################################
# Main module code

def dbwriter(queue, config):
    """
    Process for writing events to EventDB

    Pull new events from Queue and stores them to EventDB. Runs as separate
    process, because storing events is quite CPU demanding.
    """
    # Ignore SIGINT - process should be terminated from the main process
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Create instance of EventDB (PSQL wrapper)
    # It's easier to create it here again than copy the one from main process to this one
    import common.eventdb_psql
    eventdb = common.eventdb_psql.PSQLEventDatabase(config)

    event_set = []

    while True:
        event = queue.get()
        if event is None:
            print("EventDB process exiting")
            break
        event_set.append(event)
        if len(event_set) >= 100 or queue.empty():
            eventdb.put(event_set)
            event_set = []


class WardenReceiver:
    """
    Receiver of security events. Receives events as IDEA files in given directory.
    """

    def __init__(self):
        signal.signal(signal.SIGINT, self.stop)
        self.log = logging.getLogger("EventReceiver")
        self._drop_path = g.config.get('warden_filer_path')

        # Initialize RabbitMQ connection (if queue name is given)
        self.rmq_queue_name = g.config.get('eventdb.forward_to_queue', None)
        if self.rmq_queue_name:
            rmq_creds = pika.PlainCredentials('guest', 'guest')
            rmq_params = pika.ConnectionParameters('localhost', 5672, '/', rmq_creds)
            rmq_conn = pika.BlockingConnection(rmq_params)
            self.rmq_channel = rmq_conn.channel()
            # we don't declare any queue here, it should be declared statically using rabbitmqctl or web Management
        else:
            self.rmq_channel = None

        self._receive_events()

    def stop(self):
        """
        Stop receiving events.

        Will be evoked on catching SIGINT signal.
        """
        global running_flag
        running_flag = False
        self.log.info("Exiting.")

        if self.rmq_channel is not None:
            self.rmq_channel.close()

    def _receive_events(self):
        # Infinite loop reading events as files in given directory
        # This loop stops on SIGINT
        for (rawdata, event) in read_dir(self._drop_path):
            print("new event incoming, putting to database")
            # Store the event to EventDB
            g.eventdb.put([event])

            # Send copy of the IDEA message to RabbitMQ queue (currently used by experimental GRIP system)
            # Does nothing if given queue doesn't exist
            if self.rmq_channel is not None:
                print("Sending to RabbitMQ queue")
                self.rmq_channel.basic_publish(exchange='', routing_key=self.rmq_queue_name, body=rawdata)

            try:
                if "Test" in event["Category"]:
                    continue  # Ignore testing messages
                for src in event.get("Source", []):
                    for ipv4 in src.get("IP4", []):
                        # TODO check IP address validity

                        self.log.debug("EventReceiver: Updating IPv4 record {}".format(ipv4))
                        cat = '+'.join(event["Category"]).replace('.', '')
                        # Parse and reformat detect time
                        detect_time = parse_rfc_time(event["DetectTime"])  # Parse DetectTime
                        date = detect_time.strftime("%Y-%m-%d")  # Get date as a string

                        # Get end time of event
                        if "CeaseTime" in event:
                            end_time = parse_rfc_time(event["CeaseTime"])
                        elif "WinEndTime" in event:
                            end_time = parse_rfc_time(event["WinEndTime"])
                        elif "EventTime" in event:
                            end_time = parse_rfc_time(event["EventTime"])
                        else:
                            end_time = detect_time

                        node = event["Node"][-1]["Name"]

                        g.um.update(
                            ('ip', ipv4),
                            [
                                ('array_upsert', 'events', {'date': date, 'node': node, 'cat': cat}, [('add', 'n', 1)]),
                                ('add', 'events_meta.total', 1),
                                ('set', 'ts_last_event', end_time),
                            ]
                        )

                    for ipv6 in src.get("IP6", []):
                        self.log.debug(
                            "IPv6 address in Source found - skipping since IPv6 is not implemented yet.")  # The record follows:\n{}".format(str(event)), file=sys.stderr)
            except Exception as e:
                self.log.error("ERROR in parsing event: {}".format(str(e)))
                pass


if __name__ == "__main__":
    receiver = WardenReceiver()
    print("exiting")