#!/usr/bin/env python3

"""
NERD standalone script (primary module) for receiving IDEA messages about 
detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity
records accordingly.

This module can safely run in multiple instances.
"""

import time
import os
import socket
import json
import logging
import signal
import sys

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.utils import parse_rfc_time
import common.config
import common.eventdb_psql
import common.task_queue

# script global variables

running_flag = True  # read_dir function terminates when this is set to False

db_queue = [] # queue of events waiting to be written do DB in a batch

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

log = logging.getLogger('WardenReceiver')


###############################################################################
# Code for reading directory of "filer protocol"

def read_dir(path, call_when_waiting=None):
    """
    Indefinitely watches given directory for new files. Each incoming file is
    read, parsed as JSON, and yield to caller (function behaves as a generator).
    
    call_when_waiting - function to call before going to "poll wait" when there
        are no new files.
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
            os.makedirs(p, exist_ok=True)
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
            if call_when_waiting is not None:
                call_when_waiting()
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
                log.exception("Exception during loading event, file={}".format(str(nf)))
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

def put_to_db_queue(event):
    """
    Function for writing events to EventDB

    Pull new events from Queue and stores them to EventDB.
    """
    #log.debug("IDEA message enqueued".format(len(db_queue)))
    db_queue.append(event)
    if len(db_queue) >= 100:
        put_set_to_database()


def put_set_to_database():
    """
    Function for sending db_queue to database.
    :return:
    """
    if eventdb is None:
        return
    if len(db_queue) > 0:
        log.debug("Writing a set of {} IDEA messages to database.".format(len(db_queue)))
        eventdb.put(db_queue)
        db_queue.clear()


def stop(signal, frame):
    """
    Stop receiving events.

    Will be evoked on catching SIGINT signal.
    """
    global running_flag
    running_flag = False
    put_set_to_database()
    log.info("exiting")


def receive_events(filer_path, eventdb, task_queue_writer):
    # Infinite loop reading events as files in given directory
    # This loop stops on SIGINT
    log.info("Reading IDEA files from {}/incoming".format(filer_path))
    for (rawdata, event) in read_dir(filer_path, call_when_waiting=put_set_to_database):
        # Store the event to EventDB
        if eventdb is not None:
            put_to_db_queue(event)
        try:
            if "Test" in event["Category"]:
                log.debug("Test event ignored")
                continue  # Ignore testing messages
            for src in event.get("Source", []):
                for ipv4 in src.get("IP4", []):
                    # TODO check IP address validity

                    log.debug("Updating IPv4 record {}".format(ipv4))
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
                    task_queue_writer.put_task('ip', ipv4,
                        [
                            ('array_upsert', 'events',
                             {'date': date, 'node': node, 'cat': cat},
                             [('add', 'n', 1)]),
                            ('add', 'events_meta.total', 1),
                            ('set', 'ts_last_event', end_time),
                        ]
                    )
                for ipv6 in src.get("IP6", []):
                    log.debug(
                        "IPv6 address in Source found - skipping since IPv6 is not implemented yet.")  # The record follows:\n{}".format(str(event)), file=sys.stderr)
        except Exception as e:
            log.error("ERROR in parsing event '{}': {}".format(event.get('ID', 'no-ID'), str(e)))


if __name__ == "__main__":
    import argparse

    # Parse arguments
    parser = argparse.ArgumentParser(
        prog="warden_receiver.py",
        description="Primary module of the NERD system to read events from Warden system (as stored into a directory by warden_filer)."
    )
    parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
        help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    if args.verbose:
        log.setLevel('DEBUG')

    # Read config
    log.info("Loading config file {}".format(args.config))
    config = common.config.read_config(args.config)
    
    config_base_path = os.path.dirname(os.path.abspath(args.config))
    common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
    log.info("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))
    
    rabbit_config = config.get("rabbitmq")
    filer_path = config.get('warden_filer_path')

    # Get number of processes from config
    num_processes = config.get('worker_processes')
    assert (isinstance(num_processes,int) and num_processes > 0), "Number of processes ('num_processes' in config) must be a positive integer"

    # Instantiate PSQLEventDatabase if enabled
    eventdb = None # By default, events are not stored anywhere (they are either read from Mentat or not stored at all)
    if config.get('eventdb', None) == 'psql':
        eventdb = common.eventdb_psql.PSQLEventDatabase(config)
    
    # Create main task queue
    task_queue_writer = common.task_queue.TaskQueueWriter(num_processes, rabbit_config)
    task_queue_writer.connect()

    signal.signal(signal.SIGINT, stop)
    receive_events(filer_path, eventdb, task_queue_writer)

