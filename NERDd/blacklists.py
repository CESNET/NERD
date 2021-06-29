#!/usr/bin/env python3

import time
import os
import socket
import json
import logging
import signal
import sys
from datetime import datetime, timedelta
import jsonpath_rw_ext

import argparse
import yaml
import requests
import re
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.executors.pool import ThreadPoolExecutor
import time
import ipaddress

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.utils import parse_rfc_time
import common.config
import common.eventdb_psql
import common.task_queue

# script global variables

running_flag = True  # read_dir function terminates when this is set to False

db_queue = []  # queue of events waiting to be written do DB in a batch

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

log = logging.getLogger('Blacklists:')

###############################################################################

###############################################################################

# Main module code

'''
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
'''


def stop(signal, frame):
    """
    Stop receiving events.

    Will be evoked on catching SIGINT signal.
    """
    global running_flag
    running_flag = False
    # put_set_to_database()
    log.info("exiting")


'''
def receive_events(filer_path, eventdb, task_queue_writer, inactive_ip_lifetime, warden_filter=None):
    # Infinite loop reading events as files in given directory
    # This loop stops on SIGINT
    log.info("Reading IDEA files from {}/incoming".format(filer_path))
    life_span = timedelta(days=inactive_ip_lifetime)

    for (rawdata, event) in read_dir(filer_path, call_when_waiting=put_set_to_database):
        # Store the event to EventDB
        if eventdb is not None:
            put_to_db_queue(event)
        try:
            if warden_filter and not warden_filter.should_pass(event):
                log.debug("event {} ignored".format(event["ID"]))
                continue
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

                    # calculate the timestamp, to which the record should be kept
                    live_till = end_time + life_span

                    task_queue_writer.put_task('ip', ipv4,
                                               [
                                                   ('array_upsert', 'events',
                                                    {'date': date, 'node': node, 'cat': cat},
                                                    [('add', 'n', 1)]),
                                                   ('add', 'events_meta.total', 1),
                                                   ('setmax', 'last_activity', end_time),
                                                   ('setmax', '_ttl.warden', live_till),
                                               ]
                                               )
                for ipv6 in src.get("IP6", []):
                    log.debug(
                        "IPv6 address in Source found - skipping since IPv6 is not implemented yet.")  # The record follows:\n{}".format(str(event)), file=sys.stderr)
        except Exception as e:
            log.error("ERROR in parsing event '{}': {}".format(event.get('ID', 'no-ID'), str(e)))

'''

if __name__ == "__main__":
    import argparse

    # Parse arguments
    parser = argparse.ArgumentParser(
        prog="blacklists.py",
        description="Primary module of the NERD system for downloading and processing blacklists as main source."
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

    # inactive_ip_lifetime = config.get('record_life_length.warden', 14)
    rabbit_config = config.get("rabbitmq")
    filer_path = config.get('warden_filer_path')

    # Get number of processes from config
    num_processes = config.get('worker_processes')
    assert (isinstance(num_processes,
                       int) and num_processes > 0), "Number of processes ('num_processes' in config) must be a positive integer"


    # Create main task queue
    task_queue_writer = common.task_queue.TaskQueueWriter(num_processes, rabbit_config)
    task_queue_writer.connect()

    signal.signal(signal.SIGINT, stop)
    # receive_events(filer_path, eventdb, task_queue_writer, inactive_ip_lifetime, warden_filter)

    delta = timedelta(days=1)
    now_plus_3days = datetime.now() + delta
    download = datetime.now()
    blname = 'blacklistname'

    task_queue_writer.put_task('ip', '8.8.8.8', [
        ('setmax', '_ttl.bl', now_plus_3days),
        ('array_upsert', 'bl', {'n': blname}, [('set', 'v', 1), ('set', 't',
                                                                 download), ('append', 'h', download)])
    ])

##################################################################################################################

