#!/usr/bin/env python3
#-*- encoding: utf-8 -*-
"""
Updater module - periodically issues tasks to trigger regular updates of all records in entity database.

Each entity (currently only those of 'ip' and 'asn' type) should have a set of '_nru' fields (Next Regular Update)
containing date and time of the next planned regular update of the entity.

The module fetches a list of entities whose _nru field value is lower than current time and issues a task with special
events '!every1d' and '!every1w' (once per day and week, respectively).
(in fact, '!check_and_update_1d' is issued daily, which is processed by the Cleaner module, which then issues the
'!every1d' event if the record is not to be removed)

It is also possible to issue additional events for each entity (e.g. when re-processing of some data is needed after
a configuration change). In order to do this, create a file '<CONFIG_FILE_DIR>/updater_events' whose contents are:
<entity_type> <event_name> <max_time>
The entity_type must be one of 'ip', 'asn'. The event_name is the name of the event (should begin with '!') to issue
for each entity along with '!every1d'. Events are issued only if current time is less than max_time (ISO/RFC format).
Since we usually want to issue the event once for each entity, max_time should be set to exactly 24 hours in the future.
The file can contain multiple such entries, one per line.
Example:
  ip !refresh_tags 2022-01-09T15:00:00Z
When max_time elapses, the entry in the file has no meaning, so it can be removed or commented out (using '#').
The file is checked every time a new batch of events is to be issued, so it's not needed to restart updater.
"""

from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BlockingScheduler

import os
import sys
import signal
import logging

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import common.task_queue
import common.config
import NERDd.core.db
import NERDd.core.mongodb
from common.utils import parse_rfc_time

CONFIG_FILE_NAME = "updater_events" # name of the file with additional events to issue

last_fetch_time = datetime(1970, 1, 1)

def stop(signal, frame):
    """
    Stop receiving events.

    Will be evoked on catching SIGINT signal.
    """
    scheduler.shutdown()


def issue_events(db, task_queue_writer, log, fetch_limit):
    """
    Periodically issue events for entities with NRU (next regular update) fields.
    Modules may hook their functions to the corresponding event and the entity type.
    Supported entity types:
        ip
        asn
    Supported events:
        !every4h - Event !every4h is released every 4 hours.
        !every1d - Event !every1d is released every 1 day.
        !every1w - Event !every1w is released every 7 days.
    """
    global last_fetch_time
    time = datetime.utcnow()

    # Load the file with additional events
    additional_events = {'ip': [], 'asn': []}
    line_no = 0
    try:
        for line in open(additional_events_file, "r"):
            line_no += 1
            if not line.strip() or line[0] == '#':
                continue # skip empty lines and comments
            etype, event, max_time = line.split(maxsplit=2)
            if etype not in additional_events.keys():
                raise ValueError("Unsupported entity type '{}'".format(etype))
            try:
                max_time = parse_rfc_time(max_time)
            except ValueError:
                raise ValueError("Wrong timestamp format (it has to end with timezone specification or 'Z' for UTC).")
            if time > max_time:
                continue # expired entry, ignore
            additional_events[etype].append(event)
            log.debug("Additional event '{}' will be issued for all entities of type '{}'".format(event, etype))
    except FileNotFoundError:
        pass # File doesn't exist - that's OK, do nothing
    except Exception as e:
        # Other error - print message and continue
        log.error("Error in the file with additional events ('{}', line {}): {}".format(additional_events_file, line_no, e))

    for etype in ('ip', 'asn'):
        # Get list of IDs for each update interval
        # (i.e. all entities with _nru* less then current time
        #  AND greater than time of the last query - this is important since
        #  _nru* of an entity is set to next interval only after the update
        #  is processed, which may take some time, and we don't want to
        #  fetch the same entity twice)
        # Note: This algorithm depends on the fact that lists of 1d and 1w are always subsets of 4h.
        #       If other intervals will be added in the future, it might need change.
        log.debug("Getting list of '{}' entities to update ...".format(etype))
        ids4h = set()#set(g.db.find(etype, {'_nru4h': {'$lte': time, '$gt': self.last_fetch_time}}, limit=self.FETCH_LIMIT))
        ids1d = set(db.find(etype, {'_nru1d': {'$lte': time, '$gt': last_fetch_time}}, limit=fetch_limit))
        ids1w = set(db.find(etype, {'_nru1w': {'$lte': time, '$gt': last_fetch_time}}, limit=fetch_limit))

        # Merge the lists, so for each entity only one update request is issued, possibly containing more than one event
        all_ids = ids1d #ids4h | ids1d | ids1w # (Union not needed since list for 1d and 1w are always subsets of 4h)

        if not all_ids:
            log.debug("Nothing to update")
            continue

        # Issue update request(s) for each record found
        log.debug("Requesting updates for {} '{}' entities ({} 4h, {} 1d, {} 1w)".format(
            len(all_ids), etype, len(ids4h), len(ids1d), len(ids1w)))

        for n,id in enumerate(all_ids):
            # Each update request contains the corresponding "every*" event,
            # and a change of the '_nru*' attribute.
            requests = []
#           if True: #id in ids4h:  (Since ids4h is superset of other, this is always true)
#               requests.append(('event', '!every4h'))
#               requests.append(('next_step', '_nru4h', 'ts_added', time, timedelta(seconds=4*60*60)))
            if id in ids1d:
                requests.append(('*event', '!check_and_update_1d' if etype=='ip' else '!every_1d'))
                requests.append(('*next_step', '_nru1d', 'ts_added', time, timedelta(days=1)))
            if id in ids1w:
                requests.append(('*event', '!every1w'))
                requests.append(('*next_step', '_nru1w', 'ts_added', time, timedelta(days=7)))
            # Add additional events from the file, if specified
            for add_event in additional_events[etype]:
                requests.append(('*event', add_event))
            # Issue update requests
            task_queue_writer.put_task(etype, id, requests, "updater")
            if (n+1) % 100 == 0:
                log.debug("Requests for {} records submitted.".format(n+1))

    last_fetch_time = time


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description='Periodically issues update events for entities with NRU (next regular update) fields.'
    )
    parser.add_argument('-c', '--config', metavar='FILENAME', dest='cfg_file',
                    help='Path to backend configuration file. (default: /etc/nerd/nerdd.yml)',
                    default='/etc/nerd/nerdd.yml'
    )
    parser.add_argument('-l', '--limit', metavar='N', dest='limit', type=int,
                    help='Maximum number of entities fetched from the database for which the events would be issued. (default: 100000)', 
                    default=100000
    )
    parser.add_argument('-p', '--period', metavar='N', dest='period', type=int,
                    help='Number of seconds between two event issues. (default: 10)', 
                    default=10
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')

    # Parse arguments
    args = parser.parse_args()

    # Configure logging
    LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    log = logging.getLogger("Updater")

    logging.getLogger("apscheduler.scheduler").setLevel("ERROR")
    logging.getLogger("apscheduler.executors.default").setLevel("WARNING")
    if args.verbose:
        log.setLevel('DEBUG')
        logging.getLogger("apscheduler.scheduler").setLevel("INFO")
        logging.getLogger("apscheduler.executors.default").setLevel("INFO")

    log.info("**** Updater started *****")

    # Determine final path to nerdd.yml file and read the configuration
    log.debug("Loading config file {}".format(args.cfg_file))
    config = common.config.read_config(args.cfg_file)
    config_base_path = os.path.dirname(os.path.abspath(args.cfg_file))
    common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
    log.debug("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))

    additional_events_file = os.path.join(config_base_path, CONFIG_FILE_NAME)

    # Get number of processes from config
    num_processes = config.get('worker_processes')
    assert (isinstance(num_processes, int) and num_processes > 0), "Number of processes ('num_processes' in config) must be a positive integer"

    # Configure RabbitMQ
    rabbit_config = config.get("rabbitmq")
    task_queue_writer = common.task_queue.TaskQueueWriter(num_processes, rabbit_config)
    task_queue_writer.connect()

    # Configure database
    db = NERDd.core.mongodb.MongoEntityDatabase(config)

    # Create scheduler
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(lambda: issue_events(db, task_queue_writer, log, args.limit), trigger='cron', second='*/' + str(args.period))

    # Register SIGINT handler to stop the updater
    signal.signal(signal.SIGINT, stop)

    scheduler.start()
