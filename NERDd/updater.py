#!/usr/bin/env python3
#-*- encoding: utf-8 -*-
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

last_fetch_time = datetime(1970, 1, 1)

def stop(signal, frame):
    """
    Stop receiving events.

    Will be evoked on catching SIGINT signal.
    """
    scheduler.shutdown()


def issue_events(db, task_queue, log, fetch_limit):
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

        for id in all_ids:
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
            # Issue update requests
            task_queue.put_update_request(etype, id, requests)

    last_fetch_time = time


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description='Periodically issues update events for entities with NRU (next regular update) fields.'
    )
    parser.add_argument('-c', '--config', metavar='FILENAME', dest='cfg_file',
                    help='Path to configuration file. (default: /etc/nerd/nerdd.yml)', 
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

    # Parse arguments
    args = parser.parse_args()
    
    # Determine final path to nerd.yml file and read the configuration
    config_base_path = os.path.dirname(os.path.abspath(args.cfg_file))
    config_base = common.config.read_config(args.cfg_file)
    common_cfg_file = os.path.join(config_base_path, config_base.get('common_config'))
    config = common.config.read_config(common_cfg_file)

    # Configure RabbitMQ
    rabbit_config = config.get("rabbitmq")
    task_queue = common.task_queue.TaskQueue(rabbit_config)

    # Configure logging
    LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.WARNING, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    log = logging.getLogger("Updater")

    # Configure database
    db = NERDd.core.mongodb.MongoEntityDatabase(config)

    # Create scheduler
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(lambda: issue_events(db, task_queue, log, args.limit), trigger='cron', second='*/' + str(args.period))

    # Register SIGINT handler to stop the updater
    signal.signal(signal.SIGINT, stop)

    scheduler.start()
