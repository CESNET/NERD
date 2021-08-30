#!/usr/bin/env python3
"""Script to put a single task (aka update_request) to the main NERD Task Queue."""

import os
import sys
import argparse
import logging
import json

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config
from common.task_queue import TaskQueueWriter

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('PutTask')

# parse arguments
parser = argparse.ArgumentParser(
    prog="put_task.py",
    description="Put a single task (aka update_request) to the main NERD Task Queue."
)
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerd.yml',
                    help='Path to main NERD configuration file (default: /etc/nerd/nerd.yml)')
parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose mode")
parser.add_argument("etype", metavar="TYPE", help="Entity type (e.g. 'ip', 'asn')")
parser.add_argument("eid", metavar="ID", help="Entity ID (e.g. '1.2.3.4')")
parser.add_argument("requests", metavar="UPDATE_SPEC", nargs='+', help="An update request as a JSON-encoded array, e.g. '[\"set\",\"test\",1]' or '[\"event\", \"!refresh_tags\"]'")
parser.add_argument("-s", '--source', metavar="SOURCE_NAME", default="", help="Source name (e.g. 'blacklists', 'misp_receiver', 'otx_receiver', 'updater', 'warden_receiver', 'updater_manager', 'web', 'misp_updater')")
args = parser.parse_args()

if args.verbose:
    logger.setLevel("DEBUG")

# Load configuration
logger.debug("Loading config file {}".format(args.config))
config = read_config(args.config)

rabbit_params = config.get('rabbitmq', {})
num_processes = config.get('worker_processes')

# Parse the task
requested_changes = []
for req in args.requests:
    try:
        req_parsed = json.loads(req)
    except ValueError as e:
        logger.error("Invalid UPDATE_SPEC: {}".format(e))
        sys.exit(1)
    if not isinstance(req_parsed, list) or len(req_parsed) < 2:
        logger.error("Invalid UPDATE_SPEC: It must be a list with at least two items (operation and attr/event name)")
        sys.exit(1)
    requested_changes.append(req_parsed)

# Create connection to task queue (RabbitMQ)
tqw = TaskQueueWriter(num_processes, rabbit_params)
if args.verbose:
    tqw.log.setLevel("DEBUG")
tqw.connect()

# Put task
logger.debug("Sending task for {}/{}: {}".format(args.etype, args.eid, requested_changes))
tqw.put_task(args.etype, args.eid, requested_changes, args.source)

# Close connection
tqw.disconnect()
