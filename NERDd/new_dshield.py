import sys
import argparse
import os
import logging
from datetime import datetime
import urllib.request

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config
from common.task_queue import TaskQueueWriter

# parse arguments
parser = argparse.ArgumentParser(
    prog="new_dshield.py",
    description="NERD module for getting data from DShield daily sources"
)
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerd.yml)')

args = parser.parse_args()
config = read_config(args.config)
rabbit_config = config.get("rabbitmq")

# rabbitMQ
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('DShield')

dshield_feed_url = config.get('dshield.url')
min_reports = config.get('dshield.min_reports')
min_targets = config.get('dshield.min_targets')

current_date = datetime.utcnow().date().strftime("%Y-%m-%d")

def processFeed(feed_data):
    logger.info("Start processing the feed")
    ips = {}
    for record in feed_data:
        record_data = record.split('\t')
        ip_addr = record_data[0].lstrip('0')
        reports = int(record_data[3])
        targets = int(record_data[4])
        if ((reports < min_reports) or (targets < min_targets)):
            continue
        if(ip_addr in ips):
            ips[ip_addr]["reports"] += reports
            ips[ip_addr]["targets"] += targets
        else:
            ips[ip_addr] = {"reports" : reports, "targets" : targets}
    
    logger.info("Processed the feed")
    logger.info("Start creating tasks")
    for ip_addr in ips:
        tq_writer.put_task('ip', ip_addr, [
                                            ('array_upsert', 'dshield', {'date' : current_date},
                                            [('set', 'reports', ips[ip_addr]["reports"]),
                                             ('set', 'targets', ips[ip_addr]["targets"])])
                                          ], "dshield")
    logger.info("Tasks created")

if __name__ == "__main__":

    logger.info("Downloading feed...")
    feed = urllib.request.urlopen(dshield_feed_url)
    if(feed.getcode() == 200):
        feed_data = [line.decode() for line in feed.readlines() if not line.decode().startswith('#')]
    else:
        logger.error("Cannot download feed. Response status code: {}".format(feed.getcode()))
        sys.exit(1)
    logger.info("Feed downloaded")
    processFeed(feed_data)

