import sys
import argparse
import os
import logging
from datetime import datetime
import urllib.request
from apscheduler.schedulers.background import BlockingScheduler
import signal

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

scheduler = BlockingScheduler(timezone='UTC')

# Signal handler to stop scheduler gracefully
def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)

def processFeed(feed_data):
    logger.info("Start processing the feed")
    ips = {}
    for record in feed_data:
        record_data = record.split('\t')
        ip_addr = record_data[0].lstrip('0')
        reports = int(record_data[3])
        targets = int(record_data[4])
        if(ip_addr in ips):
            ips[ip_addr]["reports"] += reports
            ips[ip_addr]["targets"] += targets
        else:
            ips[ip_addr] = {"reports" : reports, "targets" : targets}
    
    logger.info("Processed the feed")
    logger.info("Start creating tasks")
    for ip_addr in ips:
        if (ips[ip_addr]["reports"] < min_reports) or (ips[ip_addr]["targets"] < min_targets):
            continue
        tq_writer.put_task('ip', ip_addr, [
                                            ('array_upsert', 'dshield', {'date' : current_date},
                                            [('set', 'reports', ips[ip_addr]["reports"]),
                                             ('set', 'targets', ips[ip_addr]["targets"])])
                                          ], "dshield")
    logger.info("Tasks created")

def downloadFeed():
    logger.info("Downloading feed...")
    feed = urllib.request.urlopen(dshield_feed_url)
    if(feed.getcode() == 200):
        feed_data = [line.decode() for line in feed.readlines() if not line.decode().startswith('#')]
    else:
        logger.error("Cannot download feed. Response status code: {}".format(feed.getcode()))
        sys.exit(1)
    logger.info("Feed downloaded")
    processFeed(feed_data)

if __name__ == "__main__":

    downloadFeed()
    # Start scheduler to get new feed every day, register signal handler
    scheduler.add_job(downloadFeed, 'cron', hour='0')
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)
    scheduler.start()
    logger.info("Stopped")

