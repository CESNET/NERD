import sys
import argparse
import os
import logging
from datetime import datetime, timedelta
import urllib.request
from apscheduler.schedulers.background import BlockingScheduler
import signal

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config
from common.task_queue import TaskQueueWriter

# parse arguments
parser = argparse.ArgumentParser(
    prog="dshield.py",
    description="""
        NERD module for getting data from DShield daily sources.
        Every night (at 5:00 UTC) it downloads the daily feed from https://isc.sans.edu/feeds/daily_sources
        and creates/updates a record in NERD for each IP address there (with at least "min_reports" and "min_targets"
        from configuration).
    """
)
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerd.yml)')
parser.add_argument('--now', action='store_true',
                    help='Download and process data immediately after start (otherwise just schedule to download it every night')

args = parser.parse_args()

# Load config
config = read_config(args.config)
rabbit_config = config.get("rabbitmq")

dshield_feed_url = config.get('dshield.url')
min_reports = config.get('dshield.min_reports')
min_targets = config.get('dshield.min_targets')
dshield_ttl_days = config.get('record_life_length.dshield', 7)

# rabbitMQ
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()

# Logging
LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('DShield')

scheduler = BlockingScheduler(timezone='UTC')

# Signal handler to stop scheduler gracefully
def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)

def process_feed(feed_data):
    logger.info("Processing the feed ...")
    data_date = datetime.utcnow() - timedelta(days=1) # Downloaded data dump comes from the previous day
    date_str = data_date.strftime("%Y-%m-%d")
    ttl_date = data_date + timedelta(days=dshield_ttl_days)
    ips = {}
    for record in feed_data:
        record_data = record.split('\t')
        # parse IP addresses with leading zeros
        ip_addr_splitted = record_data[0].split('.')
        ip_addr = ""
        for number in ip_addr_splitted:
            number = number.lstrip('0')
            if number == "":
                number = '0'
            ip_addr += number + '.'
        ip_addr = ip_addr.rstrip('.')

        reports = int(record_data[3])
        targets = int(record_data[4])
        if ip_addr in ips:
            ips[ip_addr]["reports"] += reports
            ips[ip_addr]["targets"] += targets
        else:
            ips[ip_addr] = {"reports" : reports, "targets" : targets}
    
    logger.info(f"Creating tasks to update {len(ips)} IPs ...")
    for ip_addr in ips:
        if (ips[ip_addr]["reports"] < min_reports) or (ips[ip_addr]["targets"] < min_targets):
            continue
        tq_writer.put_task('ip', ip_addr, [
                                            ('array_upsert', 'dshield', {'date' : date_str},
                                             [('set', 'reports', ips[ip_addr]["reports"]),
                                              ('set', 'targets', ips[ip_addr]["targets"])]),
                                            ('setmax', '_ttl.dshield', ttl_date),
                                          ], "dshield")
    logger.info("Tasks created")

def download_feed():
    logger.info("Downloading feed ...")
    feed = urllib.request.urlopen(dshield_feed_url)
    if feed.getcode() == 200:
        feed_data = [line.decode() for line in feed.readlines() if not line.decode().startswith('#')]
    else:
        logger.error("Cannot download feed. Response status code: {}".format(feed.getcode()))
        sys.exit(1)
    logger.info(f"Feed successfully downloaded. {len(feed_data)} records found.")
    process_feed(feed_data)

if __name__ == "__main__":
    if args.now:
        download_feed()
    # Start scheduler to get new feed every day, register signal handler
    scheduler.add_job(download_feed, 'cron', hour='5')
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)
    scheduler.start()
    logger.info("Stopped")

