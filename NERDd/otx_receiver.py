#!/usr/bin/env python3

"""
NERD standalone script for receiving IPv4 addresses from AlienVault OTX pulses.

At the first launch, it downloads all *subscribed* pulses from OTX (updated in last 180 days),
then processes indicators from the pulses and gets only those with IPv4 type.
These are then pushed to NERD. A file '/data/otx_last_update.txt' is created
which stores time of the last pulse update. Next time, only new pusles and
updates created after this time are requested.
This file also plays a role of a flag, if it doesn't exist, all pusles are
downloaded, otherwise only new ones.
The module updates pulses every 4 hours, and every time writes a new time to
the 'otx_last_update.txt'.

Only pulses subscribed by the user whose API key is used are downloaded.
Therefore, to configure which data should be used, you must set subscriptions
in the settings of the OTX user.
"""

import json
import sys
import logging
import argparse
import os
import os.path
from os import path
from datetime import timedelta, datetime
from apscheduler.schedulers.background import BlockingScheduler
import signal

from OTXv2 import OTXv2

# Set modified_since to this number of days if otx_last_update.txt is not present.
MAX_DATA_AGE_ON_FIRST_RUN = 180

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config
from common.task_queue import TaskQueueWriter

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('OTXReceiver')

# path to the file where is writen time of the last pulses update
file_path = '/data/otx_last_update.txt'

# parse arguments
parser = argparse.ArgumentParser(
    prog="OTX_receiver.py",
    description="NERD standalone script for receiving OTX pulses and indicators."
)
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerdd.yml)')

args = parser.parse_args()

# config - load nerdd.yml
logger.info("Loading config file {}".format(args.config))
config = read_config(args.config)
# update config variable (nerdd.yml) with nerd.yml
config_base_path = os.path.dirname(os.path.abspath(args.config))
common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
logger.info("Loading config file {}".format(common_cfg_file))
config.update(read_config(common_cfg_file))

inactive_pulse_time = config.get('record_life_length.otx', 30)

otx_api_key = config.get('otx_api_key', None)

if not otx_api_key:
    logger.error("Cannot load OTX API key, make sure it is properly configured in {}.".format(args.config))
    sys.exit(1)

otx = OTXv2(otx_api_key)

rabbit_config = config.get("rabbitmq")

# rabbitMQ
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()

scheduler = BlockingScheduler(timezone='UTC')


def create_new_pulse(pulse, indicator):
    """
    Creates dictionary containing information about OTX pulse used in NERD as 'otx_pulses'
    :param pulse: OTX pulse from which are the information taken
    :param indicator: OTX pulse's indicator from which are the information taken
    :return: pulse dictionary ('otx_pulse')
    """
    new_pulse = {
        'pulse_id': pulse['id'],
        'pulse_name': pulse['name'],
        'author_name': pulse['author_name'],
        'pulse_created': datetime.strptime(pulse['created'], '%Y-%m-%dT%H:%M:%S.%f'),
        'pulse_modified': datetime.strptime(pulse['modified'], '%Y-%m-%dT%H:%M:%S.%f'),
        'indicator_created': datetime.strptime(indicator['created'], '%Y-%m-%dT%H:%M:%S'),
        'indicator_role': indicator['role'],
        'indicator_title': indicator['title']
    }
    if indicator['expiration'] is not None:
        new_pulse['indicator_expiration'] = datetime.strptime(indicator['expiration'], '%Y-%m-%dT%H:%M:%S')
    return new_pulse


def upsert_new_pulse(pulse, indicator):
    """
    Creates new 'otx_pulse' dict and send it to NERD as upsert to already inserted 'otx_pulses' or creates new list
    :param pulse: OTX pulse from which are the information taken
    :param indicator: OTX pulse's indicator from which are the information taken
    :return: None
    """
    new_pulse = create_new_pulse(pulse, indicator)
    ip_addr = indicator['indicator']
    # create update sets for NERD queue
    updates = []
    for k, v in new_pulse.items():
        updates.append(('set', k, v))
    # get current time and change it format to '%Y-%m-%dT%H:%M:%S'
    current_time = datetime.utcnow()
    if indicator['expiration'] is None:
        live_till = current_time + timedelta(days=inactive_pulse_time)
    else:
        live_till = datetime.strptime(indicator['expiration'], '%Y-%m-%dT%H:%M:%S') + timedelta(days=inactive_pulse_time)
    tq_writer.put_task('ip', ip_addr, [
        ('array_upsert', 'otx_pulses', {'pulse_id': pulse['id']}, updates),
        ('setmax', '_ttl.otx', live_till),
        ('setmax', 'last_activity', current_time)
    ], "otx_receiver")


def write_time(current_time):
    """
    Gets the current time and write it to a text file 'otx_last_update', that is in the /data/
    :return: None
    """
    f = open(file_path, 'w')
    f.write(current_time)
    f.close()


def process_pulses(pulses):
    """
    Processes the pulse's indicators, selects only those with a parameter 'IPv4'
    :return: None
    """
    # get current time minus 30 days to get fresh pulses
    # TODO try to find a way to update only indicators created (or updated if it's possible?) after the last_update_time.
    #   There are pulses often adding a few IPs, now we always process all IPs in such a pulse, even the old ones that are already in NERD
    time_for_upsert = datetime.utcnow() - timedelta(days=30)
    logger.info("Processing pulses")
    for i,pulse in enumerate(pulses):
        ipv4_counter = 0
        indicators = pulse.get('indicators', [])
        for indicator in indicators:
            if (indicator["type"] == "IPv4") and (datetime.strptime(indicator['created'], '%Y-%m-%dT%H:%M:%S') >= time_for_upsert):
                ipv4_counter += 1
                upsert_new_pulse(pulse, indicator)
        logger.info("{}/{} done, pulse {}, {} IPv4 indicators added/updated".format(i+1, len(pulses), pulse.get('id', "(no id?)"), ipv4_counter))


def get_new_pulses():
    """
    Gets pulses from AlienVault OTX from time of the last update that got from 'otx_last_update'
    :return: None
    """
    if path.exists(file_path):
        # Get all pulses modified since the time stored in file
        f = open(file_path, 'r+')
        last_updated_time = f.readline()
        f.close()
        try:
            datetime.strptime(last_updated_time, '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            logger.error("Wrong time format in otx_last_update.txt, must be '%Y-%m-%dT%H:%M:%S', not '{}'".format(last_updated_time))
            sys.exit(1)
        logger.info("Downloading new pulses since {}".format(last_updated_time))
    else:
        # Get all pulses in last MAX_DATA_AGE_ON_FIRST_RUN days
        last_updated_time = datetime.utcnow() - timedelta(days=MAX_DATA_AGE_ON_FIRST_RUN)
        logger.info("Downloading all pulses not older than {} days (since {})".format(MAX_DATA_AGE_ON_FIRST_RUN, last_updated_time))

    current_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    pulses = otx.getall(modified_since=last_updated_time)
    logger.info("Downloaded {} new pulses".format(len(pulses)))
    process_pulses(pulses)
    write_time(current_time)


# Signal handler to stop scheduler (and potentially running processing of pulses) gracefully
def sigint_handler(signum, frame):
    logger.info("Signal {} received, going to stop".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    scheduler.shutdown(wait=True)


if __name__ == "__main__":
    # Get pulses on program start
    get_new_pulses()
    # Start scheduler to get new pulses every 4 hours, register signal handler
    scheduler.add_job(get_new_pulses, 'cron', hour='*/4')
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    signal.signal(signal.SIGABRT, sigint_handler)
    scheduler.start()
    logger.info("Stopped")
