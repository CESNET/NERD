#!/usr/bin/env python3

"""
NERD standalone script for receiving IPv4 addresses from OTX Alienvault pulses.

At the first launch, it downloads all subscribed pulses from OTX Alienvault,
then processing indicators from pulses and gets only with IPv4 type, that 
are then projected to NERD. After first launch will be created file 'otx_last_update.txt',
where will be stored time of the last pulse update. 
This file also playes role of a flag, on the basis of which either all pulses will
be downloaded(if this file doesn't exist) or new pulses will be downloaded(if this file exists).
New pulses are pulses that have appeared since the time of the last update.
Module updates pulses every 4 hours, and after every update write new time to the 'otx_last_update.txt'.
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

from OTXv2 import OTXv2

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
    logger.error("Cannot load OTX Alienvault API key, make sure it is properly configured in {}.".format(args.config))
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


def processing_pulses(pulses):
    """
    Processes the pulse's indicators, selects only with a parameter 'IPv4'
    :return: None
    """
    logger.info("Processing pulses")
    for pulse in pulses:
        ipv4_counter = 0
        indicators = pulse.get('indicators', [])
        for indicator in indicators:
            if indicator["type"] == "IPv4":
                ipv4_counter += 1
                upsert_new_pulse(pulse, indicator)
        logger.info("Done, {} IPv4 indicators added/updated".format(ipv4_counter))


def get_new_pulses():
    """
    Gets pulses from OTX Alienvault from time of the last update that got from 'otx_last_update'
    :return: None
    """
    f = open(file_path, 'r+')
    last_updated_time = f.readline()
    f.close()
    try:
        validtime = datetime.strptime(last_updated_time, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        logger.error("Wrong time format in otx_last_update.txt, must be '%Y-%m-%dT%H:%M:%S', not '{}'".format(last_updated_time))
        sys.exit(1)
    current_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    logger.info("Downloading new pulses since {}".format(last_updated_time))
    pulses = otx.getall(modified_since=last_updated_time)
    logger.info("Downloaded {} new pulses".format(len(pulses)))
    processing_pulses(pulses)
    write_time(current_time)


def get_all_pulses():
    """
    Get all pulses from OTX Alienvault
    :return: None
    """
    current_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    logger.info("Downloading all subscribed pulses")
    pulses = otx.getall()
    logger.info("Downloaded {} new pulses".format(len(pulses)))
    processing_pulses(pulses)
    write_time(current_time)


def pulses_manager():
    """
    Manages getting pulses. If it the first launch, will get all subscribed pulses,
    otherwise will get new pulses that have appeared science last update
    """
    if path.exists(file_path):
        get_new_pulses()
    else:
        get_all_pulses()


if __name__ == "__main__":
    pulses_manager()
    scheduler.add_job(pulses_manager, 'cron', hour='*/4')
    scheduler.start()
