import json
import sys
import logging
import argparse
import os
from datetime import timedelta, datetime

from OTXv2 import OTXv2

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

import NERDd.core.mongodb as mongodb
from common.config import read_config
from common.task_queue import TaskQueueWriter

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('OTXReceiver')

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

API_KEY = ""

rabbit_config = config.get("rabbitmq")
db = mongodb.MongoEntityDatabase(config)

# rabbitMQ
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()


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
        'pulse_created': pulse['created'],
        'pulse_modified': pulse['modified'],
        'indicator_created': indicator['created'],
        'indicator_expiration': indicator['expiration'],
        'indicator_role': indicator['role'],
        'indicator_title': indicator['title']
    }
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
    live_till = datetime.strptime(indicator['expiration'], '%Y-%m-%dT%H:%M:%S') + timedelta(days=inactive_pulse_time)
    tq_writer.put_task('ip', ip_addr, [
        ('array_upsert', 'otx_pulses', {'pulse_id': pulse['id']}, updates),
        ('setmax', '_ttl.otx', live_till),
        ('setmax', 'last_activity', pulse['created'])
    ])


def receive_pulses():
    """
    Connect to OTX Alienvault and get subscribed pulses
    :return: None
    """
    otx = OTXv2(API_KEY)
    # params max_page, limit control how many pulses will be downloaded
    # now it's max_page=1, limit=15 for testing
    pulses = otx.getall(max_page=1, limit=15)

    # Go through all pulses and each pulse indicators. Take only indicators with the type IPv4
    for pulse in pulses:
        pulse_json = json.loads(json.dumps(pulse))
        indicators = pulse_json.get("indicators", [])
        for indicator in indicators:
            if indicator["type"] == "IPv4":
                upsert_new_pulse(pulse_json, indicator)


if __name__ == "__main__":
    receive_pulses()
