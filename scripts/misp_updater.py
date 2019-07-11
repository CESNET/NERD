#!/usr/bin/env python3
"""
NERD standalone script which will synchronize NERD with data from MISP instance. Pulls all IP addresses from MISP
instance and get information about all events, where IP address occurred. All these information are then stored as
'misp_events'
"""

from pymisp import PyMISP
import logging
import datetime
import argparse
import os
import re
import sys

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config
import NERDd.core.mongodb as mongodb
from common.task_queue import TaskQueueWriter

DEFAULT_MONGO_HOST = 'localhost'
DEFAULT_MONGO_PORT = 27017
DEFAULT_MONGO_DBNAME = 'nerd'

# parse arguments
parser = argparse.ArgumentParser(
    prog="misp_receiver.py",
    description="NERD standalone, which will synchronize NERD with data from MISP instance."
)
parser.add_argument("-v", dest="verbose", action="store_true",
                    help="Verbose mode")
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
parser.add_argument("--cert", metavar='CA_FILE',
                    help="Use this server certificate (or CA bundle) to check the certificate of MISP instance, useful when the server uses self-signed cert.")
parser.add_argument("--insecure", action="store_true",
                    help="Don't check the server certificate of MISP instance.")
args = parser.parse_args()

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('MISP_updater')

if args.verbose:
    logger.setLevel("DEBUG")

# config - load nerdd.yml
logger.info("Loading config file {}".format(args.config))
config = read_config(args.config)
# update config variable (nerdd.yml) with nerd.yml
config_base_path = os.path.dirname(os.path.abspath(args.config))
common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
logger.info("Loading config file {}".format(common_cfg_file))
config.update(read_config(common_cfg_file))

db = mongodb.MongoEntityDatabase(config)

# task queue init
tq = TaskQueueWriter(config.get('rabbitmq', {}))

# load MISP instance configuration
try:
    misp_key = config['misp']['key']
    misp_url = config['misp']['url']
except KeyError:
    logging.error("Missing configuration of MISP instance in the configuration file!")
    sys.exit(1)


cert = True # set to check server certificate (default)
if args.insecure:
    cert = False # don't check certificate
elif args.cert:
    cert = args.cert # read the certificate (CA bundle) to check the cert

misp_inst = PyMISP(misp_url, misp_key, cert, 'json')

# if some error occures in ip processing, add it to list and try to process it again at the end of the script
error_ip = {}

SIGHTING_DICT = {'0': "positive", '1': "false positive", '2': "expired attribute"}
THREAT_LEVEL_DICT = {'1': "High", '2': "Medium", '3': "Low", '4': "Undefined"}


def get_ip_from_rec(ip_str, position=None):
    """
    Gets ip addresses from list of addresses in string, where records are splitted by new line
    :param ip_str: list of ip addresses in string
    :param position: position of ip_address in case of composite record ("domain|ip" --> 1)
    :return: List of ip addresses
    """
    ip_list_raw = ip_str.text.splitlines()
    # if position, have to split record (domain|ip)
    if position is not None:
        ip_list = []
        for ip_addr in ip_list_raw:
            # delimeter can be | or :
            ip = ip_addr.split("|")
            if len(ip) == 1:
                ip = ip_addr.split(":")
            ip_list.append(ip[position])
        return ip_list
    return ip_list_raw


def get_all_ip():
    """
    Get all IP addresses from MISP instance
    :return: two sets of source IP addresses and destination IP addresses
    """
    # get all ip addresses from
    try:
        ip_src = misp_inst.get_all_attributes_txt("ip-src")
        ip_dst = misp_inst.get_all_attributes_txt("ip-dst")
        # domain|ip attribute is destination ip
        dom_ip = misp_inst.get_all_attributes_txt("domain|ip")
        ip_src_port = misp_inst.get_all_attributes_txt("ip-src|port")
        ip_dst_port = misp_inst.get_all_attributes_txt("ip-dst|port")
    except ConnectionError as e:
        logger.error("Cannot connect to MISP instance: " + str(e))
        sys.exit(1)

    # remove duplicity with set and convert to list again, get_ip_from_rec(ip_src_port, 0) -- 0 because ip address is
    # at index 0 after split ("192.168.1.1|2715"), the same for ip_dst|port and domain|ip
    ip_src_all = set(get_ip_from_rec(ip_src) + get_ip_from_rec(ip_src_port, 0))
    ip_dst_all = set(get_ip_from_rec(dom_ip, 1) + get_ip_from_rec(ip_dst_port, 0) + get_ip_from_rec(ip_dst))

    return ip_src_all, ip_dst_all


def check_src_dst(attrib_list, ip_addr):
    """
    Check if ip_address is as src and dst at the same time in this event
    :param attrib_list: list of attributes of the event
    :param ip_addr: searched IP address
    :return: True if IP address is src and dst at the same time and False if not
    """
    src, dst = False, False
    for attrib in attrib_list:
        if "ip" in attrib['type']:
            if attrib['value'] == ip_addr:
                if "src" in attrib['type']:
                    src = True
                else:
                    dst = True
    return True if src and dst else False


def create_new_event(event, role, ip_addr):
    """
    Creates dictionary containing information about event used in NERD as 'misp_events'
    :param event: actual event
    :param role: src|dst
    :param ip_addr: actual ip_address which occurred in the event
    :return: event dictionary
    """
    new_event = {
        'misp_instance': misp_url,
        'event_id': event['id'],
        'org_created': event['Orgc']['name'],
        'tlp': "green",
        'tag_list': [],
        # check if ip address is not src and dst at the same time
        'role': role if not check_src_dst(event['Attribute'], ip_addr) else "src and dst at the same time",
        'info': event['info'],
        'sightings': {'positive': 0, 'false positive': 0, 'expired attribute': 0},
        'date': datetime.datetime.fromtimestamp(int(event['publish_timestamp'])),
        'threat_level': THREAT_LEVEL_DICT[event['threat_level_id']],
        'last_change': datetime.datetime.fromtimestamp(int(event['timestamp']))
    }

    # get sighting count, find the right attribute, carrying this ip address and its sighting list
    try:
        attrib = misp_inst.search(controller='attributes', eventid=event['id'], values=ip_addr)
        try:
            attrib_id = int(attrib['response']['Attribute'][0]['id'])
        except KeyError:
            logger.error("Unexpected response: " + str(attrib))
            return None
        sighting_list = misp_inst.sighting_list(attrib_id)
        try:
            for sighting in sighting_list['response']:
                new_event['sightings'][SIGHTING_DICT[sighting['Sighting']['type']]] += 1
        except KeyError:
            logger.error("Unexpected response: " + str(attrib))
            return None
    except ConnectionError as e:
        # key error occurs, when cannot connect and trying to access to ['response'] key
        logger.error("Cannot connect to MISP instance: " + str(e))
        error_ip[ip_addr] = role
        return None

    # get name and colour Tags on event level
    for tag in event.get('Tag', []):
        if not tag['name'].startswith("tlp"):
            new_event['tag_list'].append({'name': tag['name'], 'colour': tag['colour']})
        else:
            # tlp:white
            new_event['tlp'] = tag['name'][4:0]

    return new_event


def process_ip(ip_addr, role):
    """
    Find all events corresponding to the ip_addr and insert them to NERD
    :param ip_addr: actual ip_address
    :param role: type of ip address [src|dst]
    :return: None if error occured while loading info about ip address
    """
    logger.debug("Processing IP: {}".format(ip_addr))
    
    # check ip record in DB
    try:
        db_entity = db.get("ip", ip_addr)
    except ValueError:
        logger.error("ERROR: " + ip_addr, exc_info=True)
    try:
        misp_events_response = misp_inst.search(controller='events', values=ip_addr)
        misp_events = misp_events_response['response']
    except ConnectionError as e:
        logger.error("Cannot connect to MISP instance: " + str(e))
        error_ip[ip_addr] = role
        return None
    except KeyError:
        logger.error("Unexpected response: " + str(misp_events_response))
        error_ip[ip_addr] = role
        return None

    events = []
    for event in misp_events:
        event = event['Event']
        new_event = create_new_event(event, role, ip_addr)
        if new_event is not None:
            events.append(new_event)

    if events:
        if db_entity is not None:
            # compare 'misp_events' attrib from NERD with events list, if not same --> insert, else do not insert
            if db_entity.get('misp_events', {}) != events:
                # construct new update request and send it
                update_requests = [('set', 'misp_events', events)]
                tq.put_task('ip', ip_addr, update_requests)
        else:
            # ip address not even in NERD --> insert it
            update_requests = [('set', 'misp_events', events)]
            tq.put_task('ip', ip_addr, update_requests)


def main():
    logger.info("Loading a list of all IPs in MISP ...")

    ip_src, ip_dst = get_all_ip()

    ip_all = ip_src.union(ip_dst)
    logger.info("Loaded {} src IPs and {} dst IPs.".format(len(ip_src), len(ip_dst)))

    # get all IPs with 'misp_events' attribute from NERD
    logger.info("Searching NERD for IP records with misp_events ...")
    db_ip_misp_events = db.find('ip', {'misp_events': {'$exists': True, '$not': {'$size': 0}}})

    # find all IPs that are in NERD but not in MISP anymore
    db_ip_misp_events = set(db_ip_misp_events) - ip_all

    # remove all 'misp_events' attributes that are in NERD but not in MISP
    if db_ip_misp_events:
        logger.info(
            "{} NERD IPs don't have an entry in MISP anymore, removing corresponding misp_events keys...".format(
                len(db_ip_misp_events)))
        for ip in db_ip_misp_events:
            tq.put_task('ip', ip, [('remove', 'misp_events')])

    logger.info("Checking and updating NERD records for all the IPs ...")
    # this is not the absolutely correct regular expression for IP4 address, but for the purposes of this converter it
    # is enough
    re_ip_address = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    # go through every source ip
    for ip_addr in ip_src:
        if re_ip_address.search(ip_addr):
            process_ip(ip_addr, "src")

    # go through every destination ip
    for ip_addr in ip_dst:
        if re_ip_address.search(ip_addr):
            process_ip(ip_addr, "dst")

    # try to process IPs, which was not processed correctly
    for ip_addr, role in error_ip.items():
        if re_ip_address.search(ip_addr):
            process_ip(ip_addr, role)

    logger.info("Done")


if __name__ == "__main__":
    main()
