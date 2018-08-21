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

import sys
sys.path.insert(0, '..')
from common.config import read_config
import NERDd.core.mongodb as mongodb
from misp_keys import misp_key, misp_url
from common.task_queue import TaskQueue


DEFAULT_MONGO_HOST = 'localhost'
DEFAULT_MONGO_PORT = 27017
DEFAULT_MONGO_DBNAME = 'nerd'

# parse arguments
parser = argparse.ArgumentParser(
    prog="misp_receiver.py",
    description="NERD standalone, which will synchronize NERD with data from MISP instance."
)
parser.add_argument("--cert", required=False, dest="cert", action="store", default=False,
                    help="Self signed certificate of MISP instance")
args = parser.parse_args()

misp_inst = PyMISP(misp_url, misp_key, args.cert, 'json')

# db config
config = read_config("../etc/nerdd.yml")

db = mongodb.MongoEntityDatabase(config)

# task queue init
tq = TaskQueue(config.get('rabbitmq', {}))

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('MISP_updater')

# if some error occures in ip processing, add it to list and try to process it again at the end of the script
error_ip = {}

SIGHTING_DICT = {'0': "positive", '1': "false positive", '2': "expired attribute"}


def get_ip_from_rec(ip_str, position=None):
    """
    Gets ip addresses from list of addresses in string, where records are splitted by new line
    :param ip_str: list of ip addresses in string
    :param position: position of ip_address in case of composite record ("domain|ip" --> 1)
    :return: List of ip addresses
    """
    ip_list_raw = ip_str.text.split("\n")
    ip_list_raw.remove("")
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
    :return: two lists of source IP addresses and destination IP addresses
    """
    # get all ip addresses from
    try:
        ip_src = misp_inst.get_all_attributes_txt("ip-src")
        ip_dst = misp_inst.get_all_attributes_txt("ip-dst")
        # domain|ip attribute is destination ip
        dom_ip = misp_inst.get_all_attributes_txt("domain|ip")
        ip_src_port = misp_inst.get_all_attributes_txt("ip-src|port")
        ip_dst_port = misp_inst.get_all_attributes_txt("ip-dst|port")
    except ConnectionError:
        logger.error("Cannot connect to MISP instance!")
        exit(1)

    # remove duplicity with set and convert to list again, get_ip_from_rec(ip_src_port, 0) -- 0 because ip address is
    # at index 0 after split ("192.168.1.1|2715"), the same for ip_dst|port and domain|ip
    ip_src_all = list(set(get_ip_from_rec(ip_src) + get_ip_from_rec(ip_src_port, 0)))
    ip_dst_all = list(set(get_ip_from_rec(dom_ip, 1) + get_ip_from_rec(ip_dst_port, 0) + get_ip_from_rec(ip_dst)))

    return ip_src_all, ip_dst_all


def threat_level_num_to_word(threat_level):
    if threat_level == "1":
        return "High"
    elif threat_level == "2":
        return "Medium"
    elif threat_level == "3":
        return "Low"
    elif threat_level == "4":
        return "Undefined"


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
        'threat_level': threat_level_num_to_word(event['threat_level_id']),
        'last_change': datetime.datetime.fromtimestamp(int(event['timestamp']))
    }

    # get sighting count, find the right attribute, carrying this ip address and its sighting list
    try:
        kwargs = {'eventid': event['id'], 'values': ip_addr}
        attrib = misp_inst.search(controller='attributes', **kwargs)
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

    # get TLP from event, example: tlp:red
    for tag in event.get('Tag', []):
        if tag['name'][0:3] == "tlp":
            new_event['tlp'] = tag['name'][4:]
            break
    return new_event


def proccess_ip(ip_addr, role):
    """
    Find all events corresponding to the ip_addr and insert them to NERD
    :param ip_addr: actual ip_address
    :param role: type of ip address [src|dst]
    :return: None if error occured while loading info about ip address
    """
    # check ip record in DB
    db_entity = db.get("ip", ip_addr)

    try:
        kwargs = {'values': ip_addr}
        misp_events = misp_inst.search(controller='events', **kwargs)['response']
        # misp_events = misp_inst.search_all(ip_addr)['response']
    except ConnectionError or KeyError:
        # key error occurs, when cannot connect and trying to access to ['response'] key
        logger.error("Cannot connect to MISP instance!")
        error_ip[ip_addr] = role
        return None

    events = []
    for event in misp_events:
        event = event['Event']
        new_event = create_new_event(event, role, ip_addr)
        if new_event is not None:
            events.append(new_event)

    if events:
        # compare 'misp_events' attrib from NERD and compare it with events list, if same do not insert, else insert
        if db_entity:
            pairs = zip(db_entity.get('misp_events', {}), events)
            # if misp_events and events are not the same, then insert
            if not [(x, y) for x, y in pairs if x != y]:
                # construct new update request
                update_requests = [('set', 'misp_events', events)]
                # send new update request
                tq.put_update_request('ip', ip_addr, update_requests)
        else:
            # ip address not even in NERD --> insert it, construct new update request
            update_requests = [('set', 'misp_events', events)]
            # send new update request
            tq.put_update_request('ip', ip_addr, update_requests)


def main():
    logger.info("Loading a list of all IPs in MISP ...")

    ip_src, ip_dst = get_all_ip()

    ip_all = ip_src + ip_dst
    logger.info("Loaded {} src IPs and {} dst IPs.".format(len(ip_src), len(ip_dst)))

    # get all IPs with 'misp_events' attribute from NERD
    logger.info("Searching NERD for IP records with misp_events ...")
    db_ip_misp_events = db.find('ip', {'misp_events': {'$exists': True, '$not': {'$size': 0}}})

    # find all IPs that are in NERD but not in MISP anymore
    for ip in db_ip_misp_events:
        if ip in ip_all:
            db_ip_misp_events.remove(ip)

    # remove all 'misp_events' attributes that are in NERD but not in MISP
    if db_ip_misp_events:
        logger.info("{} NERD IPs don't have an entry in MISP anymore, removing corresponding misp_events keys...".format(len(db_ip_misp_events)))
        for ip in db_ip_misp_events:
            tq.put_update_request('ip', ip, [('remove', 'misp_events')])

    logger.info("Checking and updating NERD records for all the IPs ...")

    # go through every source ip
    for ip_addr in ip_src:
        # cProfile.runctx("proccess_ip(ip_addr, \"src\")", {}, {'ip_addr': ip_addr, 'proccess_ip': proccess_ip})
        #logger.debug(ip_addr)
        proccess_ip(ip_addr, "src")
    
    # go through every destination ip
    for ip_addr in ip_dst:
        #logger.debug(ip_addr)
        proccess_ip(ip_addr, "dst")

    # try to process IPs, which was not processed correctly
    for ip_addr, role in error_ip.items():
        proccess_ip(ip_addr, role)

    logger.info("Done")


if __name__ == "__main__":
    main()
