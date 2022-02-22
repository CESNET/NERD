#!/usr/bin/env python3
"""
NERD standalone script which will synchronize NERD with data from MISP instance. Pulls all IP addresses from MISP
instance and get information about all events, where IP address occurred. All these information are then stored as
'misp_events'
"""
import ipaddress
import logging
from datetime import datetime, timedelta
import argparse
import os
import sys
from ipaddress import IPv4Address, AddressValueError

from pymisp import ExpandedPyMISP

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
    prog="misp_updater.py",
    description="NERD standalone script to synchronize NERD with data from MISP instance."
)
parser.add_argument("-v", dest="verbose", action="store_true",
                    help="Verbose mode")
parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default='/etc/nerd/nerdd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
parser.add_argument("--since", action="store",
                    help="Specifies date from which should misp_updater query IP addresses from MISP. "
                    "Expected format: YYYY-MM-DD. Default is taken from MISP ip lifetime stored in /etc/nerd/nerd.yml "
                    "(180 days by default).")
parser.add_argument("--to", action="store",
                    help="Specifies date to which should misp_updater query IP addresses from MISP. "
                    "Expected format: YYYY-MM-DD. Default is today's date.")
parser.add_argument("--events", action="store_true", default=False,
                    help="Download info about IP addresses event by event. This may be useful, when even smaller time "
                         "interval cannot be properly handled by MISP server.")
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

inactive_ip_lifetime = config.get('record_life_length.misp', 180)

db = mongodb.MongoEntityDatabase(config)

rabbit_config = config.get("rabbitmq")
num_processes = config.get('worker_processes')
tq = TaskQueueWriter(num_processes, rabbit_config)
tq.connect()

# load MISP instance configuration
try:
    misp_key = config['misp']['key']
    misp_url = config['misp']['url']
except KeyError:
    logging.error("Missing configuration of MISP instance in the configuration file!")
    sys.exit(1)
misp_verify_cert = config.get('misp.verify_cert', True)  # path to CA bundle to check the server cert, or False to
                                                         # disable cert verification, or True to use default CA bundle
                                                         # (passed to "requests" as "verify" parameter)

misp_inst = ExpandedPyMISP(misp_url, misp_key, misp_verify_cert)

# if some error occures in ip processing, add it to list and try to process it again at the end of the script
error_ip = {}

SIGHTING_DICT = {'0': "positive", '1': "false positive", '2': "expired attribute"}
THREAT_LEVEL_DICT = {'1': "High", '2': "Medium", '3': "Low", '4': "Undefined"}
KEYS_TO_SAFE_FROM_ATTRIB = ('info', 'Orgc', 'id', 'Tag', 'date', 'threat_level_id', 'timestamp')


def get_ip_from_attrib(attrib):
    """
    Get ip address from MISP attribute and check its distribution level
    :param attrib: MISP attribute with ip address
    :return: double empty strings, if distribution level is not met. If distribution is ok, then return 2 values: IP,
                                                                                                        role (src|dst)
    """
    # First check distribution level of attributes, 2 = Connected Communities, 3 = All Communities, 5 can have only
    # attributes and it means inherit event's distribution
    if int(attrib.get('distribution', 0)) in (2, 3, 5) and int(attrib.get('Event', {}).get('distribution')) in (2, 3):
        if attrib['type'] in ("ip-src", "ip-dst"):
            return attrib['value'], "src" if "src" in attrib['type'] else "dst"
        elif attrib['type'] == "domain|ip":
            return attrib['value'].split("|")[1], "src" if "src" in attrib['type'] else "dst"
        elif attrib['type'] in ("ip-src|port", "ip-dst|port"):
            ip_split = attrib['value'].split("|")
            if len(ip_split) == 1:
                # ip-scr|port can use ':' as delimeter, so if after split it did not split anything, it probably uses
                # ':' as delimeter
                ip_split = attrib['value'].split(":")
            return ip_split[0], "src" if "src" in attrib['type'] else "dst"
    else:
        # if distribution level is met not met, return two empty strings
        return "", ""


def create_or_append(dict_to_update, key, value):
    """
    Create list with value in dict on the key or if it already exists, just append value to it
    :param dict_to_update: dictionary, which list will get updated on key
    :param key: key of dict updated dict record
    :param value: new value
    :return: None (result is updated dict passed in dict_to_update dictionary)
    """
    try:
        dict_to_update[key].append(value)
    except KeyError:
        # key does not exist yet
        dict_to_update[key] = [value]


def get_ip_from_query(query_result, ip_all):
    """
    Gets IP addresses and all necessary info from search query (controller='attributes'), which was run on MISP instance
    :param query_result: result of query, where will IP addresses be parsed from
    :param ip_all: dictionary with already processed IP addresses, which will be updated by this method
    :return: None (the result is updated ip_all dictionary passed as argument)
    """
    for ip_attrib in query_result['Attribute']:
        ip, role = get_ip_from_attrib(ip_attrib)
        try:
            if ip and IPv4Address(ip):
                # if retrieved from attribute, then save only info, which  will be later inserted to NERD, which means
                # all keys listed in KEYS_TO_SAFE_FROM_ATTRIB, Sightings of attribute and role of IP (src|dst)
                info_to_save = dict((k, ip_attrib['Event'][k]) for k in KEYS_TO_SAFE_FROM_ATTRIB if ip_attrib['Event'])
                try:
                    info_to_save['Sightings'] = ip_attrib['Sightings']
                except KeyError:
                    pass
                info_to_save['role'] = role
                # when all info collected, save it under IP address key in ip_all dictionary, at the end of processing
                # IPs there will be all IPs with all their events info, where they occurred
                create_or_append(ip_all, ip, info_to_save)
        except AddressValueError:
            # IP address is in wrong format
            continue


def get_all_ip_interval():
    """
    Get all IP addresses from MISP instance from selected interval
    :return: dictionary of all IPs found in MISP with all info, which will be later saved in NERD
    """
    params = {
        'date_from': args.since if args.since else (datetime.utcnow() - timedelta(days=inactive_ip_lifetime)).strftime("%Y-%m-%d"),
        'date_to': args.to if args.to else datetime.utcnow().strftime("%Y-%m-%d")
    }

    ip_all = {}

    try:
        if args.events:
            # if --events used, first download all attributes wanted just with basic info to obtain their event ids
            ip_src_basic = misp_inst.search(controller="attributes", type_attribute="ip-src", **params)
            logger.info("Downloaded basic ip-src info!")
            ip_dst_basic = misp_inst.search(controller="attributes", type_attribute="ip-dst", **params)
            logger.info("Downloaded basic ip-dst info!")
            # domain|ip attribute is destination ip
            dom_ip_basic = misp_inst.search(controller="attributes", type_attribute="domain|ip", **params)
            logger.info("Downloaded basic domain|ip info!")
            ip_src_port_basic = misp_inst.search(controller="attributes", type_attribute="ip-src|port", **params)
            logger.info("Downloaded basic ip-src|port info!")
            ip_dst_port_basic = misp_inst.search(controller="attributes", type_attribute="ip-dst|port", **params)
            logger.info("Downloaded basic ip-dst|port info!")
            logger.info("Basic info about IPs obtained, starting to query IPs event by event!")

            # then save all unique event ids for every attribute type (there are 5 types)
            event_ids = [[], [], [], [], []]
            for i, ip_query_basic in enumerate((ip_src_basic, ip_dst_basic, dom_ip_basic, ip_src_port_basic, ip_dst_port_basic)):
                for attrib in ip_query_basic['Attribute']:
                    if attrib['event_id'] not in event_ids[i]:
                        event_ids[i].append(attrib['event_id'])

            attribute_types = ("ip-src", "ip-dst", "domain|ip", "ip-src|port", "ip-dst|port")
            # now use additional params to get all IP info needed
            params['includeContext'] = 1
            params['includeSightings'] = 1
            # go through all attrib types and their event ids (5 types --> 5 lists of event ids)
            for i, event_id_list in enumerate(event_ids):
                for event_id in event_id_list:
                    logger.debug("Going to query event {} for all {} attributes".format(event_id, attribute_types[i]))
                    ip_query = misp_inst.search(controller="attributes", type_attribute=attribute_types[i],
                                                eventid=event_id, **params)
                    logger.debug("Downloaded {} {} attributes!".format(len(ip_query['Attribute']), attribute_types[i]))
                    # get all desired info from that query, it means all info, which will be later saved in NERD and
                    # save it to ip_all
                    get_ip_from_query(ip_query, ip_all)
        else:
            # else download all info about IP straight
            params['includeContext'] = 1
            params['includeSightings'] = 1
            ip_src = misp_inst.search(controller="attributes", type_attribute="ip-src", **params)
            logger.info("Downloaded all ip-src MISP attributes!")
            ip_dst = misp_inst.search(controller="attributes", type_attribute="ip-dst", **params)
            logger.info("Downloaded all ip-dst MISP attributes!")
            # domain|ip attribute is destination ip
            dom_ip = misp_inst.search(controller="attributes", type_attribute="domain|ip", **params)
            logger.info("Downloaded all domain-ip MISP attributes!")
            ip_src_port = misp_inst.search(controller="attributes", type_attribute="ip-src|port", **params)
            logger.info("Downloaded all ip-src|port MISP attributes!")
            ip_dst_port = misp_inst.search(controller="attributes", type_attribute="ip-dst|port", **params)
            logger.info("Downloaded all ip-dst|port MISP attributes!")

            # go through all the queries and get all needed information from it, it means selected information about
            # event, which means all info, which will be later saved in NERD, for now save it in ip_all
            for ip_query in (ip_src, ip_dst, dom_ip, ip_src_port, ip_dst_port):
                get_ip_from_query(ip_query, ip_all)

    except ConnectionError as e:
        logger.error("Cannot connect to MISP instance: " + str(e))
        sys.exit(1)

    return ip_all


def is_single_ip(ip_to_check):
    try:
        _ = ipaddress.IPv4Address(ip_to_check)
        return True
    except ipaddress.AddressValueError:
        return False


def get_all_ips():
    """
    Gets all IP addresses from MISP instance, which are old as inactive_ip_lifetime or younger
    :return: List of IP addresses
    """
    params = {
        'date_from': (datetime.utcnow() - timedelta(days=inactive_ip_lifetime)).strftime("%Y-%m-%d"),
        'date_to': datetime.utcnow().strftime("%Y-%m-%d")
    }
    ip_src = misp_inst.search(controller="attributes", type_attribute="ip-src", **params)
    ip_dst = misp_inst.search(controller="attributes", type_attribute="ip-dst", **params)
    # domain|ip attribute is destination ip
    dom_ip = misp_inst.search(controller="attributes", type_attribute="domain|ip", **params)
    ip_src_port = misp_inst.search(controller="attributes", type_attribute="ip-src|port", **params)
    ip_dst_port = misp_inst.search(controller="attributes", type_attribute="ip-dst|port", **params)

    ip_all = []
    for ip_attrib_list in (ip_src, ip_dst, dom_ip, ip_src_port, ip_dst_port):
        for ip_attrib in ip_attrib_list['Attribute']:
            ip_addr, _ = get_ip_from_attrib(ip_attrib)
            if is_single_ip(ip_addr):
                ip_all.append(ip_addr)

    return ip_all


def create_new_event(ip_addr, event):
    """
    Creates dictionary containing information about event used in NERD as 'misp_events'
    :param ip_addr: actual ip_address which occurred in the event
    :param event: MISP event, where the IP address occurred
    :return: event dictionary
    """
    new_event = {
        'misp_instance': misp_url,
        'event_id': event['id'],
        'org_created': event['Orgc']['name'],
        'tlp': "green",
        'tag_list': [],
        # check if ip address is not src and dst at the same time
        'role': event['role'],
        'info': event['info'],
        'sightings': {'positive': 0, 'false positive': 0, 'expired attribute': 0},
        'date': datetime.strptime(event['date'], "%Y-%m-%d"),
        'threat_level': THREAT_LEVEL_DICT[event['threat_level_id']],
        'last_change': datetime.fromtimestamp(int(event['timestamp']))
    }

    try:
        for sighting in event.get('Sighting', []):
            new_event['sightings'][SIGHTING_DICT[sighting['type']]] += 1
    except KeyError:
        logger.error("Unexpected sighting type or structure in {} IP attribute!".format(ip_addr))
        return None

    # get name and colour Tags on event level
    for tag in event.get('Tag', []):
        if not tag['name'].startswith("tlp"):
            new_event['tag_list'].append({'name': tag['name'], 'colour': tag['colour']})
        else:
            # tlp tag looks like tlp:white
            new_event['tlp'] = tag['name'][4:]

    return new_event


def switch_role(role):
    """
    Switch role from "src" to "dst" and vice versa
    :param role: src|dst
    :return: switched role
    """
    return "src" if role == "dst" else "dst"


def process_ip(ip_addr, ip_info):
    """
    Save all info about IP address in NERD
    :param ip_addr: IP address which is being processed
    :param ip_info: All info about IP address, which will be stored in MISP
    :return: None
    """
    logger.debug("Processing IP: {}".format(ip_addr))

    # check ip record in DB
    try:
        db_entity = db.get("ip", ip_addr)
    except ValueError:
        logger.error("ERROR: " + ip_addr, exc_info=True)
        return None

    # deduplicate IP events, where there was duplicate source IP and check if IP in the event is not src and dst at the
    # same time
    event_ids_roles = []
    deduplicated_events = []
    for event in ip_info:
        # if IP event with same role already in deduplicated events, just skip it. The same applies for event,
        # which is already stored as src and dst IP
        if [event['id'], event['role']] not in event_ids_roles and \
                [event['id'], "src and dst at the same time"] not in event_ids_roles:
            # if IP event not already in deduplicated events with switched role, just add it
            if [event['id'], switch_role(event['role'])] not in event_ids_roles:
                event_ids_roles.append([event['id'], event['role']])
                deduplicated_events.append(event)
            else:
                # event with opposite role already in deduplicated events, update event's role to "src and dst"
                for index, dedup_event in enumerate(deduplicated_events):
                    if dedup_event['id'] == event['id']:
                        dedup_event['role'] = "src and dst at the same time"
                        event_ids_roles[index][1] = "src and dst at the same time"

    # create all misp events and save the youngest datetime of the event for keep alive token
    events = []
    youngest_date = datetime(year=2000, month=1, day=1, hour=0, minute=0, second=0)
    for event_info in deduplicated_events:
        new_event = create_new_event(ip_addr, event_info)
        if new_event is not None:
            events.append(new_event)
        if youngest_date < new_event['date']:
            youngest_date = new_event['date']

    if events:
        live_till = youngest_date + timedelta(days=inactive_ip_lifetime)
        if db_entity is not None:
            # compare 'misp_events' attrib from NERD with events list, if not same --> insert, else do not insert
            if db_entity.get('misp_events', {}) != events:
                # construct new update request and send it
                update_requests = [('set', 'misp_events', events), ('set', '_ttl.misp', live_till),
                                   ('setmax', 'last_activity', youngest_date)]
                tq.put_task('ip', ip_addr, update_requests, "misp_updater")
        else:
            # ip address not even in NERD --> insert it
            update_requests = [('set', 'misp_events', events), ('set', '_ttl.misp', live_till), ('setmax',
                                                                'last_activity', youngest_date)]
            tq.put_task('ip', ip_addr, update_requests, "misp_updater")


def main():
    logger.info("Step 1: Remove misp_events key of IP records in NERD for IPs that are not in MISP anymore ...")
    logger.info("Loading a list of all IPs in MISP (in last {} days) ...".format(inactive_ip_lifetime))
    ip_all = get_all_ips()
    logger.info("Found {} IPs.".format(len(ip_all)))

    # get all IPs with 'misp_events' attribute from NERD
    logger.info("Searching NERD for IP records with misp_events ...")
    db_ip_misp_events = db.find('ip', {'misp_events': {'$exists': True, '$not': {'$size': 0}}})
    logger.info("Found {} IPs.".format(len(db_ip_misp_events)))

    # find all IPs that are in NERD but not in MISP anymore
    db_ip_misp_events = set(db_ip_misp_events) - set(ip_all)

    # remove all 'misp_events' attributes that are in NERD but not in MISP anymore
    if db_ip_misp_events:
        logger.info(
            "{} NERD IPs don't have a (recent) entry in MISP anymore, removing corresponding misp_events keys...".format(
                len(db_ip_misp_events)))
        for ip in db_ip_misp_events:
            tq.put_task('ip', ip, [('remove', 'misp_events')], "misp_updater")

    logger.info("Step 2: Create or update NERD records for all IPs present in MISP ...")
    logger.info("Loading a list of all IPs in MISP (in given time interval) ...")
    ip_all_selected_interval = get_all_ip_interval()
    logger.info("Loaded {} IPs, checking and updating corresponding NERD records ...".format(len(ip_all_selected_interval)))

    for ip_addr, ip_info in ip_all_selected_interval.items():
        process_ip(ip_addr, ip_info)

    # try to process IPs, which was not processed correctly
    for ip_addr, role in error_ip.items():
        process_ip(ip_addr, role)

    logger.info("Done")


if __name__ == "__main__":
    main()
