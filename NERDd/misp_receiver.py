#!/usr/bin/env python3
"""
NERD standalone script for receiving MISP instance changes of events, attributes or sightings.
All the changes are then projected to NERD.
"""

import zmq
import time
import json
import sys
import signal
import logging
import argparse
import os
import re
from datetime import timedelta, datetime


from pymisp import ExpandedPyMISP

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

import NERDd.core.mongodb as mongodb
from common.config import read_config
from common.task_queue import TaskQueueWriter
from common.utils import int2ipstr

running_flag = True

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('MispReceiver')

# parse arguments
parser = argparse.ArgumentParser(
    prog="MISP_receiver.py",
    description="NERD standalone script for receiving MISP instance changes of events, attributes or sightings."
)
parser.add_argument("--cert", metavar='CA_FILE',
                    help="Use this server certificate (or CA bundle) to check the certificate of MISP instance, useful "
                         "when the server uses self-signed cert.")
parser.add_argument("--insecure", action="store_true",
                    help="Don't check the server certificate of MISP instance.")
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
parser.add_argument("-v", dest="verbose", action="store_true",
                    help="Verbose mode")

args = parser.parse_args()

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

rabbit_config = config.get("rabbitmq")
db = mongodb.MongoEntityDatabase(config)

# rabbitMQ
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()

# load MISP instance configuration
misp_key = config.get('misp.key', None)
misp_url = config.get('misp.url', None)
misp_zmq_url = config.get('misp.zmq', None)
if not (misp_key and misp_url and misp_zmq_url):
    logger.error("Missing configuration of MISP instance in the configuration file!")
    sys.exit(1)

cert = True # set to check server certificate (default)
if args.insecure:
    cert = False # don't check certificate
elif args.cert:
    cert = args.cert # read the certificate (CA bundle) to check the cert

misp_inst = ExpandedPyMISP(misp_url, misp_key, cert)

# get attribute's type from str like: "distribution () => (5), type () => (hostname), category () => (Network activity)"
re_attrib_type_change = re.compile("type \(\) => \(([\w|\-]+)\)")
# get attribute's event_id from str like: "event_id () => (6916), distribution () => (5), type () => (hostname)"
re_event_id_change = re.compile("event_id \(\) => \(([0-9]+)\)")
# get event_id from str like: "Attribute (562857) from Event (5822): Network activity\/url bit.ly\/2m0x8IH"
re_event_id_title = re.compile("Event \(([0-9]+)\)")
# get attribute id from str like: "Attribute (562857) from Event (5822): Network activity\/url bit.ly\/2m0x8IH"
re_attrib_id_title = re.compile("Attribute \(([0-9]+)\)")
# get attribute's type and attribute's value from str like: "Event (6921): Network activity\/ip-src 24.25.34.2"
re_attrib_type_value_title = re.compile("\([0-9]+\): [\w| ]+/([\w|\-]+) (.*)")

IP_MISP_TYPES = ["ip-src", "ip-dst", "ip-dst|port", "ip-src|port", "domain|ip"]
THREAT_LEVEL_DICT = {'1': "High", '2': "Medium", '3': "Low", '4': "Undefined"}


def stop(signal, frame):
    """
    Stops receiving MISP events by setting running flag to false
    """
    global running_flag
    running_flag = False
    logger.info("exiting")


def get_sightings_for_nerd(sighting_list):
    """
    Generate 'sightings' attribute used for 'misp_events' in NERD
    :param sighting_list: list full of sightings retrieved from MISP
    :return: 'sightings' attribute for NERD
    """
    counted_sightings = {'0': 0, '1': 0, '2': 0}
    for sighting in sighting_list:
        counted_sightings[sighting['type']] += 1
    return {'positive': counted_sightings['0'],
            'false positive': counted_sightings['1'],
            'expired attribute': counted_sightings['2']}


def check_src_and_dst_one(attrib_list, ip_addr):
    """
    Check if IP address is as src and dst at the same time in this event
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


def check_src_and_dst_list(insert_ip_list):
    """
    Check if IP addresses in the event are src and dst at the same time and return them as list
    :param insert_ip_list: dict with misp_event, attribute with IP address and its sightings
    :return: list of src and dst IP addresses
    """
    ip_src = []
    ip_dst = []
    for ip_ev in insert_ip_list:
        if "src" in ip_ev['attrib']['type']:
            ip_src.append(get_ip_address(ip_ev['attrib']))
        else:
            ip_dst.append(get_ip_address(ip_ev['attrib']))

    return list(set(ip_src) & set(ip_dst))


def create_new_event(event, role, sighting_list=None):
    """
    Creates dictionary containing information about MISP event used in NERD as 'misp_events'
    :param event: the MISP event
    :param role: src|dst IP address
    :param sighting_list: list of sightings of ip_address attribute, which called event creation
    :return: event dictionary ('misp_event')
    """
    new_event = {
        'misp_instance': misp_url,
        'event_id': event['id'],
        'org_created': event['Orgc']['name'],
        'tlp': "green",
        'tag_list': [],
        'role': role,
        'info': event['info'],
        'sightings': {'positive': 0, 'false positive': 0, 'expired attribute': 0},
        'date': datetime.strptime(event['date'], "%Y-%m-%d"),
        'threat_level': THREAT_LEVEL_DICT[event['threat_level_id']],
        'last_change': datetime.fromtimestamp(int(event['timestamp']))
    }

    # get sighting count
    if sighting_list:
        new_event['sightings'] = get_sightings_for_nerd(sighting_list)

    # get name and colour Tags on event level
    for tag in event.get('Tag', []):
        if not tag['name'].startswith("tlp"):
            new_event['tag_list'].append({'name': tag['name'], 'colour': tag['colour']})
        else:
            # tlp:white
            new_event['tlp'] = tag['name'][4:]

    return new_event


def get_role_of_ip(attrib_type):
    """
    Get role (src|dst) of ip address based on attribute type
    :param attrib_type: attribute type ("ip-src", "ip-dst", ...)
    :return: "src"|"dst"
    """
    return "src" if "src" in attrib_type else "dst"


def get_ip_address(attrib):
    """
    Get ip address value based on attribute type
    :param attrib: attribute containing ip address
    :return: actual ip address
    """
    if "ip-src" == attrib['type'] or "ip-dst" == attrib['type']:
        return attrib['value']
    elif "ip-src|port" == attrib['type'] or "ip-dst|port" == attrib['type']:
        split_attrib = attrib['value'].split('|')
        if len(split_attrib) == 1:
            split_attrib = attrib['value'].split(':')
        return split_attrib[0]
    else:
        # type == domain|ip
        return attrib['value'].split("|")[1]


def get_attribute_from_event(event, attrib_id):
    """
    Find the right attribute based on attribute's id, if the attribute is not deleted
    :param event: event, that should contain searched attribute
    :param attrib_id: id of searched attribute
    :return: None
    """
    try:
        for attrib in event['Attribute']:
            if attrib['id'] == attrib_id and not attrib['deleted']:
                return attrib
    except KeyError:
        return None


def remove_misp_event(ip_addr, event_id):
    """
    Removes one specific 'misp_event' from NERD
    :param ip_addr: ip address to which does the 'misp_event' belong to
    :param event_id: event_id of the 'misp_event'
    :return: None
    """
    # remove the event from 'misp_events' array
    tq_writer.put_task("ip", ip_addr, [('array_remove', 'misp_events',
                                           {'misp_instance': misp_url, 'event_id': event_id})])


def upsert_new_event(event, attrib, sighting_list, role=None):
    """
    Creates new 'misp_event' dict and send it to NERD as upsert to already inserted 'misp_events' or creates new list
    :param event: MISP event from which are the information taken
    :param attrib: received attribute
    :param sighting_list: list of sightings of the IP address
    :param role: role of ip_address (src or|and dst)
    :return: None
    """
    new_event = create_new_event(event, role if role is not None else get_role_of_ip(attrib['type']), sighting_list)
    ip_addr = get_ip_address(attrib)
    # create update sets for NERD queue
    updates = []
    for k, v in new_event.items():
        updates.append(('set', k, v))
    live_till = new_event['date'] + timedelta(days=inactive_ip_lifetime)
    tq_writer.put_task('ip', ip_addr, [
        ('array_upsert', 'misp_events', {'misp_instance': misp_url, 'event_id': event['id']}, updates),
        ('setmax', '_ttl.misp', live_till),
        ('setmax', 'last_activity', new_event['date'])
    ])


def process_sighting_notification(sighting):
    """
    Called when sighting notification is received through ZMQ. Processes the notification
    :param sighting: the notification
    :return: None
    """
    try:
        # event which attribute was sighted
        event = misp_inst.get(sighting['event_id'])['Event']
        # get sightings of attribute (rather set actual values of all sightings, than just add or remove 1 sighting)
        sighting_list_response = misp_inst.sighting_list(int(sighting['attribute_id']))['response']
        sighting_list = []
        for sighting_rec in sighting_list_response:
            sighting_list.append({'type': sighting_rec['Sighting']['type']})

        ip_addr = get_ip_address(sighting['Attribute'])
        rec = db.get("ip", ip_addr)
        # find correct 'misp_event' and rewrite sightings via update request
        if rec:
            just_update = False
            for ev in rec['misp_events']:
                if misp_url == ev['misp_instance'] and sighting['event_id'] == ev['event_id']:
                    # correct 'misp_event' found, rewrite sightings is enough
                    just_update = True
            if just_update:
                # ip record found, just rewrite sightings
                tq_writer.put_task("ip", ip_addr, [('array_upsert', 'misp_events', {'misp_instance': misp_url,
                                                    'event_id': sighting['event_id']}, [('set', 'sightings',
                                                    get_sightings_for_nerd(sighting_list))])])
                return
        # ip address not even in NERD or not found correct 'misp_event', create new 'misp_event'
        # find correct attribute to pass it to event creation
        attributes = misp_inst.search(controller='attributes', values=ip_addr)['response']['Attribute']
        for attrib_dict in attributes:
            if attrib_dict['event_id'] == sighting['event_id']:
                attrib = attrib_dict
                break
        else:
            return
        upsert_new_event(event, attrib, sighting_list)
    except ConnectionError as e:
        logger.error("Cannot connect to MISP instance: " + str(e))


def attrib_add_or_edit(ip_addr, event_id, attrib_id):
    """
    In case of attribute add, find corresponding event and fill it into NERD, in case of edit, remove old record before
    inserting
    :param ip_addr: value of attribute (has to be IP address)
    :param event_id: id of event the attribute belongs to
    :param attrib_id: id of attribute
    :return: None
    """
    # get event from MISP, to which the attribute corresponds
    try:
        event = misp_inst.get_event(int(event_id))['Event']
    except ConnectionError as e:
        logger.error("Cannot connect to MISP instance: " + str(e))
        return
    attrib = get_attribute_from_event(event, attrib_id)
    if attrib is None:
        return

    if check_src_and_dst_one(event['Attribute'], ip_addr):
        role = "src and dst at the same time"
    else:
        role = get_role_of_ip(attrib['type'])
    # create new updated event and insert it to NERD
    upsert_new_event(event, attrib, attrib.get('Sighting'), role)


def receive_events():
    """
    Connect to MISP's ZeroMQ and listen for MISP's changes and react on them
    :return: None
    """
    context = zmq.Context()
    socket = context.socket(zmq.SUB)

    logger.info("Connecting to: " + misp_zmq_url)
    socket.connect(misp_zmq_url)
    socket.setsockopt(zmq.SUBSCRIBE, b'')

    while running_flag:
        # wait for new message (using nonblocking receive and sleep allows to
        # the exit program gracefully even if no message arrives)
        try:
            message = socket.recv(flags=zmq.NOBLOCK)
        except zmq.ZMQError:
            time.sleep(2)
            continue

        message = message.decode("utf-8")
        logger.debug("Message received:\n" + message)
        # save json part of the message
        # message starts with its category (misp_json_audit, misp_json_event ...) followed by dictionary of message data
        # whole message looks like:
        # "misp_json_audit {'Log': { 'model_id': "5822",
        #                            'action': "edit",
        #                            'change': "publish_timestamp (1529233674) => (1533713571), user_id (1) => (2)",
        #                            'title': "Event (5822): Advanced Persistent Threat Activity ...",
        #                            'xxx': "yyy",
        #                            ...... },
        #                   'action': "log"}
        # so split message on '{' with the second parameter 1, which will give: "Log": {....}, 'action': "log"} so the
        # starting bracket has to be added.
        json_message = json.loads("{" + message.split("{", 1)[1])

        # check message prefix, which defines actions
        if message.startswith("misp_json_audit"):
            if json_message['Log']['model'] == "Event" and json_message['Log']['action'] == "publish" and \
                    json_message['Log']['change'] == "":
                # final publish of event, process it
                event_id = json_message['Log']['model_id']
                try:
                    event = misp_inst.get_event(event_id)['Event']
                except ConnectionError as e:
                    logger.error("Cannot connect to MISP instance: " + str(e))
                    continue

                insert_ip_list = []
                # find all ip attributes and save their metadata
                for attrib in event['Attribute']:
                    if attrib['type'] in IP_MISP_TYPES and not attrib['deleted']:
                        insert_ip_list.append({'event': event, 'attrib': attrib, 'sighting': attrib.get('Sighting')})
                # same with attributes in event's objects
                for event_obj in event.get('Object', []):
                    for attrib in event_obj['Attribute']:
                        if attrib['type'] in IP_MISP_TYPES:
                            insert_ip_list.append(
                               {'event': event, 'attrib': attrib, 'sighting': attrib.get('Sighting')})

                # get list of ip addresses, which are both of type source and destination
                ip_src_and_dst = check_src_and_dst_list(insert_ip_list)
                # insert new ip addresses
                for ip_ev in insert_ip_list:
                    if ip_ev['attrib']['value'] in ip_src_and_dst:
                        upsert_new_event(event, ip_ev['attrib'], ip_ev['sighting'], role="src and dst at the same time")
                    else:
                        upsert_new_event(event, ip_ev['attrib'], ip_ev['sighting'])

            elif json_message['Log']['model'] == "Attribute" and json_message['Log']['action'] == "delete":
                # deletion of attribute
                attrib_type = re_attrib_type_value_title.search(json_message['Log']['title']).group(1)
                if attrib_type in IP_MISP_TYPES:
                    attrib_value = re_attrib_type_value_title.search(json_message['Log']['title']).group(2)
                    event_id = re_event_id_title.search(json_message['Log']['title']).group(1)
                    # remove the event from 'misp_events' array
                    remove_misp_event(attrib_value, event_id)

            elif json_message['Log']['model'] == "Attribute" and json_message['Log']['action'] == "edit":
                # edit of attribute
                attrib_type = re_attrib_type_value_title.search(json_message['Log']['title']).group(1)
                if attrib_type in IP_MISP_TYPES:
                    event_id = re_event_id_title.search(json_message['Log']['title']).group(1)
                    attrib_id = re_attrib_id_title.search(json_message['Log']['title']).group(1)
                    attrib_value = re_attrib_type_value_title.search(json_message['Log']['title']).group(2)
                    attrib_add_or_edit(attrib_value, event_id, attrib_id)

            elif json_message['Log']['model'] == "Attribute" and json_message['Log']['action'] == "add":
                # new attribute
                # change looks like: "to_ids () => (1), distribution () => (5), type () => (hostname)..."
                attrib = json_message['Log']['change']
                attrib_type = re_attrib_type_change.search(attrib).group(1)
                if attrib_type in IP_MISP_TYPES:
                    event_id = re_event_id_change.search(json_message['Log']['change']).group(1)
                    attrib_id = json_message['Log']['model_id']
                    #try:
                    attrib_value = re_attrib_type_value_title.search(json_message['Log']['title']).group(2)
                    #except AttributeError:
                    #    logger.error(json_message['Log']['title'])
                    #    logger.error("Error", exc_info=True)
                    #    continue
                    attrib_add_or_edit(attrib_value, event_id, attrib_id)

        elif message.startswith("misp_json_sighting"):
            # sighting edit
            sighting = json_message['Sighting']
            # was it sighting of an ip address?
            if sighting['Attribute']['type'] in IP_MISP_TYPES:
                process_sighting_notification(sighting)

        elif message.startswith("misp_json_event"):
            if json_message['action'] == "delete":
                # deletion of MISP event
                # find all ip records, which contains deleted MISP event
                outdated_records = db.aggregate('ip', {'$match': {"misp_events.event_id": json_message['Event']['id']}})
                for ip_record in outdated_records:
                    # from every ip record delete outdated misp record
                    # first id of ip record has to be converted to string IP address
                    ip_address = int2ipstr(ip_record['_id'])
                    remove_misp_event(ip_address, json_message['Event']['id'])


if __name__ == "__main__":
    signal.signal(signal.SIGINT, stop)
    receive_events()
