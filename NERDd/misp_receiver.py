#!/usr/bin/env python3
"""
NERD standalone script for receiving MISP instance changes of events, attributes or sightings.
All the changes are then projected to NERD.
"""
import ipaddress
import zmq
import time
import json
import sys
import signal
import logging
import argparse
import os
import threading
import queue
from datetime import timedelta, datetime
from pymisp import PyMISP

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

import NERDd.core.mongodb as mongodb
from common.config import read_config
from common.task_queue import TaskQueueWriter
from common.utils import int2ipstr
from common.threat_categorization import *


##############################################################################
# Initialization

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger('MispReceiver')

# Parse arguments.
parser = argparse.ArgumentParser(prog="misp_receiver.py", description="NERD standalone script for receiving MISP instance changes of events, attributes or sightings.")
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml', help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
parser.add_argument('-v', '--verbose', action='count', default=0, help="Verbose mode")
args = parser.parse_args()
if args.verbose:
    logger.setLevel("DEBUG")

# Load configuration.
logger.info(f"Loading config file {args.config}")
config = read_config(args.config)
config_base_path = os.path.dirname(os.path.abspath(args.config))
common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
logger.info(f"Loading config file {common_cfg_file}")
config.update(read_config(common_cfg_file))

# Read categorization config
categorization_cfg_file = os.path.join(config_base_path, 'threat_categorization.yml')
logger.info(f"Loading config file {categorization_cfg_file}")
config.update(read_config(categorization_cfg_file))
categorization_config = {
    "categories": config.get('threat_categories'),
    "malware_families": read_config(config.get('malpedia_family_list_path'))
}

inactive_ip_lifetime = config.get('record_life_length.misp', 180)

# Connect to NERD DB
db = mongodb.MongoEntityDatabase(config)

# Connect to NERD task queue
rabbit_config = config.get("rabbitmq")
num_processes = config.get('worker_processes')
tq_writer = TaskQueueWriter(num_processes, rabbit_config)
tq_writer.connect()

# Connect to MISP
misp_key = config.get('misp.key', None)
misp_url = config.get('misp.url', None)
misp_zmq_url = config.get('misp.zmq', None)
if not (misp_key and misp_url and misp_zmq_url):
    logger.error("Missing configuration of MISP instance in the configuration file!")
    sys.exit(1)
misp_verify_cert = config.get('misp.verify_cert', True)
misp_inst = PyMISP(misp_url, misp_key, misp_verify_cert)

IP_MISP_TYPES = ["ip-src", "ip-dst", "ip-dst|port", "ip-src|port", "domain|ip"]
THREAT_LEVEL_DICT = {'1': "High", '2': "Medium", '3': "Low", '4': "Undefined"}
ZMQ_HEALTHCHECK_TIMEOUT = 15

notification_queue = queue.Queue()
healthcheck_flag = threading.Event()
running_flag = threading.Event()
running_flag.set()


##############################################################################
# Signal handling

def stop(signum, frame):
    """
    Stop the module by clearing running_flag (so that all threads exit their loops).
    """
    logger.info(f"Signal {signum} received, the module will be stopped.")
    running_flag.clear()
    healthcheck_flag.set()  # wake healthcheck thread if it's waiting


##############################################################################
# MISP helpers

def get_event(event_id):
    """
    Fetch an event via MISP API
    """
    try:
        api_response = misp_inst.get_event(int(event_id))
        return api_response['Event']
    except Exception as e:
        logger.error(f"Failed to fetch event from MISP (event_id={event_id}): {type(e).__name__}: {e}")
    return None


def get_sightings(attr_id):
    """
    Fetch attribute sightings via MISP API
    """
    try:
        api_response = misp_inst.search_sightings(context='attribute', context_id=attr_id)
        return [item['Sighting'] for item in api_response]
    except Exception as e:
        logger.error(f"Failed to fetch sightings from MISP (attr_id={attr_id}): {type(e).__name__}: {e}")
    return None


def get_sightings_for_nerd(sighting_list):
    """
    Generate 'sightings' attribute used for 'misp_events' in NERD.

    MISP sighting types:
      0 = positive
      1 = false positive
      2 = expired attribute
    """
    if not sighting_list:
        return {'positive': 0, 'false positive': 0, 'expired attribute': 0}
    counted_sightings = {'0': 0, '1': 0, '2': 0}
    for sighting in sighting_list:
        if (type := str(sighting.get('type'))) not in counted_sightings:
            logger.warning(f"Unknown sighting type '{type}'")
            continue
        counted_sightings[type] += 1
    return {
        'positive': counted_sightings['0'],
        'false positive': counted_sightings['1'],
        'expired attribute': counted_sightings['2']
    }


def is_single_ip(ip_to_check):
    """
    Return True if ip_to_check is a valid IPv4 address.
    """
    try:
        _ = ipaddress.IPv4Address(ip_to_check)
        return True
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False


def create_new_event(event, role, sightings):
    """
    Create the dictionary containing MISP event information used by NERD.
    """
    new_event = {
        'misp_instance': misp_url,
        'event_id': str(event['id']),
        'org_created': event['Orgc']['name'],
        'tlp': "green",
        'tag_list': [],
        'role': role,
        'info': event['info'],
        'sightings': sightings,
        'date': datetime.strptime(event['date'], "%Y-%m-%d"),
        'threat_level': THREAT_LEVEL_DICT[str(event['threat_level_id'])],
        'last_change': datetime.utcfromtimestamp(int(event['timestamp']))
    }

    for tag in event.get('Tag', []):
        tag_name = tag.get('name', '')
        if not tag_name.lower().startswith("tlp:"):
            new_event['tag_list'].append({
                'name': tag_name,
                'colour': tag.get('colour')
            })
        else:
            new_event['tlp'] = tag_name[4:]

    return new_event


def get_ip_address(attrib):
    """
    Extract the IP address from an attribute.

    Supported attribute types:
      ip-src / ip-dst
      ip-src|port / ip-dst|port
      domain|ip
    """
    attrib_type = attrib.get('type', '')
    value = attrib.get('value', '')
    if attrib_type in ("ip-src", "ip-dst"):
        return value
    if attrib_type in ("ip-src|port", "ip-dst|port"):
        return value.split('|', 1)[0].split(':', 1)[0]
    if attrib_type == "domain|ip":
        parts = value.split('|', 1)
        return parts[1] if len(parts) == 2 else ''


def iter_event_ip_attributes(event):
    """
    Yield all non-deleted, IPv4-bearing attributes from an event, including attributes inside objects.
    """
    for attrib in event.get('Attribute', []):
        if attrib.get('type') in IP_MISP_TYPES and not attrib.get('deleted'):
            ip_addr = get_ip_address(attrib)
            if is_single_ip(ip_addr):
                yield attrib

    for event_obj in event.get('Object', []):
        if event_obj.get('deleted'):
            continue
        for attrib in event_obj.get('Attribute', []):
            if attrib.get('type') in IP_MISP_TYPES and not attrib.get('deleted'):
                ip_addr = get_ip_address(attrib)
                if is_single_ip(ip_addr):
                    yield attrib


def get_ip_attributes(event):
    """
    Return a mapping of IP address to its MISP attribute and role.

    If the same IP occurs multiple times in an event with different roles, its role is combined to "src and dst at the same time".
    """
    ip_attributes = {}
    for attrib in iter_event_ip_attributes(event):
        ip_addr = get_ip_address(attrib)
        ip_role = "src" if "src" in attrib['type'] else "dst"
        if ip_addr in ip_attributes and ip_role != ip_attributes[ip_addr][0]:
            ip_role = 'src and dst at the same time'
        ip_attributes[ip_addr] = (ip_role, attrib)
    return ip_attributes


##############################################################################
# NERD helpers

def remove_misp_event(ip_addr, event_id):
    """
    Remove one MISP event from the NERD 'misp_events' array.
    """
    logger.debug(f"Deleting event {event_id} from the record of {ip_addr}")
    tq_writer.put_task(
        "ip",
        ip_addr,
        [('array_remove', 'misp_events', {
            'misp_instance': misp_url,
            'event_id': str(event_id)
        })],
        "misp_receiver"
    )


def upsert_new_event(event, attrib, ip_addr, ip_role):
    """
    Create/update a NERD misp_event for an IP-bearing attribute.
    """
    new_event = create_new_event(event, ip_role, get_sightings_for_nerd(attrib.get('Sighting')))
    live_till = new_event['date'] + timedelta(days=inactive_ip_lifetime)

    # misp event updates
    updates = [
        (
            'array_upsert',
            'misp_events',
            {
                'misp_instance': misp_url,
                'event_id': str(event['id'])
            },
            [
                ('set', key, value) for key, value in new_event.items()
            ]
        ),
        ('setmax', '_ttl.misp', live_till),
        ('setmax', 'last_activity', new_event['date'])
    ]

    # threat categorization updates
    for category_data in classify_ip(ip_addr, "misp_receiver", logger, categorization_config, new_event, attrib, ip_role):
        subcategory_updates = []
        for subcategory, values in category_data['subcategories'].items():
            subcategory_updates.append(('extend_set', subcategory, values))
        updates.append((
            'array_upsert',
            '_threat_category',
            {'d': category_data['date'], 'c': category_data['id']},
            [('add', 'src.misp', 1), *subcategory_updates]
        ))

    logger.debug(f"Updates for {ip_addr}:\n{updates}")
    tq_writer.put_task(
        "ip",
        ip_addr,
        updates,
        "misp_receiver"
    )


def get_db_records_with_event(event_id):
    """
    Fetch IP records that currently contain the given event.
    """
    return db.aggregate(
        'ip',
        {
            '$match': {
                'misp_events': {
                    '$elemMatch': {
                        'misp_instance': misp_url,
                        'event_id': str(event_id)
                    }
                }
            }
        }
    )


##############################################################################
# ZMQ notification processing

def process_misp_json_notification(notification):
    """
    Process misp_json notifications (sent when an event is published).

    The messages contain the MISP event data along with all its component children.
    """

    if not (event := notification.get('Event')):
        logger.warning("Received 'misp_json' notification with no event")
        return

    event_id = str(event['id'])
    logger.debug(f"Event {event_id} published")

    # Extract the complete list of IPs from the newly published event
    ip_attributes = get_ip_attributes(event)

    # Find IPs that currently contain this event in NERD
    old_ips = {int2ipstr(rec['_id']) for rec in get_db_records_with_event(event_id)}

    # Add/update the DB record for all IPs present in the new event
    for ip_addr, (ip_role, attrib) in ip_attributes.items():
        upsert_new_event(event, attrib, ip_addr, ip_role)

    # Remove the event from IPs that are no longer present
    for ip_addr in old_ips - set(ip_attributes):
        remove_misp_event(ip_addr, event_id)


def process_misp_json_event_notification(notification):
    """
    Process misp_json_event notifications (sent when an event is added, edited, or deleted).

    We only care about deletion here as add/edit is handled when the event is published.
    """

    if not (event := notification.get('Event')):
        logger.warning("Received 'misp_json_event' notification with no event")
        return

    if notification.get('action') == 'delete':
        event_id = str(event['id'])
        logger.debug(f"Event {event_id} deleted")
        for rec in get_db_records_with_event(event_id):
            ip_addr = int2ipstr(rec['_id'])
            remove_misp_event(ip_addr, event_id)


def process_misp_json_sighting_notification(notification):
    """
    Process sighting notifications.

    If the IP and the corresponding event exists in NERD, just update the sightings dict with the current values,
    otherwise fetch the whole event via MISP API and create a new event record.
    """

    if not (sighting := notification.get('Sighting')):
        logger.warning("Received 'misp_json_sighting' notification with no sighting")
        return

    event_id = str(sighting['event_id'])
    attrib = sighting['Attribute']
    if attrib['type'] not in IP_MISP_TYPES:
        return

    ip_addr = get_ip_address(attrib)
    if not is_single_ip(ip_addr):
        return
    logger.debug(f"New sighting for {ip_addr}")

    # IP and event are in NERD DB already -> just update sightings (query MISP API to get the current values)
    if rec := db.get("ip", ip_addr):
        for evtrec in rec.get('misp_events', []):
            if misp_url == evtrec['misp_instance'] and event_id == evtrec['event_id']:
                if sighting_list := get_sightings(attrib['id']):
                    tq_writer.put_task(
                        "ip",
                        ip_addr,
                        [(
                            'array_upsert',
                            'misp_events',
                            {'misp_instance': misp_url, 'event_id': str(event_id)},
                            [('set', 'sightings', get_sightings_for_nerd(sighting_list))]
                        )],
                        "misp_receiver"
                    )
                    return

    # IP or event is not in NERD DB yet -> create new event record
    if event := get_event(event_id):
        if ip_addr not in (ip_attributes := get_ip_attributes(event)):
            logger.warning(f"IP {ip_addr} from sighting {sighting['id']} was not found in event {event_id}")
            return
        ip_role, event_attrib = ip_attributes[ip_addr]
        upsert_new_event(event, event_attrib, ip_addr, ip_role)


def processing_loop():
    """
    Process notifications in the queue.
    """
    logger.info(f"Processing started")

    while running_flag.is_set():
        try:
            topic, notification, message = notification_queue.get(timeout=1)
        except queue.Empty:
            continue

        try:
            if handler := globals().get(f"process_{topic}_notification"):
                handler(notification)
            else:
                logger.debug(f"Notification ignored (no handler for topic '{topic}')")
        except Exception as e:
            logger.exception(f"Failed to process {topic} notification: {type(e).__name__}: {e}")
            running_flag.clear()
        finally:
            notification_queue.task_done()

    logger.info(f"Processing stopped")


##############################################################################
# ZMQ notification receiver

def receiver_loop():
    """
    Connect to MISP's ZeroMQ, listen for notifications and store them in the processing queue.
    """
    logger.info(f"Receiver started")

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.RCVTIMEO, 2000)

    logger.info(f"Connecting to ZMQ at {misp_zmq_url}")
    socket.connect(misp_zmq_url)

    # Subscribe to all MISP topics
    # The topic is the first token in the received message, followed by a JSON object
    socket.setsockopt(zmq.SUBSCRIBE, b'')

    while running_flag.is_set():
        try:
            message = socket.recv()
            healthcheck_flag.set()  # wake healthcheck
        except zmq.Again:
            continue
        except zmq.ZMQError as e:
            if running_flag.is_set():
                logger.error(f"ZMQ receive error: {e}")
                time.sleep(2)
            continue

        try:
            message = message.decode("utf-8")
            topic, _, notification_str = message.partition(" ")
            notification = json.loads(notification_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.error(f"Invalid ZMQ message: {type(e).__name__}: {e}")
            continue

        if args.verbose > 1:
            logger.debug(f"Received new message (topic={topic}):\n{message}")

        # Keep-alive messages are logged for debugging, other notifications are put in the processing queue
        if topic == "misp_json_self":
            logger.debug(f"Keep-alive: {notification.get('status')} (uptime={notification.get('uptime')})")
        else:
            notification_queue.put((topic, notification, message))

    # Close ZMQ connection
    socket.close(linger=0)
    context.term()
    logger.info(f"Receiver stopped")


##############################################################################
# ZMQ healthcheck

def wait_for_message():
    """
    Return True if a message is received (healthcheck flag is set) during the waiting interval, otherwise return False.
    """
    message_received = healthcheck_flag.wait(timeout=ZMQ_HEALTHCHECK_TIMEOUT)
    if not message_received:
        return False
    healthcheck_flag.clear()
    return True


def healthcheck_loop():
    """
    Check that ZMQ messages are being received (keep-alive messages should be sent every 10 seconds).
    """
    logger.info(f"Healthcheck started")

    # If the connection cannot be verified on startup, stop the module
    if not wait_for_message():
        logger.error(f"Cannot verify connection to ZMQ (no message received within {ZMQ_HEALTHCHECK_TIMEOUT}s). The module will be stopped.")
        running_flag.clear()
        return
    logger.info("ZMQ connection OK")

    zmq_alive = True
    while running_flag.is_set():
        if wait_for_message():
            if not zmq_alive:
                logger.info("ZMQ connection OK")
                zmq_alive = True
        elif zmq_alive:
            logger.error(f"ZMQ connection lost (no message received for {ZMQ_HEALTHCHECK_TIMEOUT}s)")
            zmq_alive = False

    logger.info(f"Healthcheck stopped")


##############################################################################
# Main

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # Start processing thread
    processing_thread = threading.Thread(target=processing_loop)
    processing_thread.daemon = True
    processing_thread.start()

    # Start healthcheck thread
    healthcheck_thread = threading.Thread(target=healthcheck_loop)
    healthcheck_thread.daemon = True
    healthcheck_thread.start()

    # Receive ZMQ messages until stopped
    receiver_loop()

    # Cleanup
    processing_thread.join()
    healthcheck_thread.join()
