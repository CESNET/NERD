#!/usr/bin/env python3

import os
import sys
import requests
import argparse
import json
from datetime import datetime
import logging

from cachetools import TTLCache
import pika

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.config import read_config

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

logger = logging.getLogger('Shodan_requester')

# parse arguments
parser = argparse.ArgumentParser(
    prog="shodan_requester.py",
    description="NERD standalone, which will get info about IP from Shodan service when requested."
)
parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerd.yml',
                    help='Path to configuration file (default: /etc/nerd/nerd.yml)')
parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose mode")
args = parser.parse_args()

if args.verbose:
    logger.setLevel("DEBUG")

# config - load nerd.yml
logger.info("Loading config file {}".format(args.config))
config = read_config(args.config)

api_key = config.get('shodan_api_key')
rmq_settings = config.get('rabbitmq')
if not api_key:
    logger.error("Cannot load Shodan API key, make sure it is properly configured in {}.".format(args.config))
    sys.exit(1)

try:
    rmq_creds = pika.PlainCredentials(rmq_settings['username'], rmq_settings['password'])
    rmq_params = pika.ConnectionParameters(rmq_settings['host'], rmq_settings['port'], rmq_settings['virtual_host'],
                                           rmq_creds)
except KeyError:
    logger.error("RabbitMQ settings are not configured properly, make sure it is properly configured in {}.".format(
                 args.config))
    sys.exit(1)

connection = pika.BlockingConnection(rmq_params)
channel = connection.channel()
channel.queue_declare(queue='shodan_rpc_queue', arguments={'x-message-ttl' : 30000}) # set ttl of messages to 30 sec

# dictionary in format: { 'ipaddr': {ttl: time, data: data}}
cache = TTLCache(maxsize=10000, ttl=3600)


def get_shodan_data(ip):
    if ip in cache:
        logger.debug("cache hit for {}".format(ip))
        data = cache[ip]
    else:
        url = 'https://api.shodan.io/shodan/host/{ip}?key={api_key}'.format(ip=ip, api_key=api_key)
        # Send request to Shodan API
        # expected result is a JSON with many keys containing details about the IP
        # (of 404 if there are no data for given IP)
        resp = requests.get(url)
        logger.debug(f"Shodan response status code: {resp.status_code}")
        if resp.status_code == 429:
            return json.dumps({"error": "Shodan API rate-limit exceeded"})
        if resp.status_code not in (200, 404):
            logger.error(f"Shodan returned unexpected response ({resp.status_code}): {resp.content[:1000]}")
            return json.dumps({"error": f"Shodan returned unexpected response ({resp.status_code})"})

        try:
            response_dict = json.loads(resp.text)
        except ValueError:
            logger.error("Error response for url: {}\n{}".format(url, resp.content))
            return json.dumps({"error": "Shodan returned invalid response"})

        # Only extract fields that are actually used in NERD
        # (some responses can be so large they hit a default message size limit in RabbitMQ. It could be increased,
        #  but we don't need most of the data anyway)
        keys_used = {'ports', 'os', 'tags', 'error'}
        response_dict2 = {k: response_dict[k] for k in (response_dict.keys() & keys_used)}

        data = json.dumps(response_dict2)

        # store returned data (or info that there's no data) to cache
        cache[ip] = data

    return data


def on_request(ch, method, props, body):
    ip = str(body, 'utf-8')
    logger.debug("Received request for '{}'".format(ip))
    response = get_shodan_data(ip)
    ch.basic_publish(exchange='',
                     routing_key=props.reply_to,
                     properties=pika.BasicProperties(correlation_id=props.correlation_id),
                     body=response)
    ch.basic_ack(delivery_tag=method.delivery_tag)
    logger.debug("Sent response for '{}'".format(ip))


channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue='shodan_rpc_queue', on_message_callback=on_request)

logger.info("*** Shodan request handler started, awaiting RPC requests ***")
channel.start_consuming()
