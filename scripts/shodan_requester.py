#!/usr/bin/env python3

import sys
import requests
import pika
from argparse import ArgumentParser
from cachetools import TTLCache
import json

rmq_creds = pika.PlainCredentials('guest', 'guest')
rmq_params = pika.ConnectionParameters('localhost', 5672, '/', rmq_creds)
connection = pika.BlockingConnection(rmq_params)
channel = connection.channel()
channel.queue_declare(queue='shodan_rpc_queue', arguments={'x-message-ttl' : 30000}) # set ttl of messages to 30 sec

# dictionary in format: { 'ipaddr': {ttl: time, data: data}}
cache = TTLCache(maxsize=128, ttl=3600)


def get_shodan_data(ip):
    if ip in cache:
        print("cache hit for {}".format(ip))
        data = cache[ip]
    else:
        url = 'https://api.shodan.io/shodan/host/{ip}?key={api_key}'.format(ip=ip, api_key=api_key)
        resp = requests.get(url)
        if resp.status_code == 200:
            cache[ip] = resp.content
            data = resp.content
        else:
            if resp.status_code != 404:
                print("Error response for url: {}\n{}".format(url, resp.content))
            try:
                response_dict = json.loads(resp.text)
            except Exception:
                return json.dumps({"error": "Shodan returned invalid response"})
            data = json.dumps({"error": response_dict["error"] if "error" in response_dict else "Unknown error"})

    return data

def on_request(ch, method, props, body):
    ip = str(body, 'utf-8')
    print("Received request for ip '{}'".format(ip))
    response = get_shodan_data(ip)
    ch.basic_publish(exchange='',
                     routing_key=props.reply_to,
                     properties=pika.BasicProperties(correlation_id=props.correlation_id),
                     body=response)
    ch.basic_ack(delivery_tag=method.delivery_tag)

# Get API key, either directly from parameter or from a file
arg_parser = ArgumentParser()
group = arg_parser.add_mutually_exclusive_group(required=True)
group.add_argument('-k', '--api-key', help='Shodan API key')
group.add_argument('-f', '--api-key-file', default='/etc/nerd/shodan_key', help='Path to a file with shodan API key stored')
args = arg_parser.parse_args()

if args.api_key:
    api_key = args.api_key
else:
    try:
        with open(args.api_key_file, "r") as f:
            api_key = f.read().strip()
    except IOError as e:
        print("Can't open file with Shodan API key. Please, put the key into '{}'".format(args.api_key_file), file=sys.stderr)
        sys.exit(1)


channel.basic_qos(prefetch_count=1)
channel.basic_consume(on_request, queue='shodan_rpc_queue')

print("*** Shodan request handler started, awaiting RPC requests ***")
channel.start_consuming()
