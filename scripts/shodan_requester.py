#!/usr/bin/env python3

import requests
import pika
from argparse import ArgumentParser
from cachetools import TTLCache
import json
from datetime import datetime

rmq_creds = pika.PlainCredentials('guest', 'guest')
rmq_params = pika.ConnectionParameters('localhost', 5672, '/', rmq_creds)
connection = pika.BlockingConnection(rmq_params)
channel = connection.channel()
channel.queue_declare(queue='shodan_rpc_queue', arguments={'x-message-ttl' : 30000}) # set ttl of messages to 30 sec

# dictionary in format: { 'ipaddr': {ttl: time, data: data}}
cache = TTLCache(maxsize=128, ttl=3600)


def get_shodan_data(ip):
    if ip in cache:
        print("{} Cache hit for {}".format(datetime.now().isoformat(), ip))
        data = cache[ip]
    else:
        url = 'https://api.shodan.io/shodan/host/{ip}?key={api_key}'.format(ip=ip, api_key=api_key)
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.content
        else:
            if resp.status_code != 404:
                print("Error response for url: {}\n{}".format(url, resp.content))
            try:
                response_dict = json.loads(resp.text)
            except Exception:
                return json.dumps({"error": "Shodan returned invalid response"})
            data = json.dumps({"error": response_dict["error"] if "error" in response_dict else "Unknown error"})
        
        if resp.status_code == 200 or resp.status_code == 404:
            # store returned data (or info that there's no data) to cache
            cache[ip] = data

    return data

def on_request(ch, method, props, body):
    ip = str(body, 'utf-8')
    print("{} Received request for '{}'".format(datetime.now().isoformat(), ip))
    response = get_shodan_data(ip)
    ch.basic_publish(exchange='',
                     routing_key=props.reply_to,
                     properties=pika.BasicProperties(correlation_id=props.correlation_id),
                     body=response)
    ch.basic_ack(delivery_tag=method.delivery_tag)
    print("{} Sent response for '{}'".format(datetime.now().isoformat(), ip))


argument_parser = ArgumentParser()
argument_parser.add_argument('-k', '--api-key', help='Shodan API key', required=True)
args = argument_parser.parse_args()
api_key = args.api_key

channel.basic_qos(prefetch_count=1)
channel.basic_consume(on_request, queue='shodan_rpc_queue')

print(" [x] Awaiting RPC requests")
channel.start_consuming()
