from time import sleep
import signal
import requests
import pika
from time import time, sleep

api_key = 'WPucWws6cwXKbvFTHsGIGsXqsjS4IHKs'
rmq_creds = pika.PlainCredentials('guest', 'guest')
rmq_params = pika.ConnectionParameters('localhost', 5672, '/', rmq_creds)
connection = pika.BlockingConnection(rmq_params)
channel = connection.channel()
channel.queue_declare(queue='shodan_rpc_queue')

# dictionary in format: { 'ipaddr': {ttl: time, data: data}}
cache = dict()
# number of seconds for data validity
ttl = 3600

max_requests_for_second = 1
time_for_one_request = 1 / max_requests_for_second


def get_shodan_data(ip):
    if ip in cache and cache[ip]['ttl'] < time():
        print("cache hit for {}".format(ip))
        return cache[ip]['data']
    else:
        url = 'https://api.shodan.io/shodan/host/{ip}?key={api_key}'.format(ip=ip, api_key=api_key)
        start = time()
        resp = requests.get(url)
        end = time()
        if end - start < time_for_one_request:
            sleep(time_for_one_request - (end - start))
        if resp.status_code == 200:
            cache[ip] = {
                'ttl': time() + ttl,
                'data': resp.content
            }
    return resp.content


def on_request(ch, method, props, body):
    ip = str(body, 'utf-8')
    print("Received request for ip '{}'".format(ip))
    response = get_shodan_data(ip)
    ch.basic_publish(exchange='',
                     routing_key=props.reply_to,
                     properties=pika.BasicProperties(correlation_id=props.correlation_id),
                     body=response)
    ch.basic_ack(delivery_tag=method.delivery_tag)


channel.basic_qos(prefetch_count=1)
channel.basic_consume(on_request, queue='shodan_rpc_queue')

print(" [x] Awaiting RPC requests")
channel.start_consuming()
