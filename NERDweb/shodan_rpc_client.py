import pika
import uuid

from common.config import read_config

# config - load nerd.yml
config = read_config("/etc/nerd/nerd.yml")
rmq_settings = config.get('rabbitmq', {
    'host': "localhost",
    'port': 5672,
    'virtual_host': "/",
    'username': "guest",
    'password': "guest"
})


class ShodanRpcClient(object):
    def __init__(self):
        rmq_creds = pika.PlainCredentials(rmq_settings['username'], rmq_settings['password'])
        rmq_params = pika.ConnectionParameters(rmq_settings['host'], rmq_settings['port'], rmq_settings['virtual_host'],
                                               rmq_creds)
        self.connection = pika.BlockingConnection(rmq_params)
        self.channel = self.connection.channel()

        result = self.channel.queue_declare(queue='', arguments={'x-message-ttl' : 30000}, exclusive=True)
        self.callback_queue = result.method.queue
        self.response = None
        self.corr_id = None
        self.channel.basic_consume(queue=self.callback_queue, on_message_callback=self.on_response, auto_ack=True)

    def __del__(self):
        if not self.channel.connection.is_closed:
            try:
                self.channel.close()
            except pika.exceptions.ConnectionClosed: # for case it's been closed by the server
                pass

    def on_response(self, ch, method, props, body):
        if self.corr_id == props.correlation_id:
            self.response = body

    def call(self, ip):
        #print("(shodan_rpc_client) Request for {} received".format(str(ip)))
        self.response = None
        self.corr_id = str(uuid.uuid4())
        self.channel.basic_publish(exchange='',
                                   routing_key='shodan_rpc_queue',
                                   properties=pika.BasicProperties(
                                         reply_to=self.callback_queue,
                                         correlation_id=self.corr_id,
                                   ),
                                   body=str(ip))
        #print("(shodan_rpc_client) Request sent to RabbitMQ, waiting for response...")
        
        while self.response is None:
            self.connection.process_data_events()

        #print("(shodan_rpc_client) Response received, returning to web client")
        return str(self.response.decode('utf8'))
