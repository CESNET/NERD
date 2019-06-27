#!/bin/sh

echo "=============== Configure RabbitMQ ==============="

echo "** Configuring RabbitMQ for NERD **"

# Declare exchanges (normal and priority)
rabbitmqadmin declare exchange name=nerd-main-task-exchange type=direct durable=true
rabbitmqadmin declare exchange name=nerd-priority-task-exchange type=direct durable=true

# Declare queues for 2 workers
rabbitmqadmin declare queue name=nerd-worker-0 durable=true 'arguments={"x-max-length":100}'
rabbitmqadmin declare queue name=nerd-worker-0-pri durable=true

rabbitmqadmin declare queue name=nerd-worker-1 durable=true 'arguments={"x-max-length":100}'
rabbitmqadmin declare queue name=nerd-worker-1-pri durable=true

# Bind queues to exchanges
rabbitmqadmin declare binding source=nerd-main-task-exchange destination=nerd-worker-0 routing_key=0
rabbitmqadmin declare binding source=nerd-main-task-exchange destination=nerd-worker-1 routing_key=1
rabbitmqadmin declare binding source=nerd-priority-task-exchange destination=nerd-worker-0-pri routing_key=0
rabbitmqadmin declare binding source=nerd-priority-task-exchange destination=nerd-worker-1-pri routing_key=1
