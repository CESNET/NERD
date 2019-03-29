#!/bin/sh

echo "=============== Configure RabbitMQ ==============="

echo "** Configuring RabbitMQ for NERD **"

rabbitmqadmin declare exchange name=nerd-main-task-exchange type=fanout durable=true
rabbitmqadmin declare exchange name=nerd-task-distributor type=x-consistent-hash durable=true
rabbitmqadmin declare binding source=nerd-main-task-exchange destination=nerd-task-distributor destination_type=exchange
