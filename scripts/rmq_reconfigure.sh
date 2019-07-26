#!/bin/bash

# TODO: check that NERD components are not running somehow

if ! echo "$1" | grep -E '^[0-9]+$' >/dev/null; then
  echo "(Re)configure RabbitMQ exchanges and queues for NERD workers." >&2
  echo "Number of workers must be a non-negative integer." >&2
  echo "Zero means to remove all NERD exchanges and queues." >&2
  echo >&2
  echo "Usage: $0 number_of_workers" >&2
  exit 1
fi

N=$1

echo "** Removing all NERD exchanges and queues **"

exchange_list=$(rabbitmqadmin list exchanges name -f tsv | grep "^nerd-.*-task-exchange")
for q in $exchange_list
do
  rabbitmqadmin delete exchange name=$q
done

queue_list=$(rabbitmqadmin list queues name -f tsv | grep "^nerd-worker-")
for q in $queue_list
do
  rabbitmqadmin delete queue name=$q
done

if [[ "$N" -eq 0 ]]; then
  exit 0
fi

echo "** Setting up exchanges and queues for $N workers **"

# Declare exchanges (normal and priority)
rabbitmqadmin declare exchange name=nerd-main-task-exchange type=direct durable=true
rabbitmqadmin declare exchange name=nerd-priority-task-exchange type=direct durable=true

# Declare queues for N workers
for i in $(seq 0 $(($N-1)))
do
  rabbitmqadmin declare queue name=nerd-worker-$i durable=true 'arguments={"x-max-length": 100, "x-overflow": "reject-publish"}'
  rabbitmqadmin declare queue name=nerd-worker-$i-pri durable=true
done

# Bind queues to exchanges
for i in $(seq 0 $(($N-1)))
do
  rabbitmqadmin declare binding source=nerd-main-task-exchange destination=nerd-worker-$i routing_key=$i
  rabbitmqadmin declare binding source=nerd-priority-task-exchange destination=nerd-worker-$i-pri routing_key=$i
done
