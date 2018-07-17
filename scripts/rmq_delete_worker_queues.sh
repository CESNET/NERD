#!/bin/sh
# Delete all nerd-worker-* queues in RabbitMQ (needed when decreasing number of workers or after some errors)
# Must be run as root.

queue_list=$(rabbitmqadmin list queues name -f tsv | grep "^nerd-worker-")

for q in $queue_list
do
  rabbitmqadmin delete queue name=$q
done
