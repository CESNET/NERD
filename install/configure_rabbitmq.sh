#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure RabbitMQ ==============="

# Configure RMQ queues for 2 workers by default
/nerd/scripts/rmq_reconfigure.sh 2
