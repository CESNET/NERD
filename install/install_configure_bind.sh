#!/bin/sh
# Install and configure BIND (supports DNS queries made by various modules)

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Install & Configure BIND ==============="

echob "** Installing BIND **"
yum install -y -q bind bind-utils

echob "** Starting BIND **"
systemctl enable named.service
systemctl restart named.service
