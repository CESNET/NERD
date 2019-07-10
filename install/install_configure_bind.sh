#!/bin/sh
# Install and configure BIND (supports DNS queries made by various modules)

echo "=============== Install & Configure BIND ==============="

echo "** Installing BIND **"
yum --disableplugin=fastestmirror install -y -q bind bind-utils

echo "** Starting BIND **"
systemctl enable named.service
systemctl restart named.service
