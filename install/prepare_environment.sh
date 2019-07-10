#!/bin/sh
# Creates a system user and various directories

echo "=============== Prepare environment =============="

echo "** Creating user 'nerd' **"

useradd --system --home-dir /nerd --shell /sbin/nologin nerd


echo "** Creating NERD directories and setting up permissions **"

# Code base (executables, scripts, etc.)
mkdir -p /nerd
chown nerd:nerd /nerd
chmod 775 /nerd

# Configuration directory
mkdir -p /etc/nerd
chown nerd:nerd /etc/nerd
chmod 775 /etc/nerd

# Log directory
mkdir -p /var/log/nerd
chown nerd:nerd /var/log/nerd
chmod 775 /var/log/nerd

# Data directory
mkdir -p /data
chown nerd:nerd /data
chmod 775 /data

# local_bl plugin stores data into /data/local_bl  # TODO: should modules be handled in the main installation script?
mkdir -p /data/local_bl
chown nerd:nerd /data/local_bl
chmod 775 /data/local_bl

# directory to where blacklists are rsync'ed
mkdir -p /data/blacklists
chown nerd:nerd /data/blacklists
chmod 775 /data/blacklists

