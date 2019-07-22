#!/bin/sh
# Creates a system user and various directories

echo "=============== Prepare environment =============="

echo "** Creating user 'nerd' **"

useradd --system --home-dir /nerd --shell /sbin/nologin nerd


echo "** Creating NERD directories and setting up permissions **"
# Note: "chown" and "chown" use -R flag for a case there already is something 
# in the directories from a previous installation.

# Code base (executables, scripts, etc.)
mkdir -p /nerd
chown -R nerd:nerd /nerd
chmod -R 775 /nerd

# Configuration directory
mkdir -p /etc/nerd
chown -R nerd:nerd /etc/nerd
chmod -R 775 /etc/nerd

# Log directory
mkdir -p /var/log/nerd
chown -R nerd:nerd /var/log/nerd
chmod -R 775 /var/log/nerd

# Data directory
mkdir -p /data
chown -R nerd:nerd /data
chmod -R 775 /data

# local_bl plugin stores data into /data/local_bl  # TODO: should modules be handled in the main installation script?
mkdir -p /data/local_bl
chown -R nerd:nerd /data/local_bl
chmod -R 775 /data/local_bl

# directory to where blacklists are rsync'ed
mkdir -p /data/blacklists
chown -R nerd:nerd /data/blacklists
chmod -R 775 /data/blacklists

