#!/bin/sh
# Optional parameter "open" opens http port on all interfaces (default: localhost only)
# Use only in development environment (Vagrant), never in production!

echo "=============== Configure Supervisor ==============="

open_port=0
if [ "$1" = "open" ]; then
  open_port=1
fi

echo "** Copying supervisor config files **"

# Copy main configuration file
cp /tmp/nerd_install/supervisord.conf /etc/nerd/supervisord.conf
if [ $open_port = 1 ]; then
  # replace "localhost:9001" (which should be in the config file) by "*:9001"
  echo "WARNING: SUPERVISORD HTTP PORT IS OPEN ON ALL INTERFACES!"
  sed -i "s/^port=[^:]*/port=*/" /etc/nerd/supervisord.conf
fi

# Copy files specifying individual NERD components running under Supervisor
mkdir -p /etc/nerd/supervisord.conf.d/
cp /tmp/nerd_install/supervisord.conf.d/* /etc/nerd/supervisord.conf.d/

chown -R nerd:nerd /etc/nerd/supervisord.conf
chown -R nerd:nerd /etc/nerd/supervisord.conf.d/

echo "** Set up supervisord systemd unit **"

cp /tmp/nerd_install/nerd-supervisor.service /etc/systemd/system/nerd-supervisor.service
systemctl daemon-reload
systemctl enable nerd-supervisor
#systemctl restart nerd-supervisor

echo "** TO RUN NERD, START ITS SUPERVISOR: systemctl start nerd-supervisor"
