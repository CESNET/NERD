#!/bin/sh
# Install and configure Munin to monitor the host and some metrics of NERD processing.
#
# Note:
# - munin is the master, which queries status of (potentially multiple) hosts
# - munin-node runs on the host and provides provides information to the maser
# In this case, the same host runs both munin (master) and munin-node

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Install & configure Munin ==============="

yum -y -q install munin munin-node

# ** Configure munin-node **
# Allow connections from localhost only
sed -i -e 's/^host \*$/# host \*/' -e 's/^#\s*host 127.0.0.1/host 127.0.0.1/' /etc/munin/munin-node.conf

# Install and enable NERD plugins
cp $BASEDIR/munin/* /usr/share/munin/plugins/
chmod +x /usr/share/munin/plugins/nerd_*
ln -s /usr/share/munin/plugins/nerd_* /etc/munin/plugins/

# Enable Apache and named (BIND) plugins
ln -s /usr/share/munin/plugins/apache_* /etc/munin/plugins/
ln -s /usr/share/munin/plugins/named /etc/munin/plugins/

# Run munin-node
systemctl enable munin-node
systemctl restart munin-node

# ** Enable web access **
# Copy prepared config file for Apache
cp $BASEDIR/httpd/munin.conf /etc/httpd/conf.d/munin.conf

touch /etc/munin/munin-htpasswd

systemctl reload httpd

echoy
echoy "INFO: Munin is available at http://<this_host>/munin/ (if NERD is not installed into \"/\")"
echoy "INFO: To enable access, add an account to /etc/munin/munin-htpasswd:"
echoy "INFO:   htpasswd -B /etc/munin/munin-htpasswd username"

