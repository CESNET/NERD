#!/bin/sh
# Install and configure BIND (supports DNS queries made bz various modules)

echo "=============== Install & Configure BIND ==============="

echo "** Installing BIND **"
yum install -y bind bind-utils

# Configuration for ASN plugin
# TODO: This should be re-done periodically
echo "** Downloading origin AS zone file from routeviews.org **"
mkdir -p /etc/named/zones
# The grep removes "short" entries such as "3.2.1" and only leaves "*.3.2.1" or "4.3.2.1",
# since NERD always asks for full IPv4
wget -q -O - 'http://archive.routeviews.org/dnszones/originas.bz2' | bunzip2 | \
  grep -E "^\\*\\.|^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\s" > /etc/named/zones/originas

echo "** Configuring zone files **"
# configure asn.localhost. zone for ASN plugin
if ! grep -q '^include "/etc/named/named\.conf\.local";' /etc/named.conf ; then
  echo 'include "/etc/named/named.conf.local";' >> /etc/named.conf
fi
echo 'zone "asn.localhost" {
   type master;
   file "/etc/named/zones/db.asn.localhost"; # zone file path
};' > /etc/named/named.conf.local

echo '
$TTL    60480
@       IN      SOA     asn.localhost. asn.localhost. (
                 3     ; Serial
             60480     ; Refresh
              8640     ; Retry
            241920     ; Expire
             60480 )   ; Negative Cache TTL

@       IN      NS      asn.localhost.
@       IN      A       127.0.0.1

$INCLUDE /etc/named/zones/originas
' > /etc/named/zones/db.asn.localhost


echo "** Starting BIND (may take a long time since it needs to load large zone files) **"
# Disable pre-start zone_checking and increase timeout
mkdir -p /etc/systemd/system/named.service.d/
echo '
[Service]
Environment="DISABLE_ZONE_CHECKING=yes"
TimeoutStartSec=300
' > /etc/systemd/system/named.service.d/override.conf
systemctl daemon-reload

systemctl enable named.service
systemctl restart named.service
