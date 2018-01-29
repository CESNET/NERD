# -*- mode: ruby -*-
# vi: set ft=ruby :

###############################################################################
# This Vagrantfile creates a VM and installs and configures all dependencies
# needed to run NERD.
# It's intended for development/debugging, so there are some differences from
# produciton dpeloyment:
# - Web interface doesn't use any authentication, full access is automatically
#   granted.
# - Web interface is available only via plain HTTP.
# - NERDd must be started manually.
# - Warden data must be copied from somewhere (or warden_receiver registered 
#   and started manually)
#
###############################################################################

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.

##### Install some basic yum packages #####

$basic_packages = <<EOF

echo "** Installing packages **"
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum install -y git wget gcc vim python34 python34-devel


EOF

##### Install various Python packages needed by NERD #####

$python_packages = <<EOF

echo "** Installing pip and Python packages **"
wget -q https://bootstrap.pypa.io/get-pip.py
python3.4 get-pip.py
rm -f get-pip.py
pip3 install -r /vagrant/NERDd/requirements.txt
pip3 install -r /vagrant/NERDweb/requirements.txt

# Patch bgpranking_web to work in Python 3
echo 'import sys
if sys.version_info[0] == 2:
    from api import *
else:
    from .api import *
' > /usr/lib/python3.4/site-packages/bgpranking_web/__init__.py

EOF

##### Install MongoDB #####
$mongo = <<EOF
echo "** Installing MongoDB **"

echo '[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=0
enabled=1
' > /etc/yum.repos.d/mongodb-org-3.2.repo

yum install -y mongodb-org

echo "** Starting MongoDB **"
/sbin/chkconfig mongod on
systemctl start mongod.service

echo "** Setting up MongoDB for NERD (create indexes) **"
mongo nerd /vagrant/mongo_prepare_db.js

EOF

##### Install and configure PostgreSQL #####

$postgres = <<EOF

echo "** Installing PostgreSQL **"
yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-centos96-9.6-3.noarch.rpm
yum install -y postgresql96-server postgresql96-devel
PATH=$PATH:/usr/pgsql-9.6/bin
export PATH

echo "** Configuring and starting PostgreSQL **"
#adduser postgres
mkdir -p /data/pgsql
chown -R postgres /data/pgsql
sudo -u postgres /usr/pgsql-9.6/bin/initdb -D /data/pgsql
sed -i "s,PGDATA=.*$,PGDATA=/data/pgsql," /lib/systemd/system/postgresql-9.6.service

systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service

echo "** Creating a database for NERD in PostgreSQL **"
/usr/pgsql-9.6/bin/createuser -U postgres nerd
/usr/pgsql-9.6/bin/createdb -U postgres --owner nerd nerd

# initialize database (create tables etc.)
/usr/pgsql-9.6/bin/psql -d nerd -U nerd -f /vagrant/create_db.sql

EOF

##### Install and configure BIND and download zone files #####

$bind = <<EOF

echo "** Installing BIND **"
yum install -y bind bind-utils

echo "** Downloading origin AS zone file from routeviews.org **"
mkdir -p /etc/named/zones
# The grep removes "short" entries such as "3.2.1" and only leaves "*.3.2.1" or "4.3.2.1",
# since NERD always asks for full IPv4
wget -q -O - 'http://archive.routeviews.org/dnszones/originas.bz2' | bunzip2 | \ 
  grep -E "^\\*\\.|^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\s" > /etc/named/zones/originas

echo "** Configuring zone files **"
# configure asn.localhost. zone for ASN plugin
echo 'include "/etc/named/named.conf.local";' >> /etc/named.conf
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
systemctl start named.service

EOF


##### Install Warden filer #####

$warden = <<EOF

echo "** Downloading Warden filer **"
wget -q https://homeproj.cesnet.cz/tar/warden/contrib_3.0-beta2.tar.bz2
tar -xf contrib_3.0-beta2.tar.bz2
cp -r contrib_3.0-beta2/warden_filer/ /data/
rm -rf contrib_3.0-beta2.tar.bz2 contrib_3.0-beta2

EOF

##### Configure Apache #####

$web = <<EOF

echo "** Installing WSGI **"
yum install -y httpd httpd-devel mod_wsgi
pip3 install mod_wsgi

rm -f /usr/lib64/httpd/modules/mod_wsgi.so
ln -s /usr/lib64/python3.4/site-packages/mod_wsgi/server/mod_wsgi-py34.cpython-34m.so /usr/lib64/httpd/modules/mod_wsgi.so

echo "** Configuring Apache **"
echo '
# NERD (Flask app)

Define NERDBaseLoc /
Define NERDBaseDir /vagrant/NERDweb

# Set up WSGI script (use debug version since Vagrant is used only for development/debugging)
WSGIDaemonProcess nerd_wsgi python-path=${NERDBaseDir}
#WSGIScriptAlias ${NERDBaseLoc} ${NERDBaseDir}/wsgi.py
WSGIScriptAlias ${NERDBaseLoc} ${NERDBaseDir}/wsgi-debug.py

<Location ${NERDBaseLoc}>
    WSGIProcessGroup nerd_wsgi
</Location>

<Directory ${NERDBaseDir}>
    <Files wsgi-debug.py>
        Require all granted
    </Files>
</Directory>

# Static files must be served direcly by Apache, not by Django/Flask
Alias ${NERDBaseLoc}/static/ ${NERDBaseDir}/static/
<Directory ${NERDBaseDir}/static>
    Require all granted
</Directory>

# Authentication using local accounts
<Location ${NERDBaseLoc}/login/basic>
#    AuthType basic
#    AuthName "NERD web"
#    AuthUserFile "/vagrant/NERD/etc/.htpasswd"
#    Require valid-user
    Require all granted
</Location>

# API handlers
<Location ${NERDBaseLoc}api>
    # Pass Authorization header
    WSGIPassAuthorization On
    # Return JSON-formatted error message in case something goes wrong.
    ErrorDocument 500 "{\\"err_n\\": 500, \\"error\\": \\"Internal Server Error\\"}"
</Location>

<VirtualHost *:80>
</VirtualHost>
' > /etc/httpd/conf.d/nerd.conf

# (not needed, default is to allow everything)
#echo "** Setting up firewall **"
#iptables -I INPUT 1 -p TCP --dport 80 -j ACCEPT
#iptables -I INPUT 1 -p TCP --dport 5000 -j ACCEPT
#iptables-save > /etc/sysconfig/iptables

echo "** Disabling SELinux **"
# Disable for now (until reboot)
setenforce 0
# Disable permanently
sed -i --follow-symlinks -e 's/^SELINUX=.*$/SELINUX=disabled/' /etc/sysconfig/selinux

echo "** Starting Apache **"
systemctl enable httpd
systemctl start httpd

EOF


##### Prepare various data files #####

$data_files = <<EOF

echo "** Downloading GeoIP database **"
mkdir -p /data/geoip
wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz
gunzip /data/geoip/GeoLite2-City.mmdb.gz

echo "** Copying CAIDA AS-type mapping file **"
# Copy caida file (if present)
if [ -f /vagrant/caida-as2types.txt ]; then
    cp /vagrant/caida-as2types.txt /data/caida-as2types.txt
else
    echo "Warning: caida-as2types.txt not found, AS type classification will be disabled." 1>&2 
fi

echo "** Copying/downloading whois data **" 

if ! [ -f /vagrant/nerd-whois-asn.csv -o -f /vagrant/nerd-whois-asn.csv ]; then
    echo "Downloading and processing whois data from RIRs"
    cd /vagrant
    python3 /vagrant/scripts/get_iana_assignment_files.py
    cd -
fi
cp /vagrant/nerd-whois-asn.csv /tmp/nerd-whois-asn.csv
cp /vagrant/nerd-whois-ipv4.csv /tmp/nerd-whois-ipv4.csv

echo "** Creating various directories and setting up permissions **"

# directory for incoming IDEA files
mkdir -p /data/warden_filer/warden_receiver/{incoming,temp,errors}
chown -R vagrant:vagrant ~vagrant/ /data/warden_filer

# local_bl plugin stores data into /data/local_bl:
mkdir -p /data/local_bl
chown -R vagrant:vagrant /data/local_bl

chown vagrant:vagrant /data

EOF


##########


$start = <<SCRIPT
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.network "forwarded_port", guest: 80, host: 2280
  config.vm.network "forwarded_port", guest: 5000, host: 5000
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  config.vm.provision :shell, inline: $basic_packages
  config.vm.provision :shell, inline: $python_packages
  config.vm.provision :shell, inline: $mongo
  config.vm.provision :shell, inline: $postgres
  config.vm.provision :shell, inline: $bind
  config.vm.provision :shell, inline: $warden
  config.vm.provision :shell, inline: $web
  config.vm.provision :shell, inline: $data_files
end
