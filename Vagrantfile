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



##### MongoDB #####
$mongo = <<EOF
echo "** Configuring MongoDB **"

echo "** Setting up MongoDB for NERD (create indexes) **"
mongo nerd /vagrant/mongo_prepare_db.js

EOF

##### PostgreSQL #####

$postgres = <<EOF

echo "** Configuring PostgreSQL database **"

# Create a database for NERD in PostgreSQL
sudo -u postgres /usr/pgsql-9.6/bin/createuser nerd
sudo -u postgres  /usr/pgsql-9.6/bin/createdb --owner nerd nerd

# TODO separate user database (mandatory for web) and event database (which is optional)
# initialize database (create tables etc.)
sudo -u nerd /usr/pgsql-9.6/bin/psql -d nerd -f /vagrant/create_db.sql

# TODO install pgadmin4
# Install pgAdmin4 and set it up to run via WSGI under Apache
# yum install -y pgadmin4
# Run initial setup to set the admin user account
# see https://computingforgeeks.com/how-to-install-pgadmin-4-on-centos-7-fedora-29-fedora-28/
# python /usr/lib/python2.7/site-packages/pgadmin4-web/setup.py


EOF

##### RabbitMQ #####

$rabbitmq = <<EOF

echo "** Configuring RabbitMQ for NERD **"

rabbitmqadmin declare exchange name=nerd-main-task-exchange type=fanout durable=true
rabbitmqadmin declare exchange name=nerd-task-distributor type=x-consistent-hash durable=true
rabbitmqadmin declare binding source=nerd-main-task-exchange destination=nerd-task-distributor destination_type=exchange

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

# TODO copy this from a file
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
<Location ${NERDBaseLoc}login/basic>
    AuthType basic
    AuthName "NERD web"
    AuthUserFile "/vagrant/etc/.htpasswd"
    Require valid-user
#    Require all granted
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
gunzip -f /data/geoip/GeoLite2-City.mmdb.gz

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

##### Supervisor #####

$supervisor = <<EOF

cp /vagrant/install/supervisord.conf /etc/nerd/supervisord.conf
mkdir -p /etc/nerd/supervisord.conf.d/


EOF

##### Create testing users #####

$users = <<EOF

echo "** Creating user accounts **"
sudo -u nerd psql -c "\
  INSERT INTO users (id,groups,name,email) VALUES ('devel:devel_admin','{\"admin\",\"registered\"}','Mr. Developer','test@example.org') ON CONFLICT DO NOTHING;\
  INSERT INTO users (id,groups,name,email) VALUES ('local:test','{\"registered\"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;\
"
# Set password for local test user
htpasswd -bc /vagrant/etc/.htpasswd test test

echo
echo "************************************************************"
echo "Two user accounts for testing are available:"
echo ""
echo "* Administrator/developer - use 'Devel. autologin' option"
echo "* Unprivileged local account - username/password: test/test"
echo ""

EOF

##########


Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: '127.0.0.1' # Main web server (NERDweb)
  config.vm.network "forwarded_port", guest: 15672, host: 15672, host_ip: '127.0.0.1' # RabbitMQ management web interface
  config.vm.network "forwarded_port", guest: 9001, host: 9001, host_ip: '127.0.0.1' # Supervisor web interface
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  config.vm.provision :shell, path: "install/install_basic_dependencies.sh"
  config.vm.provision :shell, path: "install/prepare_environment.sh"
  config.vm.provision :shell, inline: $mongo
  config.vm.provision :shell, inline: $postgres
  config.vm.provision :shell, inline: $rabbitmq
  config.vm.provision :shell, inline: $bind
  config.vm.provision :shell, inline: $warden
  config.vm.provision :shell, inline: $web
  config.vm.provision :shell, inline: $data_files
  config.vm.provision :shell, inline: $supervisor
  config.vm.provision :shell, inline: $users
end
