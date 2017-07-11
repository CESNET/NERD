# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.

$dependencies = <<SCRIPT
echo '[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=0
enabled=1
' > /etc/yum.repos.d/mongodb-org-3.2.repo

# install dependencies
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-centos96-9.6-3.noarch.rpm
yum install -y mongodb-org git wget python34 python34-devel httpd gcc postgresql96-server postgresql96-devel mod_wsgi httpd-devel vim
PATH=$PATH:/usr/pgsql-9.6/bin
export PATH
wget -q https://bootstrap.pypa.io/get-pip.py
python3.4 get-pip.py
rm get-pip.py
pip3 install -r /vagrant/NERDd/requirements.txt
pip3 install -r /vagrant/NERDweb/requirements.txt
pip3 install mod_wsgi

# start mongo
/sbin/chkconfig mongod on
service mongod start
SCRIPT

$prepare_db = <<SCRIPT
# Configure and start PostgreSQL
adduser postgres
mkdir -p /data/pgsql
chown -R postgres /data/pgsql
sudo -u postgres /usr/pgsql-9.6/bin/initdb -D /data/pgsql
sed -i "s,PGDATA=.*$,PGDATA=/data/pgsql," /lib/systemd/system/postgresql-9.6.service
systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service

# create database and user "nerd"
/usr/pgsql-9.6/bin/createuser -U postgres nerd
/usr/pgsql-9.6/bin/createdb -U postgres --owner nerd nerd

# initialize database (create tables etc.)
/usr/pgsql-9.6/bin/psql -d nerd -U nerd -f /vagrant/create_db.sql
    
# Set up MongoDB (create indexes)
mongo nerd /vagrant/mongo_prepare_db.js

# Download GeoIP database
mkdir -p /data/geoip
wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz
gunzip /data/geoip/GeoLite2-City.mmdb.gz

# Add caida file
#cp /vagrant/caida-as2types.txt /data/caida-as2types.txt

# Warden_filer
wget -q https://homeproj.cesnet.cz/tar/warden/contrib_3.0-beta2.tar.bz2
tar -xf contrib_3.0-beta2.tar.bz2
cp -r contrib_3.0-beta2/warden_filer/ /data/
rm -rf contrib_3.0-beta2.tar.bz2 contrib_3.0-beta2

# Install local bind
yum install -y bind bind-utils

# configure asn.localhost. zone for ASN plugin
echo 'include "/etc/named/named.conf.local";' >> /etc/named.conf
echo 'zone "asn.localhost" {
   type master;
   file "/etc/named/zones/db.asn.localhost"; # zone file path
};' > /etc/named/named.conf.local
echo 'zone "asn.localhost" {
   type master;
   file "/etc/named/zones/db.asn.localhost"; # zone file path
};' > /etc/named/named.conf.local

mkdir -p /etc/named/zones
wget -q -O - 'http://archive.routeviews.org/dnszones/originas.bz2' |
    bunzip2 > /etc/named/zones/originas

echo '
$TTL    60480
@       IN      SOA     asn.localhost. asn.localhost. (
                              3         ; Serial
             60480     ; Refresh
              8640     ; Retry
            241920     ; Expire
             60480 )   ; Negative Cache TTL

@       IN      NS      asn.localhost.
@       IN      A       127.0.0.1

$INCLUDE /etc/named/zones/originas
' > /etc/named/zones/db.asn.localhost
systemctl start named.service

# local_bl plugin stores data into /data/local_bl:
mkdir -p /data/local_bl
chown -R vagrant:vagrant /data/local_bl
   
# Set up permissions of some directories
chown -R vagrant:vagrant ~vagrant/ /data/warden_filer
chown vagrant:vagrant /data
SCRIPT

$httpd_nerd_config = <<SCRIPT
echo '
# NERD (Flask app)

Define NERDBaseLoc /
Define NERDBaseDir /vagrant/NERDweb

# Set up WSGI script
WSGIDaemonProcess nerd_wsgi python-path=${NERDBaseDir}
WSGIScriptAlias ${NERDBaseLoc} ${NERDBaseDir}/wsgi.py
WSGIScriptAlias ${NERDBaseLoc}-debug ${NERDBaseDir}/wsgi-debug.py

<Location ${NERDBaseLoc}>
    WSGIProcessGroup nerd_wsgi
</Location>
<Location ${NERDBaseLoc}-debug>
    WSGIProcessGroup nerd_wsgi
</Location>

<Directory ${NERDBaseDir}>
    <Files wsgi.py>
        Require all granted
    </Files>
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
    AuthType basic
    AuthName "NERD web"
    AuthUserFile "/vagrant/NERD/etc/.htpasswd"
    Require valid-user
</Location>

# API handlers
<Location ${NERDBaseLoc}/api>
    # Pass Authorization header
    WSGIPassAuthorization On
    # Return JSON-formatted error message in case something goes wrong.
    ErrorDocument 500 "{\"err_n\": 500, \"error\": \"Internal Server Error\"}"
</Location>

<VirtualHost *:80>
</VirtualHost>
' > /etc/httpd/conf.d/nerd.conf
SCRIPT

$start = <<SCRIPT
echo '
from nerd_main import config
config.testing = True
' >> /vagrant/NERDweb/wsgi.py

iptables -I INPUT 1 -p TCP --dport 80 -j ACCEPT
setenforce 0
rm -f /usr/lib64/httpd/modules/mod_wsgi.so
ln -s /usr/lib64/python3.4/site-packages/mod_wsgi/server/mod_wsgi-py34.cpython-34m.so /usr/lib64/httpd/modules/mod_wsgi.so
systemctl enable httpd
systemctl start httpd

#cd /vagrant/NERDd
#python3 nerdd.py
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.network "forwarded_port", guest: 80, host: 2280
  config.vm.network "forwarded_port", guest: 5000, host: 5000
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  config.vm.provision :shell, inline: $dependencies
  config.vm.provision :shell, inline: $prepare_db
  config.vm.provision :shell, inline: $httpd_nerd_config
  config.vm.provision :shell, inline: $start
end
