# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure(2) do |config|
  config.vm.box = "centos/7"
  config.vm.network "forwarded_port", guest: 5000, host: 5000
  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end

  config.vm.provision "shell", inline: <<-SHELL
    echo '[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=0
enabled=1
' > /etc/yum.repos.d/mongodb-org-3.2.repo

    ln -s /vagrant sync

    # install dependencies
    yum install -y https://centos7.iuscommunity.org/ius-release.rpm
    yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-centos96-9.6-3.noarch.rpm
    yum -y install mongodb-org git wget python34 python34-devel httpd gcc postgresql96-server postgresql96-devel
    PATH=$PATH:/usr/pgsql-9.6/bin
    export PATH
    wget -q https://bootstrap.pypa.io/get-pip.py
    python3.4 get-pip.py
    rm get-pip.py
    pip3 install -r sync/NERDd/requirements.txt
    pip3 install -r sync/NERDweb/requirements.txt
    # start services
    #systemctl enable httpd
    systemctl enable mongod
    #service httpd start
    service mongod start
    
    # install some other useful tools
    yum -y install vim 
    
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
    /usr/pgsql-9.6/bin/psql -d nerd -U nerd -f sync/create_db.sql
    
    # Set up MongoDB (create indexes)
    mongo nerd sync/mongo_prepare_db.js

    # Download GeoIP database
    mkdir -p /data/geoip
    wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz
    gunzip /data/geoip/GeoLite2-City.mmdb.gz

    # Add caida file
    cp sync/caida-as2types.txt /data/caida-as2types.txt

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
    service named start

    # local_bl plugin stores data into /data/local_bl:
    mkdir -p /data/local_bl
    chown -R vagrant:vagrant /data/local_bl
    
    # Set up permissions of some directories
    chown -R vagrant:vagrant ~vagrant/ /data/warden_filer
    chown vagrant:vagrant /data

    echo "
------------------------------------------------------------
Installation finished.

Get into VM: vagrant ssh
Run NERDd: cd sync/NERDd; python3 nerdd.py
and NERDweb: cd sync/NERDweb: python3 nerd_main.py" >&2


  SHELL
end
