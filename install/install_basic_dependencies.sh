#!/bin/sh
# Install all packages needed to run NERD and run all the services

echo "=============== Install basic dependencies ==============="

echo "** Installing basic RPM packages **"
#yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum install -y epel-release
yum install -y git wget gcc vim python36 python36-devel python36-setuptools python-setuptools

echo "** Installing pip and Python packages **"
easy_install-2.7 --prefix /usr pip # Py2 is needed for Supervisor (until stable Supervisor 4 is out, which should work under Py3)
easy_install-3.6 --prefix /usr pip
# for some reason, this creates file /usr/bin/pip3.7 instead of pip3.6 (but everything works OK)

# Allow to run python3.6 as python3
ln -s /usr/bin/python3.6 /usr/bin/python3

pip3 install -r /tmp/nerd_install/pip_requirements_nerdd.txt
pip3 install -r /tmp/nerd_install/pip_requirements_nerdweb.txt

# Patch bgpranking_web to work in Python 3
echo "Patching bgpranking_web package to work in Python 3"
# get package path
path="$(pip3 show bgpranking_web 2>/dev/null | sed -n '/Location: / s/Location: //p')"
# check path and overwrite package's __init__.py
if [ -z "$path" ]
then
  echo "ERROR: Can't find the path to bgpranking_web python package, it won't be patched" >&2
else
  echo 'import sys
if sys.version_info[0] == 2:
    from api import *
else:
    from .api import *
' > "$path/bgpranking_web/__init__.py"
fi


echo "** Installing MongoDB **"

# Add repository
echo '[mongodb-org-3.6]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.6/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-3.6.asc
' > /etc/yum.repos.d/mongodb-org-3.6.repo

yum install -y mongodb-org

# ** Set up logrotate **
# Configure Mongod to only reopen file after receiving SIGUSR1
if ! grep '^\s*logRotate: reopen' /etc/mongod.conf ; then
  sed -i '/logAppend: true/a \ \ logRotate: reopen' /etc/mongod.conf
fi
# Configure logrotate
echo '/var/log/mongodb/mongod.log {
    weekly
    missingok
    rotate 8
    compress
    delaycompress
    notifempty
    postrotate
        /usr/bin/pkill -USR1 mongod
    endscript
}
' > /etc/logrotate.d/mongodb

echo "** Starting MongoDB **"
# /sbin/chkconfig mongod on
systemctl enable mongod.service
systemctl start mongod.service



echo "** Installing Redis **"
yum install -y redis

echo "** Starting Redis **"
systemctl enable redis.service
systemctl start redis.service



echo "** Installing RabbitMQ **"
# We need more recent version than in CentOS7 (>=3.7.0), so install from developer sites

# Install Erlang (dependency)
echo '[rabbitmq-erlang]
name=rabbitmq-erlang
baseurl=https://dl.bintray.com/rabbitmq/rpm/erlang/20/el/7
gpgcheck=1
gpgkey=https://dl.bintray.com/rabbitmq/Keys/rabbitmq-release-signing-key.asc
repo_gpgcheck=0
enabled=1
' > /etc/yum.repos.d/rabbitmq-erlang.repo

yum install -y erlang

# Install RabbitMQ
yum install -y https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.7.6/rabbitmq-server-3.7.6-1.el7.noarch.rpm

# Allow guest user to login remotely (allowed only from localhost by default)
# This is necessary for Vagrant, but DON'T DO THIS IN PRODUCTION!
# (rabbitmq.conf is not present after installation, so we just create it)
if [ -d /vagrant ] ; then
  echo "It seems we run in Vagrant, allowing RabbitMQ guest user to login remotely."
  echo "loopback_users = none" > /etc/rabbitmq/rabbitmq.conf
fi

echo "** Starting RabbitMQ **"
systemctl enable rabbitmq-server
systemctl start rabbitmq-server

# Enable necessary plugins
rabbitmq-plugins enable rabbitmq_management
rabbitmq-plugins enable rabbitmq_consistent_hash_exchange

# Get rabbitmqadmin tool (provided via local API by the management plugin)
wget -q http://localhost:15672/cli/rabbitmqadmin -O /usr/bin/rabbitmqadmin
chmod +x /usr/bin/rabbitmqadmin



echo "** Installing Supervisor **"
pip2 install supervisor



echo "** Installing PostgreSQL **"
yum install -y https://download.postgresql.org/pub/repos/yum/11/redhat/rhel-7-x86_64/pgdg-centos11-11-2.noarch.rpm
yum install -y postgresql11-server postgresql11-devel

# Initialize database (creates DB files in /var/lib/pgsql/11/data/)
if ! [ -e /var/lib/pgsql/11/data/PG_VERSION ] ; then
  /usr/pgsql-11/bin/postgresql-11-setup initdb
fi

# Non.default DB path:
# mkdir -p /data/pgsql
# chown -R postgres /data/pgsql
# sudo -u postgres /usr/pgsql-11/bin/initdb -D /data/pgsql
# sed -i "s,PGDATA=.*$,PGDATA=/data/pgsql," /lib/systemd/system/postgresql-11.service

# Edit /db/pgsql/pg_hba.conf to trust all local connections
# It allows to use "psql -U user" instead of "sudo -u USER psql"
# and it allows easier connection from web server
sed -i -E '/^local|127\.0\.0\.1\/32|::1\/128/ s/[^ ]+$/trust/' /var/lib/pgsql/11/data/pg_hba.conf

# Start PostgreSQL
systemctl enable postgresql-11.service
systemctl restart postgresql-11.service


echo "** All main dependencies installed **"
