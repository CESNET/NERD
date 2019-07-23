#!/bin/sh
# Install all packages needed to run NERD and run all the services

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Install basic dependencies ==============="

echob "** Installing basic RPM packages **"
yum install -y -q epel-release
yum install -y -q git wget gcc vim python36 python36-devel python36-setuptools python-setuptools

echob "** Installing pip and Python packages **"
easy_install-2.7 --prefix /usr pip # Py2 is needed for Supervisor (until stable Supervisor 4 is out, which should work under Py3)
easy_install-3.6 --prefix /usr pip
# for some reason, this creates file /usr/bin/pip3.7 instead of pip3.6 (but everything works OK)

# Allow to run python3.6 as python3 (not needed, is created automatically)
# ln -s /usr/bin/python3.6 /usr/bin/python3

pip3 install -r $BASEDIR/pip_requirements_nerdd.txt
pip3 install -r $BASEDIR/pip_requirements_nerdweb.txt

echob "** Installing pybgpranking from git repo **"
# install CIRCL BGP ranking python library (pybgpranking)
pushd /tmp
git clone https://github.com/D4-project/BGP-Ranking.git
cd BGP-Ranking/client/
python3 setup.py install
popd
rm -rf /tmp/BGP-Ranking/

echob "** Installing MongoDB **"

# Add repository
echo '[mongodb-org-4.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/4.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc
' > /etc/yum.repos.d/mongodb-org-4.0.repo

yum install -y -q mongodb-org

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

echob "** Starting MongoDB **"
# /sbin/chkconfig mongod on
systemctl enable mongod.service
systemctl start mongod.service



echob "** Installing Redis **"
yum install -y -q redis

echob "** Starting Redis **"
systemctl enable redis.service
systemctl start redis.service



echob "** Installing RabbitMQ **"
# We need more recent version than in CentOS7 (>=3.7.0), so install from developer sites

# Install Erlang (dependency)
echo '[rabbitmq_erlang]
name=rabbitmq_erlang
baseurl=https://packagecloud.io/rabbitmq/erlang/el/6/$basearch
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packagecloud.io/rabbitmq/erlang/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300

[rabbitmq_erlang-source]
name=rabbitmq_erlang-source
baseurl=https://packagecloud.io/rabbitmq/erlang/el/6/SRPMS
repo_gpgcheck=1
gpgcheck=0
enabled=1
gpgkey=https://packagecloud.io/rabbitmq/erlang/gpgkey
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
metadata_expire=300
' > /etc/yum.repos.d/rabbitmq_erlang.repo

yum install -y -q erlang

# Install RabbitMQ
if ! yum list installed rabbitmq-server >/dev/null 2>&1 ; then
  yum install -y -q https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.7.15/rabbitmq-server-3.7.15-1.el7.noarch.rpm
fi

# For some reason, hostname in Vagrant is often not set to anything meaningful,
# but erlang needs to know it - this helps. 
# Reference: https://stackoverflow.com/questions/45425286/rabbitmq-server-dont-start-unable-to-connect-to-epmd-ubuntu-16-04 
# echo "HOSTNAME=localhost" >/etc/rabbitmq/rabbitmq-env.conf

# Allow guest user to login remotely (allowed only from localhost by default)
# This is necessary for Vagrant, but DON'T DO THIS IN PRODUCTION!
# (rabbitmq.conf is not present after installation, so we just create it)
if [ -d /vagrant/NERDd ] ; then
  echor "It seems we run in Vagrant, allowing RabbitMQ guest user to login remotely."
  echo "loopback_users = none" > /etc/rabbitmq/rabbitmq.conf
fi

# Enable necessary plugins
rabbitmq-plugins enable rabbitmq_management
# rabbitmq-plugins enable rabbitmq_consistent_hash_exchange

echob "** Starting RabbitMQ **"
systemctl enable rabbitmq-server
systemctl start rabbitmq-server

# Get rabbitmqadmin tool (provided via local API by the management plugin)
if ! [ -f /usr/bin/rabbitmqadmin ] ; then
  wget -q http://localhost:15672/cli/rabbitmqadmin -O /usr/bin/rabbitmqadmin
  chmod +x /usr/bin/rabbitmqadmin
fi



echob "** Installing Supervisor **"
pip2 install supervisor



echob "** Installing PostgreSQL **"
if ! yum list installed postgresql11-server >/dev/null 2>&1 ; then
  yum install -y -q https://download.postgresql.org/pub/repos/yum/11/redhat/rhel-7-x86_64/pgdg-centos11-11-2.noarch.rpm
  yum install -y -q postgresql11-server postgresql11-devel
fi

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


echob "** All main dependencies installed **"
