echo "** Installing basic RPM packages **"
yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum install -y git wget gcc vim python34 python34-devel
# TODO install Python3.6 or 3.7 from sources (3.4 won't be supported soon)

echo "** Installing pip and Python packages **"
wget -q https://bootstrap.pypa.io/get-pip.py
python3.4 get-pip.py
python2.7 get-pip.py
rm -f get-pip.py
# TODO FIXME this is specific to vagrant
pip3 install -r /vagrant/NERDd/requirements.txt
pip3 install -r /vagrant/NERDweb/requirements.txt

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

# TODO, put there installation (and basic configuration which is needed in every NERD deployment):
# (keep starting up and configuration of deployment-specific parameters for later)
# - Mongo
# - Redis
# - Rabbit



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
sed -i '/logAppend: true/a \ \ logRotate: reopen' /etc/mongod.conf
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
echo "loopback_users = none" > /etc/rabbitmq/rabbitmq.conf

echo "** Starting RabbitMQ **"
systemctl enable rabbitmq-server
systemctl start rabbitmq-server

# Enable necessary plugins
rabbitmq-plugins enable rabbitmq_management
rabbitmq-plugins enable rabbitmq_consistent_hash_exchange

# Get rabbitmqadmin tool (provided via local API by the management plugin)
wget http://localhost:15672/cli/rabbitmqadmin -O /usr/bin/rabbitmqadmin
chmod +x /usr/bin/rabbitmqadmin



echo "** Installing Supervisor **"
pip2 install supervisor



# TODO: move to another file (only needed for web or if local EventDB is enabled)
echo "** Installing PostgreSQL **"
yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-centos96-9.6-3.noarch.rpm
yum install -y postgresql96-server postgresql96-devel

# Initialize database (creates DB files in /var/lib/pgsql/9.6/data/)
sudo -u postgres /usr/pgsql-9.6/bin/postgresql96-setup initdb

# Non.default DB path:
# mkdir -p /data/pgsql
# chown -R postgres /data/pgsql
# sudo -u postgres /usr/pgsql-9.6/bin/initdb -D /data/pgsql
# sed -i "s,PGDATA=.*$,PGDATA=/data/pgsql," /lib/systemd/system/postgresql-9.6.service

# TODO edit /db/pgsql/pg_hba.conf to trust all local connections? It would allow to use "psql -U user" instead of "sudo -u USER psql"

# Start PostgreSQL
systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service


echo "** All main dependencies installed **"
