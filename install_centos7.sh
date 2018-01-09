#!/bin/sh
# ** Run this script as root! **

# Parameters:

install_nrpe=0   # client for external Nagios
install_munin=1   # server and client for locally running Nagios

# == Initialization and cloning of NERD repository ==

# Create user "nerd"
useradd nerd

# Clone NERD repository into /home/nerd/NERD
cd /home/nerd
sudo -u nerd git clone https://github.com/CESNET/NERD.git NERD

# Allow access to /home/nerd (needed for Apache to access /home/nerd/NERD/NERDweb/wsgi.py)
chmod a+x /home/nerd


# == Create needed directories ==

mkdir -p /data
chmod 777 /data

mkdir /data/blacklists
chown -R nerd:nerd /data/blacklists

# local_bl plugin stores data into /data/local_bl:
mkdir -p /data/local_bl
chown -R nerd:nerd /data/local_bl


# == Install dependencies ==

# MongoDB 3.2 repo
echo '[mongodb-org-3.2]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/3.2/x86_64/
gpgcheck=0
enabled=1
' > /etc/yum.repos.d/mongodb-org-3.2.repo

yum install -y https://centos7.iuscommunity.org/ius-release.rpm
yum install -y https://download.postgresql.org/pub/repos/yum/9.6/redhat/rhel-7-x86_64/pgdg-centos96-9.6-3.noarch.rpm

yum install -y mongodb-org git wget python34 python34-devel httpd gcc postgresql96-server postgresql96-devel mod_ssl mod_wsgi httpd-devel vim screen

wget -q https://bootstrap.pypa.io/get-pip.py
python3.4 get-pip.py
rm get-pip.py

pip3 install -r /home/nerd/NERD/NERDd/requirements.txt
pip3 install -r /home/nerd/NERD/NERDweb/requirements.txt
pip3 install mod_wsgi



# == Configure and start MongoDB ==

systemctl enable mongod
systemctl start mongod

# Set up database (create indexes)
mongo nerd /vagrant/mongo_prepare_db.js


# == Configure and start PostgreSQL ==

# Configure database path to /data/pgsql
mkdir -p /data/pgsql
chown -R postgres /data/pgsql
sudo -u postgres /usr/pgsql-9.6/bin/initdb -D /data/pgsql
sed -i "s,PGDATA=.*$,PGDATA=/data/pgsql," /lib/systemd/system/postgresql-9.6.service

# Enable and run
systemctl enable postgresql-9.6.service
systemctl start postgresql-9.6.service

# Create user and database "nerd"
/usr/pgsql-9.6/bin/createuser -U postgres nerd
/usr/pgsql-9.6/bin/createdb -U postgres --owner nerd nerd

# Initialize the database (create tables etc.)
/usr/pgsql-9.6/bin/psql -d nerd -U nerd -f /home/nerd/NERD/create_db.sql
# Change API key for the testing API user to something random
sh /home/nerd/NERD/scripts/set_api_token.sh api_user

# == Install and configure BIND ==

yum install -y bind bind-utils bzip2

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

# Increase start timeout in systemd, because of the need to check and load large zone file(s)
sed -i -e '/^ExecStop/ a TimeoutStartSec=180' /usr/lib/systemd/system/named.service
systemctl daemon-reload

# Start BIND
systemctl enable named.service
systemctl start named.service


# == Install and configure Postfix ==

systemctl enable postfix
systemctl start postfix


# == Configure Apache ==

# Create configuration file
echo '# NERD (Flask app)

# Paths (no trailing slash)
Define NERDBaseLoc /nerd
Define NERDBaseDir /home/nerd/NERD/NERDweb

# Set up WSGI script
WSGIDaemonProcess nerd_wsgi python-path=${NERDBaseDir}
WSGIScriptAlias ${NERDBaseLoc}/ ${NERDBaseDir}/wsgi.py

<Location ${NERDBaseLoc}/>
    WSGIProcessGroup nerd_wsgi
</Location>

<Directory ${NERDBaseDir}>
    <Files wsgi.py>
        Require all granted
    </Files>
</Directory>

# Static files must be served direcly by Apache, not by Flask
Alias ${NERDBaseLoc}/static/ ${NERDBaseDir}/static/
<Directory ${NERDBaseDir}/static>
    Require all granted
</Directory>

# Authentication using local accounts
<Location ${NERDBaseLoc}/login/basic>
    AuthType basic
    AuthName "NERD web"
    AuthUserFile "/home/nerd/NERD/etc/.htpasswd"
    Require valid-user
</Location>

# API handlers
<Location ${NERDBaseLoc}/api>
    # Pass Authorization header
    WSGIPassAuthorization On
    # Return JSON-formatted error message in case something goes wrong.
    ErrorDocument 500 "{\"err_n\": 500, \"error\": \"Internal Server Error\"}"
</Location>

# Force HTTPS (for NERD location)
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^${NERDBaseLoc}/?(.*) https://%{SERVER_NAME}/${NERDBaseLoc}/$1 [R=301,L]
' > /etc/httpd/conf.d/nerd.conf

# TODO Edit config of mod_ssl to allow only modern/secure protocols and ciphers

# Create a file for passwords of local accounts
touch /home/nerd/NERD/etc/.htpasswd
chown nerd:apache /home/nerd/NERD/etc/.htpasswd
chmod 660 /home/nerd/NERD/etc/.htpasswd

# Edit the NERDweb config:
# Set Flask's secret_key to random 16 alnum chars
sed -ie 's|^"secret_key": "!!! CHANGE THIS !!!",$|"secret_key": "'$(tr -cd [:alnum:] < /dev/urandom | head -c 16)'",|' /home/nerd/NERD/etc/nerdweb.cfg

# Replace system's default mod_wsgi by one complied against Python3.4
mv /usr/lib64/httpd/modules/mod_wsgi.so{,_backup}
ln -s /usr/lib64/python3.4/site-packages/mod_wsgi/server/mod_wsgi-py34.cpython-34m.so /usr/lib64/httpd/modules/mod_wsgi.so

# Allow HTTP and HTTPS in firewall
iptables -I INPUT 1 -p TCP --dport 80 -j ACCEPT
iptables -I INPUT 1 -p TCP --dport 443 -j ACCEPT

# Set SELinux to permissive mode (TODO: we should rather configure SELinux rules correctly)
setenforce 0

# Run Apache
systemctl enable httpd
systemctl start httpd


# == Download GeoIP database ==

mkdir -p /data/geoip
chown nerd:nerd /data/geoip
sudo -u nerd wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz
sudo -u nerd gunzip /data/geoip/GeoLite2-City.mmdb.gz


# == Configure cron ==

# Copy scripts to /data/NERD_scripts
mkdir -p /data/NERD_scripts
cp /home/nerd/NERD/scripts/nerd_db_remove_old_records.sh /data/NERD_scripts/
cp /home/nerd/NERD/scripts/nerd_clean_eventdb.sh /data/NERD_scripts/
cp /home/nerd/NERD/scripts/update_db_meta_info.js /data/NERD_scripts/
chmod +x /home/nerd/NERD/scripts/nerd_db_remove_old_records.sh
chmod +x /home/nerd/NERD/scripts/nerd_clean_eventdb.sh

# Set up cron rules
crontab -u nerd /home/nerd/NERD/scripts/crontab



# == Install and enable munin and munin-node ==

# Web authentication is NOT set up by this

if [ $install_munin == 1 ]; then
  yum -y install munin munin-node

  # Configure munin-node - allow connections from localhost only
  sed -i -e 's/^host \*$/# host \*/' -e 's/^# host 127.0.0.1/host 127.0.0.1/' /etc/munin/munin-node.conf

  # Install and enable NERD plugins
  cp /home/nerd/NERD/scripts/munin/* /usr/share/munin/plugins/
  chmod +x /usr/share/munin/plugins/nerd_*
  ln -s /usr/share/munin/plugins/nerd_* /etc/munin/plugins/

  # Run munin-node
  systemctl enable munin-node
  systemctl start munin-node
fi


# == Install and enable NRPE (for nagios) ==

# TODO


# == Install and configure Warden client ==

# Install warden client (as Python2.7 package)
wget https://homeproj.cesnet.cz/tar/warden/warden_client_3.0-beta2.tar.bz2
tar -xjf warden_client_3.0-beta2.tar.bz2
cp warden_client_3.0-beta2/warden_client.py /usr/lib/python2.7/site-packages/
rm -f warden_client_3.0-beta2.tar.bz2
rm -rf warden_client_3.0-beta2

# Install warden_filer (into /opt/warden_filer)
wget https://homeproj.cesnet.cz/tar/warden/contrib_3.0-beta2.tar.bz2
tar -xjf contrib_3.0-beta2.tar.bz2
cp -R contrib_3.0-beta2/warden_filer /opt/
chmod +x /opt/warden_filer/warden_filer.py

# Set up warden_filer
mkdir -p /data/warden_filer/warden_receiver/incoming
mkdir -p /data/warden_filer/log
chown -R nerd:nerd /data/warden_filer

echo '{
    "warden": {
        "url": "https://EDIT_THIS.example.com/warden3",
        "certfile": "/data/warden_filer/cert.pem",
        "keyfile": "/data/warden_filer/key.pem",
        "cafile": "/etc/pki/tls/certs/ca-bundle.crt",
        "timeout": 10,
        "errlog": {"level": "debug"},
        "filelog": {"file": "/data/warden_filer/log/warden_filer.log", "level": "warning"},
        "idstore": "/data/warden_filer/warden_filer.id",
        "name": "EDIT-THIS"
    },
    "receiver": {
        // Maildir like directory, whose "incoming" will serve as target for events
        "dir": "/data/warden_filer/warden_receiver",
        "work_dir": "/data/warden_filer/",
        "poll_time": 5,
        // max number of files in incoming dir (approx)
        "file_limit": 10000,
        // seconds to wait if max number of files exceeded
        "limit_wait_time": 10
    }
}' > /data/warden_filer/nerd_warden_filer.cfg

# Download warden_apply.sh
wget https://homeproj.cesnet.cz/tar/warden/warden_apply.sh -O /data/warden_filer/warden_apply.sh
chown nerd:nerd /data/warden_filer/warden_apply.sh
chmod +x /data/warden_filer/warden_apply.sh



echo "************************************************************"
echo "**********    Warden filer needs configuration    **********"
echo ""
echo "1. Ask Warden admins for registration of reveiving client"
echo "2. Generate certificates:"
echo "     /data/warden_filer/warden_apply.sh CLIENT_NAME PASSWORD"
echo "3. Edit url and name in /data/warden_filer/nerd_warden_filer.cfg"
echo "4. Run (e.g. inside 'screen -S warden'):"
echo "     /opt/warden_filer/warden_filer.py -c /data/warden_filer/nerd_warden_filer.cfg receiver"
echo ""
echo "************************************************************"
echo ""



echo "************************************************************"
echo "Installation script completed."
echo "What to do now:"
echo " 1. See logs above for potential error messages."
# TODO download warden_apply.py to /data/warden_filer and prepare paths to cert in .cfg file to those where the cert will be generated
echo " 2. Register Warden client, configure and run warden_filer (see above)."
echo " 3. Create a user for web interface":
echo "      psql -U nerd"
echo "        INSERT INTO users VALUES ('local:username', '{"registered","admin"}','Name Surname','email@example.com','Organization',NULL);"
echo "      htpasswd -c -B -C 12 /home/nerd/NERD/etc/.htpasswd username
echo " 4. Run NERDd:"
echo "      screen -S nerdd"
echo "      cd NERD/NERDd/"
echo "      python3 nerdd.py"
echo " 5. Go to https://<this_server>/nerd/ and check if everything works."
echo ""