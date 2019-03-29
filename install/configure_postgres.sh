#!/bin/sh
# Configure PSQL databases
# There are two databases by default:
# 1) user database for web (mandatory)
# 2) database of Warden events (optional, disabled by default)
# The second one can be enabled by passing "--warden" as argument

echo "=============== Configure PostgreSQL ==============="

echo "** Configuring PostgreSQL database **"

cd / # to avoid "could not change directory to /home/vagrant" error in Vagrant

sudo -u postgres /usr/pgsql-11/bin/createuser nerd

# Create a user database for NERDweb in PostgreSQL
sudo -u postgres /usr/pgsql-11/bin/createdb --owner nerd nerd_users
sudo -u nerd /usr/pgsql-11/bin/psql -d nerd_users -f /tmp/nerd_install/create_user_db.sql

# (Optional) Create a database for Warden events
if [ "$1" == "--warden" ] ; then
  sudo -u postgres /usr/pgsql-11/bin/createdb --owner nerd nerd_warden
  sudo -u nerd /usr/pgsql-11/bin/psql -d nerd_warden -f /tmp/nerd_install/create_warden_db.sql
fi

# TODO install pgadmin4
# Install pgAdmin4 and set it up to run via WSGI under Apache
# yum install -y pgadmin4
# Run initial setup to set the admin user account
# see https://computingforgeeks.com/how-to-install-pgadmin-4-on-centos-7-fedora-29-fedora-28/
# python /usr/lib/python2.7/site-packages/pgadmin4-web/setup.py
