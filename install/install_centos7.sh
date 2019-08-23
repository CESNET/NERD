#!/bin/sh
# !! Run this script as root !!

# == Parameters ==

#install_nrpe=0   # client for external Nagios
install_munin=1   # server and client for locally running Munin

# == Common definitions ==

# disable "fastestmirror plugin, which in fact slows down yum"
alias yum="yum --disableplugin=fastestmirror"

# print notes (section header) in blue color
echob () {
  tput setaf 4 # light blue
  tput bold
  echo "$@"
  tput sgr0
}

# print important notes in yellow color
echoy () {
  tput setaf 3 # yellow
  tput bold
  echo "$@"
  tput sgr0
}

# ==========

echob "** Disabling SELinux **"
# TODO: learn how to properly configure everything with SELinux enabled
# Disable for now (until reboot)
setenforce 0
# Disable permanently
sed -i --follow-symlinks -e 's/^SELINUX=.*$/SELINUX=disabled/' /etc/sysconfig/selinux

echob "=============== Installing git (needed to clone repository) ==============="

yum install -y -q git

echob "=============== Cloning repository ==============="

if ! [ -d /tmp/nerd_install ]; then
  mkdir /tmp/nerd_install
  git clone https://github.com/CESNET/NERD.git /tmp/nerd_install
  cd /tmp/nerd_install
  git checkout master
else
  echoy "NOTICE: Using existing installation files in /tmp/nerd_install/"
  cd /tmp/nerd_install
fi
chmod +x /tmp/nerd_install/install/*.sh

# Prepare environment (create "nerd" user, create directories, etc.)
/tmp/nerd_install/install/prepare_environment.sh


# Copy files into final locations
sudo -u nerd mkdir -p /nerd/{common,NERDd,NERDweb,scripts}
sudo -u nerd cp -R /tmp/nerd_install/common/* /nerd/common
sudo -u nerd cp -R /tmp/nerd_install/NERDd/* /nerd/NERDd
sudo -u nerd cp -R /tmp/nerd_install/NERDweb/* /nerd/NERDweb
sudo -u nerd cp -R /tmp/nerd_install/scripts/* /nerd/scripts
sudo -u nerd cp -R /tmp/nerd_install/etc/* /etc/nerd
chmod -R g+w /nerd/
chmod -R g+w /etc/nerd/
chmod +x /nerd/scripts/*.sh


# Install and configure all dependencies
/tmp/nerd_install/install/install_basic_dependencies.sh

/tmp/nerd_install/install/configure_mongo.sh
/tmp/nerd_install/install/configure_postgres.sh --warden # create database for Warden events
/tmp/nerd_install/install/configure_rabbitmq.sh
/tmp/nerd_install/install/install_configure_bind.sh
/tmp/nerd_install/install/configure_apache.sh /nerd # install to /nerd
/tmp/nerd_install/install/install_warden_filer.sh
if [ "$install_munin" == "1" ]; then
  /tmp/nerd_install/install/install_configure_munin.sh
fi
/tmp/nerd_install/install/download_data_files.sh
/tmp/nerd_install/install/configure_cron.sh
/tmp/nerd_install/install/configure_supervisor.sh

# TODO only do this when some parameter is passed
# Backup newly created system-user accounts, so they don't disappear when users are synchronized, then, put them manually to /etc/*.template
cp /etc/passwd /etc/passwd-backup
cp /etc/shadow /etc/shadow-backup
cp /etc/group /etc/group-backup


echob "=============== Create testing user accounts ==============="
#sudo -u nerd psql nerd_users -c "INSERT INTO users (id,groups,name,email) VALUES ('devel:devel_admin','{\"admin\",\"registered\"}','Mr. Developer','test@example.org') ON CONFLICT DO NOTHING;"
sudo -u nerd psql nerd_users -c "INSERT INTO users (id,groups,name,email) VALUES ('local:test','{\"registered\"}','Mr. Test','test@example.org') ON CONFLICT DO NOTHING;"
# Set password for local test user
htpasswd -bc /etc/nerd/htpasswd test test
chown apache:nerd /etc/nerd/htpasswd
chmod 660 /etc/nerd/htpasswd

echoy
echoy "************************************************************"
echoy "A user account for testing is available:"
echoy ""
#echoy "* Administrator/developer - use 'Devel. autologin' option"
echoy "* Unprivileged local account - username/password: test/test"
echoy ""


# == Install and enable NRPE (for nagios) ==

# TODO



echoy "************************************************************"
echoy "Installation script completed."
echoy "What to do now:"
echoy " 1. See logs above for potential error messages."
# TODO download warden_apply.py to /data/warden_filer and prepare paths to cert in .cfg file to those where the cert will be generated
echoy " 2. Register Warden client, configure and run warden_filer (see above)."
echoy " 3. Create a user for web interface":
echoy "      psql -U nerd nerd_users"
echoy "        INSERT INTO users VALUES ('local:admin', '{\"registered\",\"trusted\",\"admin\"}','Mr. Admin','email@example.com','Test org');"
echoy "      htpasswd -c -B -C 12 /etc/nerd/htpasswd username"
echoy " 4. Run NERDd:"
echoy "      sudo systemctl start nerd-supervisor"
echoy " 5. Manage backend via supervisord interface (supervisorctl or https://localhost:9100/)"
echoy " 6. Check frontend at https://<this_server>/nerd/"
echoy ""
