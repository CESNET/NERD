#!/bin/sh
# Install warden_filer into /data

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Install Warden filer ==============="

# Install latest packages from git repository, since the official packages are quite outdated

# echob "** Installing Warden client Python library **"
# if ! [ -f /usr/lib/python3*/site-packages/warden_client.py ] ; then
#   # Download and extract into Python2 site-packages
#   wget -q https://homeproj.cesnet.cz/tar/warden/warden_client_3.0-beta2.tar.bz2
#   tar -xjf warden_client_3.0-beta2.tar.bz2
#   cp warden_client_3.0-beta2/warden_client.py /usr/lib/python2*/site-packages/
#   rm -rf warden_client_3.0-beta2 warden_client_3.0-beta2.tar.bz2
# fi
# 
# echob "** Installing Warden filer **"
# if ! [ -d /opt/warden_filer ] ; then
#   # Download and extract to /opt
#   wget -q https://homeproj.cesnet.cz/tar/warden/contrib_3.0-beta2.tar.bz2
#   tar -xjf contrib_3.0-beta2.tar.bz2
#   cp -r contrib_3.0-beta2/warden_filer/ /opt/
#   rm -rf contrib_3.0-beta2.tar.bz2 contrib_3.0-beta2
# fi

echob "** Installing Warden client Python library and Warden filer **"
if ! [ -f /usr/lib/python3*/site-packages/warden_client.py -a -d /opt/warden_filer ] ; then
  git clone https://homeproj.cesnet.cz/git/warden.git
  cp warden/warden_client/warden_client.py /usr/lib/python3*/site-packages/
  cp warden/warden_client/warden_client.py /usr/lib/python2*/site-packages/
  cp -r warden/warden_filer/ /opt/
  rm -rf warden
fi

echob "** Preparing directory structure for Warden filer receiver **"
# directory for incoming IDEA files
mkdir -p /data/warden_filer/warden_receiver/{incoming,temp,errors}
chown -R nerd:nerd /data/warden_filer
chmod -R 775 /data/warden_filer


echoy "** Preparing template configuration file **"
install -o nerd -g nerd -m 664 $BASEDIR/warden_filer.cfg.template /etc/nerd/warden_filer.cfg.template
echoy
echoy "!!! WARDEN CLIENT MUST BE MANUALLY CONFIGURED !!!"
echoy "!! Before it can be run, do:"
echoy "!! - Register the client at a Warden server"
echoy "!! - Get client certificates (use warden_apply.sh available at Warden website)"
echoy "!! - Fill 'url', 'name' and path to certs in '/etc/nerd/warden_filer.cfg.template'."
echoy "!! - Rename 'warden_filer.cfg.template' to 'warden_filer.cfg'."
echoy
