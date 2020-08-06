#!/bin/sh
# Set up cron to periodically run several supporting scripts

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure cron ==============="

echob "** Copying cron config file **"

cp $BASEDIR/cron/nerd /etc/cron.d/nerd

# if Warden events are stored to local PSQL DB, enable DB cleaning script
if psql -U nerd -lqt | grep -qw nerd_warden
then
  echob "Found PSQL DB for Warden alerts, enabling cleanup script"
  sed -i '/nerd_clean_eventdb.sh/ s/^#//' /etc/cron.d/nerd
fi
