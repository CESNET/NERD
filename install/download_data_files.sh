#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Download data files ==============="

# Perform everything as "nerd" user instead of root
cd /
sudo -u nerd sh <<EOF
. $BASEDIR/common.sh
umask 0002

# CAIDA AS type data are currently not available (see https://www.caida.org/catalog/datasets/as-classification/ for more info)
#echob "** Copying CAIDA AS-type mapping file **"
## Copy caida file (if present)
#if ! [ -f /data/caida-as2types.txt ]; then
#  # TODO: the data seem to be updated every month, download the latest one automatically (and write an update script)
#  wget -q http://data.caida.org/datasets/as-classification/20200701.as2types.txt.gz -O /data/caida-as2types.txt.gz
#  gunzip -f /data/caida-as2types.txt.gz
#fi

echob "** Copying/downloading whois data **"

if ! [ -f /data/nerd-whois-asn.csv -a -f /data/nerd-whois-ipv4.csv ]; then
    echo "Downloading and processing whois data from RIRs"
    cd /data/
    python3 /nerd/scripts/get_iana_assignment_files.py
    cd -
fi

EOF
