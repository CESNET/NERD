#!/bin/sh

echo "=============== Download data files ==============="

# Perform everything as "nerd" user instead of root
cd /
sudo -u nerd sh <<EOF
umask 0002

echo "** Downloading GeoIP database **"
if ! [ -f /data/geoip/GeoLite2-City.mmdb ]; then
  mkdir -p /data/geoip
  wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz
  gunzip -f /data/geoip/GeoLite2-City.mmdb.gz
fi

echo "** Copying CAIDA AS-type mapping file **"
# Copy caida file (if present)
if ! [ -f /data/caida-as2types.txt ]; then
  # TODO: the data seem to be updated every month, download the latest one automatically (and write an update script)
  wget -q http://data.caida.org/datasets/as-classification/20190301.as2types.txt.gz -O /data/caida-as2types.txt.gz
  gunzip -f /data/caida-as2types.txt.gz
fi

echo "** Copying/downloading whois data **" 

if ! [ -f /data/nerd-whois-asn.csv -a -f /data/nerd-whois-ipv4.csv ]; then
    echo "Downloading and processing whois data from RIRs"
    cd /data/
    python3 /nerd/scripts/get_iana_assignment_files.py
    cd -
fi

EOF
