#!/bin/sh

# Download MaxMind's GeoLite2 database to /data/geoip/GeoLite2-City.mmdb
#
# MaxMind no longer allows to download the data without registration.
# Therefore, this script must be called manually with licence key passed.
#
# Usage:
#   ./donwload_maxmind_geolite.sh LICENCE_KEY
#
#

KEY=$1
if [ -z "$KEY" ]; then
  echo "Licence key is needed (just register for free on maxmind.com)." >&2
  echo "Usage:" >&2
  echo "  ./download_maxmind_geolite.sh LICENCE_KEY" >&2
  echo "Run as user 'nerd' or root." >&2
  exit 1
fi

user=$(whoami)
if [ "$user" != "nerd" -a "$user" != "root" ]; then
  echo "Run as user 'nerd' or root." >&2
  exit 2
fi

# exit when any command fails
set -e

echo "Downloading MaxMind GeoLite2 database to /data/geoip/GeoLite2-City.mmdb"
mkdir -p /data/geoip
cd /data/geoip
# Download archive using the licence key
wget -q "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${KEY}&suffix=tar.gz" -O GeoLite2-City.tar.gz
# The archive contains a directory named by creation date, containing the DB
# and some txt file - extract just the DB file (*/GeoLite2-City.mmdb) to
# current dir
tar -xzf GeoLite2-City.tar.gz '*/GeoLite2-City.mmdb' --strip-components=1

if [ "$user" == "root" ]; then
  echo "Setting ownership to 'nerd' account"
  chown -R nerd:nerd /data/geoip
fi

echo "Done"
