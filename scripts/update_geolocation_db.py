# this script needs to be run with root priviledges

# wget -q http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz -O /data/geoip/GeoLite2-City.mmdb.gz && gunzip -f /data/geoip/GeoLite2-City.mmdb.gz

import requests
import logging
import os
import sys
sys.path.append("../")
from common.notifier import Notifier
fname = '/data/geoip/GeoLite2-City.mmdb.gz'
url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz'

logger = logging.getLogger("GeolocationDbUpdater")


def notify_nerd():
    notif = Notifier()
    notif.publish("new_geolocation_db")


def download_db():
    try:
        # download db
        response = requests.get(url)
        open(fname, 'wb').write(response.content)
    except Exception as e:
        logger.exception(str(e))
        exit(1)

    os.system("gunzip -f {}".format(fname))


if __name__ == "__main__":
    download_db()
    notify_nerd()




