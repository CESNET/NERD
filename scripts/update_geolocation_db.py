# this script needs to be run with root priviledges

import requests
import sys
import gzip
import shutil
import os

sys.path.append("../")
from common.notifier import Notifier

file_zip_name = '/data/geoip/GeoLite2-City.mmdb.gz'
file_name = '/data/geoip/GeoLite2-City.mmdb'
url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz'


def notify_nerd():
    notif = Notifier()
    notif.publish("new_geolocation_db")


def download_db():
    response = requests.get(url)
    open(file_zip_name, 'wb').write(response.content)


def unzip_file():
    with gzip.open(file_zip_name, 'rb') as f_in:
        with open(file_name, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(file_zip_name)


if __name__ == "__main__":
    download_db()
    unzip_file()
    notify_nerd()
    print("Database successfully updated.")




