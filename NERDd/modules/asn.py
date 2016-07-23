"""
NERD module getting ASN.

Requirements:
- "dnspython" package
- "BeautifulSoup4" package

Acknowledgment:
Code of the GetASN class was inspired by https://github.com/oneryalcin/pyip2asn
"""

from .base import NERDModule

import dns.resolver
import requests
from bs4 import BeautifulSoup
import pickle
import datetime
import logging

class GetASN:
    def __init__(self, cacheFile = "/tmp/nerd-asn-cache.json", maxValidity = 24 * 60 * 60):
        self.cacheFile = cacheFile
        self.maxValidity = maxValidity
        self.logger = logging.getLogger("ASNmodule")
        self.update_asn_dictionary()

    def update_asn_dictionary(self):
        ''' This module gets the latest AS Number to Desctiption from www.bgplookingglass.com'''

        try:
            with open(self.cacheFile, "rb") as f:
                cache = eval(pickle.load(f))
            f.close()
        except:
            cache = { '_create_date': 0 }

        curTime = int(datetime.datetime.now().strftime('%s'))
        if (curTime - cache['_create_date']) < self.maxValidity:
            # Get cached data
            self.logger.info("Using ASN list from cache.")
            self._asn_dct = cache['data']
            return

        asn_pages = [
            "http://www.bgplookingglass.com/list-of-autonomous-system-numbers",
            "http://www.bgplookingglass.com/list-of-autonomous-system-numbers-2",
            "http://www.bgplookingglass.com/4-byte-asn-names-list"
        ]

        self._asn_dct = {}
        for asn_page in asn_pages:
            r = requests.get(asn_page)
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("pre")
            lst = table.find_all(text=True)
            for asn in lst:
                if asn[9:13] == "    ":
                    marker = 13
                else:
                    marker = 8
                try:
                    as_number = int(asn[2:marker].strip())
                    as_desc = asn[marker:].strip()
                    self._asn_dct[as_number] = as_desc
                except:
                    continue
        with open(self.cacheFile, "wb") as f:
            data = str({'_create_date': curTime, 'data': self._asn_dct})
            pickle.dump(data, f)
        f.close()


    def asnLookup(self, ip_address):
        # Check if ASN description dictionary is provided, if not populate it
        octs = ip_address.split(".")
        query =  "%s.%s.%s.origin.asn.cymru.com" % (octs[2], octs[1], octs[0])
        answers = dns.resolver.query(query, 'TXT')
        record = str(answers[0]).split("|")
        asn = int(record[0][1:].strip())
        subnet = record[1].strip()
        result = {
            "asn_num": asn,
            "asn_desc": self._asn_dct[asn],
            "asn_subnet": subnet
        }
        return result

class ASN(NERDModule):
    """
    Geolocation module.

    Queries newly added IP addresses in MaxMind's GeoLite legacy database to get its
    autonomous system information.
    Stores the following attributes:
      asn.id  # ASN
      asn.description # name of ASN
      asn.subnet # subnet of ASN

    Event flow specification:
      !NEW -> geoloc -> asn.{id,description,subnet}
    """

    def __init__(self, config, update_manager):
        # Instantiate DB reader (i.e. open GeoLite database), raises IOError on error
        cacheFile = config.get("asn.cache_file", "/tmp/nerd-asn-cache.json")
        maxValidity = config.get("asn.cache_max_valitidy", 86400)
        self.reader = GetASN(cacheFile, maxValidity)

        update_manager.register_handler(
            self.handleRecord,
            ('!NEW',),
            ('asn.id', 'asn.description', 'asn.subnet')
        )

    def handleRecord(self, ekey, rec, updates):
        """
        Query GeoLite2 DB to get country, city and timezone of the IP address.
        If address isn't found, don't set anything.

        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and
          their new values (or events and their parameters) as a list of
          2-tuples: [(attr, val), (!event, param), ...]


        Returns:
        List of update requests.
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        result = self.reader.asnLookup(key)

        return [
            ('set', 'asn.id', result["asn_num"]),
            ('set', 'asn.decription', result["asn_desc"]),
            ('set', 'asn.subnet', result["asn_subnet"]),
        ]

