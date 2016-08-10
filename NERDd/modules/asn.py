"""
NERD module getting ASN.

Requirements:
- "BeautifulSoup4" package
- "pygeoip" package

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
import pygeoip
import gzip
import os

class GetASN:
    def __init__(self, geoipasnFile, cacheFile, maxValidity):
        self.cacheFile = cacheFile
        self.geoipasnFile = geoipasnFile
        self.maxValidity = maxValidity
        self.log = logging.getLogger("ASNmodule")
        self.update_asn_dictionary()

        # Create DNS resolver that uses localhost
        self.dnsresolver = dns.resolver.Resolver()
        self.dnsresolver.nameservers = ['127.0.0.1']

    def update_asn_dictionary(self):
        '''Update MaxMind database and list of ASN names.'''

        try:
            with open(self.cacheFile, "rb") as f:
                cache = eval(pickle.load(f))
            f.close()
        except:
            cache = { '_create_date': 0 }

        curTime = int(datetime.datetime.now().timestamp())
        if (curTime - cache['_create_date']) < self.maxValidity:
            # Get cached data
            self.log.info("Using ASN list from cache.")
            self._asn_dct = cache['data']
            self._pygeoip = pygeoip.GeoIP(self.geoipasnFile)
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

        try:
            ctime =  os.stat(self.geoipasnFile).st_ctime
        except:
            ctime = 0
        if curTime -  ctime >= self.maxValidity:
            # Download latest MaxMind DB
            r = requests.get("http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz")
            # decompress it
            rt = r.content
            decompressed_data = gzip.decompress(rt)
            # and save result for future
            with open(self.geoipasnFile, "wb") as f:
                f.write(decompressed_data)
            f.close()
            del(decompressed_data)
            del(rt)
        
        self._pygeoip = pygeoip.GeoIP(self.geoipasnFile)

        with open(self.cacheFile, "wb") as f:
            data = str({'_create_date': curTime, 'data': self._asn_dct})
            pickle.dump(data, f)
        f.close()


    def geoipLookup(self, ip_address):
        # Check if ASN description dictionary is provided, if not populate it
        ret = {}
        res = self._pygeoip.asn_by_addr(ip_address)
        if res:
            self.log.debug("Looked up " + ip_address + " in GeoIP: " + res)
            
            asn = res.split(maxsplit=1)
            ret["as_maxmind.num"] = int(asn[0][2:])
            ret["as_maxmind.desc"] = asn[1] if len(asn) >= 2 else ""
            return ret
        else:
            self.log.info("ASN for " + ip_address + " not found in GeoIP")
            return None

    def routeviewsLookup(self, ip_address):
        ret = {}
        octs = ip_address.split(".")
        query =  "{0}.{1}.{2}.{3}.asn.localhost.".format(octs[3], octs[2], octs[1], octs[0])
        try:
            answers = self.dnsresolver.query(query, 'TXT')
            record = str(answers[0]).replace('"', '').split()
            asnum = int(record[0])
            ret["as_rw.num"] = asnum
            ret["as_rw.desc"] = self._asn_dct[asnum]
            self.log.debug("Looked up " + ip_address + " using routeviews: " + ip_address + ": {0} {1} ({2}/{3})".format(ret["as_rw.num"],
                    ret["as_rw.desc"], record[1], record[2]))
        except:
            self.log.info("ASN for " + ip_address + " not found in routeviews data")
        return ret

    def asnLookup(self, ip_address):
        ret1 = self.geoipLookup(ip_address)
        ret2 = self.routeviewsLookup(ip_address)

        results = {}
        if ret1:
            if "as_maxmind.num" in ret1:
                results['as_maxmind.num'] = ret1["as_maxmind.num"]
            if "as_maxmind.desc" in ret1:
                results['as_maxmind.description'] = ret1["as_maxmind.desc"]
        if ret2:
            if "as_rw.num" in ret2:
                results['as_rw.num'] = ret2["as_rw.num"]
            if "as_rw.desc" in ret2:
                results['as_rw.description'] = ret2["as_rw.desc"]
        self.log.debug("Results: " + str(results))
        return results

class ASN(NERDModule):
    """
    Geolocation module.

    Queries newly added IP addresses in MaxMind's GeoLite legacy database to get its
    autonomous system information.
    Stores the following attributes:
      asn.id  # ASN
      asn.description # name of ASN

    Event flow specification:
      !NEW -> geoloc -> asn.{id,description}
    """

    def __init__(self, config, update_manager):
        # Instantiate DB reader (i.e. open GeoLite database), raises IOError on error
        geoipFile = config.get("asn.geoipasn_file", "/tmp/GeoIPASNum.dat")
        cacheFile = config.get("asn.cache_file", "/tmp/nerd-asn-cache.json")
        maxValidity = config.get("asn.cache_max_valitidy", 86400)
        self.reader = GetASN(geoipFile, cacheFile, maxValidity)

        update_manager.register_handler(
            self.handleRecord,
            ('!NEW',),
            ('as_maxmind.num', 'as_maxmind.description', 'as_rw.num', 'as_rw.description')
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
        if not result:
            return None

        actions = []
        for key in result:
            actions.append(('set', key, result[key]))

        return actions

