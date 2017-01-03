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
#from bs4 import BeautifulSoup
import pickle
import datetime
import logging
import re
import pygeoip
import gzip
import os

class GetASN:
    def __init__(self, geoipasnFile, cacheFile, maxValidity):
        self.cacheFile = cacheFile
        self.geoipasnFile = geoipasnFile
        self.maxValidity = maxValidity
        self.log = logging.getLogger("ASNmodule")
        #self.log.setLevel("DEBUG")
        self.update_asn_dictionary()

        # Create DNS resolver that uses localhost
        self.dnsresolver = dns.resolver.Resolver()
        self.dnsresolver.nameservers = ['127.0.0.1']

    def update_asn_dictionary(self):
        '''Update MaxMind database and list of ASN names.'''

        # *** Try to load cached data ***
        try:
            with open(self.cacheFile, "rb") as f:
                cache = eval(pickle.load(f))
        except Exception:
            cache = { '_create_date': 0 }

        curTime = int(datetime.datetime.now().timestamp())
        if (curTime - cache['_create_date']) < self.maxValidity:
            # Get cached data
            self.log.info("Using ASN list from cache.")
            self._asn_dct = cache['data']
            self._pygeoip = pygeoip.GeoIP(self.geoipasnFile)
            return

        # *** Download list of AS names ***
        self._asn_dct = {}
        self.log.info("Downloading AS info from http://www.cidr-report.org/as2.0/autnums.html")
        r = requests.get("http://www.cidr-report.org/as2.0/autnums.html")
        data = r.text
        #data = open("autnums.html", encoding="latin-1").read()
        
        # Extract content of <pre>
        i1 = data.find("<pre>")
        i2 = data.find("</pre>",i1+5)
        data = data[i1+5 : i2]
        
        # Extract needed information
        # (expected format of one line: '<a href="http://www.cidr-report.org/cgi-bin/as-report?as=AS12&amp;view=2.0">AS12   </a> NYU-DOMAIN - New York University, US')
        for n,line in enumerate(data.splitlines()):
            try:
                i1 = line.find(">AS")
                i2 = line.find("</a>")
                asn = int(line[i1+3:i2])
                name = line[i2+5:]
            except Exception:
                self.log.debug('Parsing of line {} in "autnums.html" failed, skipping'.format(n))
                continue

            # Parse country from the end of the name
            if len(name) >= 4 and name[-4] == "," and name[-3] == " ":
                ctry = name[-2:]
                name = name[:-4].strip()
            else:
                ctry = ""
            self._asn_dct[asn] = (name, ctry)
        
        # *** Download MaxMind GeoIP DB ***
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

        # *** Store data to cache file ***
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
            ret["as_rv.num"] = asnum
            ret["as_rv.desc"] = self._asn_dct[asnum][0]
            self.log.debug("Looked up " + ip_address + " using routeviews: " + ip_address + ": {0} {1} ({2}/{3})".format(ret["as_rv.num"],
                    ret["as_rv.desc"], record[1], record[2]))
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
            if "as_rv.num" in ret2:
                results['as_rv.num'] = ret2["as_rv.num"]
            if "as_rv.desc" in ret2:
                results['as_rv.description'] = ret2["as_rv.desc"]
        self.log.debug("Results: " + str(results))
        return results


class ASN(NERDModule):
    """
    ASN module.

    Queries newly added IP addresses in MaxMind's GeoLite legacy database to get its
    autonomous system information.
    Stores the following attributes:
      asn.id  # ASN
      asn.description # name of ASN

    Event flow specification:
      !NEW -> handleRecord() -> asn.{id,description}
    """

    def __init__(self, config, update_manager):
        # Instantiate DB reader (i.e. open GeoLite database), raises IOError on error
        geoipFile = config.get("asn.geoipasn_file", "/tmp/GeoIPASNum.dat")
        cacheFile = config.get("asn.cache_file", "/tmp/nerd-asn-cache.json")
        maxValidity = config.get("asn.cache_max_valitidy", 86400)
        self.reader = GetASN(geoipFile, cacheFile, maxValidity)

        self.um = update_manager
        update_manager.register_handler(
            self.ip2asn,
            'ip',
            ('!NEW','!refresh_asn'),
            ('as_maxmind.num', 'as_maxmind.description', 'as_rv.num', 'as_rv.description')
        )
        update_manager.register_handler(
            self.asn_info,
            'asn',
            ('!NEW','!refresh_asn_info'),
            ('name', 'descr', 'rir')
        )

    def ip2asn(self, ekey, rec, updates):
        """
        Query GeoLite2 DB to get ASN of the IP address.
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
        for k,v in result.items():
            actions.append(('set', k, v))
            # Add or update a record for the ASN
            if k.endswith('.num'):
                self.um.update(('asn', v), []) # empty list of update_requests - just create the record if not exist

        return actions


    def asn_info(self, ekey, rec, updates):
        """
        Set ASN name and description for each newly added ASN.
        """
        etype, key = ekey
        if etype != 'asn':
            return None
        
        requests = [
            ('set', 'name', self.reader._asn_dct[key][0]),
            ('set', 'ctry', self.reader._asn_dct[key][1]),
            ('set', 'rir', 'xyz'),
        ]
        
        return requests

