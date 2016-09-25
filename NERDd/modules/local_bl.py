"""
NERD module getting ASN.

"""

from .base import NERDModule

import requests
import re

import datetime
import logging
import os

class IPBlacklist():
    def __init__(self, name, url, re):
        self.name = name
        self.url = url
        self.re = re
        self.iplist = set()
    def update(self):
        r = requests.get(self.url)
        rc = r.content
        self.iplist = set()
        for line in rc.decode('utf-8').split('\n'):
            ips = re.search(self.re, line)
            if ips:
                self.iplist.add(ips.group())
        with open("/data/local_bl/{0}".format(self.name), "w") as f:
            f.write(repr(self.iplist))
    def __contains__(self, item):
        """Is IP address in this blacklist?

item(str) IP Address
Returns: True if blacklisted"""
        return (item in self.iplist)



class LocalBlacklist(NERDModule):
    """
    LocalBlacklist module.

    Downloads and parses publicly available blacklists and allows for querying IP addresses.
    Stores the following attributes:
      asn.id  # ASN
      asn.description # name of ASN

    Event flow specification:
      !NEW -> handleRecord() -> bl.id
    """

    def __init__(self, config, update_manager):
        # Instantiate DB reader (i.e. open GeoLite database), raises IOError on error
        blacklists = config.get("local_bl.lists", [])
        self._update = config.get("local_bl.update", 3600)
        self._blacklists = {}
        self.log = logging.getLogger("local_bl")

        if blacklists:
            for bl in blacklists:
                if bl[0] not in self._blacklists:
                    self._blacklists[bl[0]].update()

        itemlist = ['bl.' + i for i in self._blacklists]
        self.log.info("Registering {0}".format(itemlist))
        update_manager.register_handler(
            self.handleRecord,
            ('!NEW',),
            itemlist
        )

        # TODO DNS blacklists:
        #update_manager.register_handler(
        #    self.handleRecord,
        #    ('hostname'),
        #    ('bl')
        #)

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

        actions = []

        for blname in self._blacklists:
            bl = self._blacklists[blname]
            if key in bl:
                actions.append( ('append', 'bl.' + blname, datetime.datetime.now()) )
                self.log.debug("IP address ({0}) is on {1}.".format(key, blname))
            else:
                self.log.debug("IP address ({0}) is not on {1}.".format(key, blname))

        return actions

    def getBlacklistInfo(self):
        """
        Return a list of blacklists with their properties.

        Returns:
        dict(str(name)): dict(str(url): str())
        """
        l = {}
        for bl in self._blacklists:
            l[bl] = {"url": self._blacklists[bl].url}
        return l


