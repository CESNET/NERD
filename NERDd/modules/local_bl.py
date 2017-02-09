"""
NERD module that downloads configured blacklists and queries them locally.
"""

from core.basemodule import NERDModule
import g

import requests
import re

import datetime
import logging
import os

class IPBlacklist():
    def __init__(self, name, url, re, tmpdir = ""):
        self.name = name
        self.url = url
        self.re = re
        self.tmpdir = tmpdir
        self.iplist = set()
        self.log = logging.getLogger("local_bl")

    def update(self):
        try:
            r = requests.get(self.url)
        except requests.exceptions.ConnectionError as e:
            self.log.error("Error getting list '{0}' from '{1}': {2}".format(self.name, self.url, str(e)))
            self.iplist = set()
            return
        rc = r.content
        self.iplist = set()
        for line in rc.decode('utf-8').split('\n'):
            ips = re.search(self.re, line)
            if ips:
                self.iplist.add(ips.group())
        self.log.info("Downloaded blacklist {0} with {1} entries.".format(self.name, len(self.iplist)))
        if self.tmpdir:
            with open("{0}/{1}".format(self.tmpdir, self.name), "w") as f:
                f.write(repr(self.iplist))

    def __contains__(self, item):
        """
        Is IP address in this blacklist?

        item(str) IP Address
        Returns: True if blacklisted
        """
        return (item in self.iplist)



class LocalBlacklist(NERDModule):
    """
    LocalBlacklist module.

    Downloads and parses publicly available blacklists and allows for querying IP addresses.

    Event flow specification:
      [ip] !NEW -> search_ip() -> bl.id
    """

    def __init__(self):
        # Instantiate DB reader (i.e. open GeoLite database), raises IOError on error
        blacklists = g.config.get("local_bl.lists", [])
        tmpdir = g.config.get("local_bl.tmp_dir", "")
        self._update = g.config.get("local_bl.update", 3600)
        self._blacklists = {}
        self.log = logging.getLogger("local_bl")

        if blacklists:
            for bl in blacklists:
                if bl[0] not in self._blacklists:
                    self._blacklists[bl[0]] = IPBlacklist(bl[0], bl[2], bl[3], tmpdir)
                    self._blacklists[bl[0]].update()

        itemlist = ['bl.' + i for i in self._blacklists]
        self.log.debug("Registering {0}".format(itemlist))
        g.um.register_handler(
            self.search_ip,
            'ip',
            ('!NEW','!refresh_localbl'),
            itemlist
        )

        # TODO DNS blacklists:
        #update_manager.register_handler(
        #    self.handleRecord,
        #    ('hostname'),
        #    ('bl')
        #)

    def search_ip(self, ekey, rec, updates):
        """
        Query all loaded blacklists for the given IP address. Store blacklist
        ID to the IP's record for each blacklist the IP is present on.

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


