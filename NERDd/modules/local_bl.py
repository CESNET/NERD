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
    def __init__(self, name, url, re, refresh_spec, tmpdir = ""):
        self.name = name
        self.url = url
        self.re = re
        self.tmpdir = tmpdir
        self.iplist = set()
        self.log = logging.getLogger("local_bl")
        #self.log.setLevel("DEBUG")
        # TODO: Check if a recent version is already in tmpdir and read it instead of downloading a new one
        
        # Register periodic call of the "update" function 
        g.scheduler.register(self.update, **refresh_spec)

    def update(self):
        # TODO PARALLELIZATION this function may be called asynchronously, self.iplist should be replaced atomically in all processes at once
        # Download via HTTP(S)
        if self.url.startswith("http://") or self.url.startswith("https://"):
            self.log.debug("Downloading blacklist '{0}' ...".format(self.name))
            # Download blacklist
            try:
                r = requests.get(self.url)
            except requests.exceptions.ConnectionError as e:
                self.log.error("Error getting list '{0}' from '{1}': {2}".format(self.name, self.url, str(e)))
                self.iplist = set()
                return
            data = r.content.decode('utf-8', 'ignore')
        # Load from local file
        elif self.url.startswith("file://"):
            with open(self.url[7:], encoding='utf-8', errors='ignore') as f:
                data = f.read()
        else:
            self.log.error("Unknown URL scheme for blacklist {0}".format(self.name))

        # Parse blacklist and load it into memory
        iplist = set()
        for line in data.split('\n'):
            ips = re.search(self.re, line)
            if ips:
                iplist.add(ips.group())
        self.log.info("Loaded blacklist '{0}' with {1} entries.".format(self.name, len(iplist)))

        # Replace the old list
        self.iplist = iplist

        # Store blacklist into tmpdir
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
        blacklists = g.config.get("local_bl.lists", [])
        tmpdir = g.config.get("local_bl.tmp_dir", "")
        self._blacklists = {}
        self.log = logging.getLogger("local_bl")

        if blacklists:
            for bl in blacklists:
                if bl[0] not in self._blacklists:
                    self._blacklists[bl[0]] = IPBlacklist(bl[0], bl[2], bl[3], bl[4], tmpdir)
                    self._blacklists[bl[0]].update()

        itemlist = ['bl.' + i for i in self._blacklists]
        self.log.debug("Registering {0}".format(itemlist))
        g.um.register_handler(
            self.search_ip,
            'ip',
            ('!NEW','!every1d'),
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


