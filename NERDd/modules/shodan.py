"""
NERD module getting Shodan information about an IP address from InternetDB API (ports, tags, CPEs).
"""
import logging

from core.basemodule import NERDModule
import g

import requests

class Shodan(NERDModule):
    """
    Shodan InternetDB module.
    
    Retrieves information about a host from the Shodan's Internet database.

    The InternetDB API provides host's ports, tags, and CPEs if available. The data are updated once a week,
    so we ask for each new IP address and then every one week.
    The module stores the following attributes:
      shodan.ports   # open ports
      shodan.tags    # tags
      shodan.cpes    # common platform enumerations
    """
    
    def __init__(self):
        self.log = logging.getLogger("Shodan")
        self.log.setLevel("DEBUG")
        self.log.debug("Module loaded")

        # Event logging using EventCountLogger
        # (if "shodan" group is not configured in EventCountLogger config, DummyEventGroup is returned, which does nothing)
        # Log result of every request to InternetDB API (add_or_update_data, no_data, remove_old_data, rate_limit, unexpected_reply)
        self.elog = g.ecl.get_group("shodan", True)

        g.um.register_handler(
            self.shodan,
            'ip',
            ('!NEW', '!every1w'),
            ('shodan.ports','shodan.tags','shodan.cpes')
        )

    def shodan(self, ekey, rec, updates):
        """
        Retrieves information about a host from the Shodan's Internet database.
        It returns the host's ports, tags, and CPEs if available, or None if the host is not found.
        
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
     
        reply = requests.get(f"https://internetdb.shodan.io/{key}")
        if reply.status_code == 404:
            # Shodan does not have any data about this IP address
            if 'shodan' in rec:
                # We already had some Shodan data in the record -> remove them
                self.elog.log('remove_old_data')
                self.log.debug(f"Shodan info for {key} not available anymore - removing 'shodan' attribute")
                return [('remove', 'shodan')]
            self.elog.log('no_data')
            self.log.debug(f"Shodan info for {key} not available")
            return None
        elif reply.status_code == 429:
            # Rate limit exceeded
            self.elog.log('rate_limit')
            self.log.warning(f"InternetDB rate-limit exceeded")

            return None
        elif reply.status_code != 200:
            self.elog.log('unexpected_reply')
            # Log warning message - status code and at most 500 chars of content (presumably error message)
            self.log.warning(f"Unexpected reply from InternetDB: ({reply.status_code}) {reply.text[:500]}")
            return None

        reply = reply.json()
        ports = reply.get('ports', None)
        tags = reply.get('tags', None)
        cpes = reply.get('cpes', None)
        self.elog.log('add_or_update_data')
        self.log.debug(f"Shodan info for {key} available: {ports}, {tags}, {cpes}")

        return [
            ('set', 'shodan.ports', ports),
            ('set', 'shodan.tags', tags),
            ('set', 'shodan.cpes', cpes),
        ]
        

