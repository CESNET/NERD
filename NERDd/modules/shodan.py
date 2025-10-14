"""
NERD module getting Shodan information about an IP address from InternetDB API (ports, tags, CPEs).
"""
import logging
import time

from core.basemodule import NERDModule
import g

import requests

RATE_LIMIT_SLEEP = 10 # seconds to wait when rate limit is hit (code 429 is returned form API)
RATE_LIMIT_MAX_RETRIES = 0 # retry the request this number of times, give up when API still returns error 429
DONT_UPDATE_SHORT_LIVED_IPS = True # Skip weekly updates for IPs that are not present in the database for long (they don't have _ttl.long_active tag)

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
        #self.log.setLevel("DEBUG")
        self.log.debug("Module loaded")

        # Event logging using EventCountLogger
        # (if "shodan" group is not configured in EventCountLogger config, DummyEventGroup is returned, which does nothing)
        # Log result of every request to InternetDB API (add_or_update_data, no_data, remove_old_data, rate_limit, unexpected_reply)
        self.elog = g.ecl.get_group("shodan", True)

        g.um.register_handler(
            self.shodan,
            'ip',
            ('!NEW', '!every1w', '!refresh_shodan'),
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

        # To lower the number of queries, perform weekly updates only for addresses with "long_active" TTL tag
        # (by default those that are in the database for at least 30 days)
        if DONT_UPDATE_SHORT_LIVED_IPS and ('!every1w', None) in updates and not rec.get('_ttl', {}).get('long_active'):
            self.elog.log('skipped')
            self.log.debug(f"Shodan update skipped for short-lived IP {key}.")
            return None

        rate_limit_retry_counter = 0
        while True:
            try:
                reply = requests.get(f"https://internetdb.shodan.io/{key}")
            except Exception as e:
                self.log.error(f"Shodan request failed: {e}")
                return None

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
                # Rate limit exceeded - sleep for a few seconds and try again
                self.elog.log('rate_limit')
                if rate_limit_retry_counter >= RATE_LIMIT_MAX_RETRIES:
                    self.log.warning(f"InternetDB rate-limit exceeded, giving up.")
                    return None
                self.log.warning(f"InternetDB rate-limit exceeded, will try again after {RATE_LIMIT_SLEEP}")
                rate_limit_retry_counter += 1
                time.sleep(RATE_LIMIT_SLEEP)
                continue
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
        
