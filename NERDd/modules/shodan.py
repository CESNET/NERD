"""
NERD module getting Shodan information about an IP address (ports, tags, CPEs).
"""
import logging

from core.basemodule import NERDModule
import g

import requests

class Shodan(NERDModule):
    """
    Shodan InternetDB module.
    
    Retrieves information about a host from the Shodan Internet database. 
    It returns the host's ports, tags, and CPEs if available, or None if the host is not found.
    Stores the following attributes:
      ports   # open ports
      tags    # tags
      cpes    # common platform enumerations
    
    Event flow specification:
    """
    
    def __init__(self):
        self.log = logging.getLogger("Shodan")
        self.log.info("Loaded")
        g.um.register_handler(
            self.shodan,
            'ip',
            ('!NEW',),
            ('shodan.ports','shodan.tags','shodan.cpes')
        )
    
    def shodan(self, ekey, rec, updates):
        """
        Retrieves information about a host from the Shodan Internet database. 
        It returns the host's ports, tags, and CPEs if available, or None if the host is not found.
        
        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggerd this call and  
          their new values (or events and their parameters) as a list of 
          2-tuples: [(attr, val), (!event, param), ...]

        
        Returns:
        List of update requests.
        """
        etype, key = ekey
        if etype != 'ip':
            return None   
     
        host = requests.get(f"https://internetdb.shodan.io/{key}")
        if host.status_code != 200:
            return None
        
        host = host.json()
        ports = host.get('ports', None)
        tags = host.get('tags', None)
        cpes = host.get('cpes', None)
        
        self.log.debug(f"Added Shodan info for {key}")
        return [
            ('set', 'shodan.ports', ports),
            ('set', 'shodan.tags', tags),
            ('set', 'shodan.cpes', cpes),
        ]
        

