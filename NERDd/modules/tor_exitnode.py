"""
NERD module tags possible exit TOR nodes.
"""

from .base import NERDModule

import requests
import re

import datetime
import logging
import os

class TORNodes(NERDModule):
    """
    TORNodes module.
    Downloads and parses list of TOR exits nodes.

    Event flow specification:
    [ip] !NEW -> search_in_TORlist() -> tor
    """
    
    def download_list(self, url):
        try:
            r = requests.get(url)
        except requests.exceptions.ConnectionError as e:
            self.log.error("Error getting TOR exit nodes from {}: {}".format(url, str(e)))
            return []
       
        content = r.content
        torlist = []
        for line in content.decode('utf-8').split('\n'):
            if line.startswith("#"):
                continue
            torlist.append(line)
       
        self.log.info("Downloaded TOR exit nodes list from {} with {} entries.".format(url, len(torlist))) 
        return torlist

    def __init__(self, config, update_manager):
        self.log = logging.getLogger("tor_nodes")
        torlisturl = config.get("tor_exitnodes.address")
        
        self.log.debug("Start download TOR exit list from {}.".format(torlisturl))
        self.torlist = self.download_list(torlisturl)
	
        update_manager.register_handler(
	    self.search_in_TORlist,
	    'ip',
	    ('!NEW','!refresh_tornodes'),
	    ('tor',)
        )


    def search_in_TORlist(self, ekey, rec, updates):
        etype, key = ekey
        if etype != 'ip':
            return None
       
        actions = []

        if key in self.torlist:
            actions.append( ('append', 'tor', datetime.datetime.now()) )
            self.log.debug("IP address ({}) is TOR exit node.".format(key))
        else:
            self.log.debug("IP adderss ({}) is not found on TOR exit node list.".format(key))
   
        return actions   
         
