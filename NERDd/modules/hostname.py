
from .base import NERDModule

import requests
import re

import datetime
import logging
import os

class Hostname(NERDModule):
    """
    Hostname module.
    Tags hostnames according to given list and regular expressions

    Event flow specification:
    TODO
    """

    def __init__(self, config, update_manager):
        self.log = logging.getLogger("hostname_tag")
        self.known_domains = config.get("hostname_tagging.known_domains", [])
        self.regex_domains = config.get("hostname_tagging.regex_tagging", [])
        	
        update_manager.register_handler(
	    self.tag_hostname,
	    'ip',
	    ('!NEW','!refresh_hostname'),
	    ('tags',)
        )

    def tag_hostname(self, ekey, rec, updates):
        etype, key = ekey
        if etype != 'ip':
            return None
             
        if "hostname" not in rec:
            self.log.debug("Hostname attribute is not filled for IP ({}).".format(key))
            return None
        
        hostname = rec["hostname"]

        if hostname is None:
            self.log.debug("Hostname attribute is not filled for IP ({}).".format(key))
            return None
        
        for domain in self.known_domains:
            if hostname.endswith(domain[0]):
                self.log.debug("Hostname ({}) ends with domain {} and has been tagged as {}.".format(hostname, domain[0], domain[1]))
                return [('set', 'tags.' + domain[1], {"date_added": datetime.datetime.now()})]
        
        for regex in self.regex_domains:
            if re.match(regex[0], hostname):
                self.log.debug("Hostname ({}) matches regex {} and has been tagged as {}.".format(hostname, regex[0], regex[1]))
                return [('set', 'tags.' + regex[1], {"date_added": datetime.datetime.now()})]
