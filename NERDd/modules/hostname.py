"""
Module classifies type of service associated to given IP according to hostname.
"""
 
from .base import NERDModule

import requests
import re

import datetime
import logging
import os

class HostnameClass(NERDModule):
    """
    HostnameClass module.
    Classifies IP according to hostname and given list of known domains and regular expressions

    Event flow specification:
    [ip] 'hostname' -> hostname_classify() -> 'service.known_domain_service' and/or 'service.hostname_regex_service'
    """

    def __init__(self, config, update_manager):
        self.log = logging.getLogger("hostname_class")
        self.regex_hostname = config.get("hostname_tagging.regex_tagging", [])
        self.known_domains = self.convert_domain_list_to_dict(config.get("hostname_tagging.known_domains", []))
        	
        update_manager.register_handler(
	    self.hostname_classify,
	    'ip',
	    ('hostname',),
	    ('service.known_domain_service', 'service.hostname_regex_service')
        )

    def convert_domain_list_to_dict(self, domain_list):
        """
        Converts list of domains and types of service to dictionary because of better time complexity of search operation.
        
        Arguments:
        domain_list -- list of lists of known domains and their type of service

        Return:
        Dicitonary with known domain as a key and type of service as a value
        """

        ret = {}
        for domain in domain_list:
             ret[domain[0]] = domain[1]
        return ret

    def hostname_classify(self, ekey, rec, updates):
        """
        Searches each hostname portion in known domain dictionary and sets type of service if match found. 
        Tries to match hostname with regular expression and sets type of service if matches.

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
        
        hostname = rec["hostname"]

        if hostname is None:
            self.log.debug("Hostname attribute is not filled for IP ({}).".format(key))
            return None
        
        ret = []
        
        dot_count = hostname.count(".")
        
        for i in range(0,dot_count):
            portion = hostname.split(".",i)[-1]
            if portion in self.known_domains:
                self.log.debug("Hostname ({}) ends with domain {} and has been classified as {}.".format(hostname, portion, self.known_domains[portion]))
                ret.append(('set', 'service.known_domain_service', self.known_domains[portion]))
                break
        
        for regex in self.regex_hostname:
            if re.match(regex[0], hostname):
                self.log.debug("Hostname ({}) matches regex {} and has been classified as {}.".format(hostname, regex[0], regex[1]))
                ret.append(('set', 'service.hostname_regex_service', regex[1]))
        
        return ret
