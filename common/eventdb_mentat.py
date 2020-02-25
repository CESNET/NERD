"""
Proxy to event database in external Mentat instance.

Provides MentatEventDatabase class -- a proxy for reading data from Mentat API.
Mentat is supposed to receive the same data as NERD, but via its own channel.
This module only reads the data, storage is not implemented. 
"""
from __future__ import print_function

import json
import logging
import datetime
import requests

from common.utils import parse_rfc_time


class BadEntityType(ValueError):
    pass

class NotConfigured(RuntimeError):
    pass

class GatewayError(RuntimeError):
    pass

class MentatEventDBProxy:
    """
    Event database reading IDEA messages from external Mentat via its API.
    """

    def __init__(self, config):
        """
        Initialize all internal structures as necessary.
        """
        self.log = logging.getLogger('MentatEventDBProxy')
        #self.log.setLevel('DEBUG')
        
        # Load URL and API key from config
        self.base_url = config.get('eventdb_mentat.url', None) # should point to Mentat base API (e.g. https://example.com/mentat/)
        self.api_key = config.get('eventdb_mentat.api_key', None)
        
        # Check presence and validity of config (only print error if invalid)
        if not self.base_url:
            self.log.error("Mentat API used but URL not configured ('eventdb_mentat.url' config entry is missing)")
        elif not (self.base_url.startswith("https://") or self.base_url.startswith("http://")):
            self.log.error("Invalid URL of Mentat API")
            self.base_url = None
        elif not self.base_url.endswith("/"):
            self.base_url += "/" # ensure base_url ends with a slash
        if not self.api_key:
            self.log.error("Mentat API used but api_key not configured ('eventdb_mentat.api_key' config entry is missing)")

    def get(self, etype, key, limit=None, dt_from=None):
        """
        Return all events where given IP is among Sources.
        
        Arguments:
        etype   entity type (str), must be 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        limit   max number of returned events
        dt_from minimal value of DetectTime (datetime) 
        
        Return a list of IDEA messages (strings).
        
        Raise BadEntityType if etype is not 'ip'.
        """
        if etype != 'ip':
            raise BadEntityType("etype must be 'ip'")
        
        if not self.base_url or not self.api_key:
            raise NotConfigured("Mentat DB connection not properly configured")
        
        # Prepare request to Mentat API
        url = self.base_url + "api/events/search?submit=Search"
        url += "&source_addrs="+key
        url += "&limit=" + (str(limit) if limit is not None else "100")
        if dt_from:
            url += "&dt_from=" + dt_from.strftime("%Y-%m-%d %H:%M:%S")
        data = {"api_key": self.api_key}
        # Send request
        try:
            resp = requests.post(url, data)
        except Exception as e:
            raise GatewayError("Can't get data from Mentat database: " + str(e))
        # Parse response
        if resp.status_code == 400 and "search query quota" in resp.text:
            raise GatewayError("Search query quota exceeded, try again later.")
        try:
            result = resp.json()['items']
        except (ValueError, KeyError):
            #self.log.error("Invalid data received from Mentat database: req. URL: '{}', req. body: '{}', resp. code: {}, resp. body: '{}'".format(resp.request.url, resp.request.body, resp.status_code, resp.text))
            raise GatewayError("Invalid data received from Mentat database")
        
        return result
        

    def put(self, ideas):
        """
        Does nothing. Implemented only for compatibility with other EventDB layers.
        
        Arguments:
        ideas    list of IDEA message parsed into Python-native structures
        """
        return
                