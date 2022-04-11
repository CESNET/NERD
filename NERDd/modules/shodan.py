"""
NERD module querying Shodan.io using its Python API.

Requirements:
- "shodan" package
"""

from core.basemodule import NERDModule
import g

import logging
import threading
import shodan

# *** Global lock disabling parallel querying ***
# Shodan API has a limit on query rate. Normally API response is so slow
# (there is probably an artifically added delay) that the threshold can not be
# exceeded by sequential querying. If we would send queries by more threads in
# parallel, the rate limit would be easily exceeded and API would return errors.
#
# IMPORTANT: The API query takes around 0.7 second (according to my experiments 
# at the time of writing), so maximal rate of queries is ~1.4/s.
# THIS LIMITS THE MAXIMAL RATE OF NEW IPs NERD CAN PROCESS and also MAXIMAL 
# NUMBER OF IPs IN DATABASE (since Shodan info of IPs is updated every week)
shodan_api_lock = threading.Lock()


class Shodan(NERDModule):
    """
    Module querying IP addresses in Shodan
    
    Queries newly added IP addresses to Shodan database to get list of open 
    ports and other available info.
    
    Event flow specification:
      !NEW -> getShodanInfo -> shodan.{ports,os,devicetype,linktype,tags}
    """
    
    def __init__(self):
        self.log = logging.getLogger('Shodan')
        #self.log.setLevel("DEBUG")
        self.errors = 0 # Number of API errors that has occurred
        self.enabled = True
        
        self.apikey = g.config.get('shodan_api_key', None)
        if not self.apikey:
            self.log.warning("No API key set, Shodan module disabled.")
            return
        
        try:
            self.client = shodan.Shodan(key=self.apikey)
            self.client.info() # Test connection and validity of the key
        except shodan.exception.APIError as e:
            self.log.error("Cannot initialize Shodan module: {}".format(str(e)))
            self.log.error("Shodan module disabled.")
            return

        g.um.register_handler(
            self.getShodanInfo, # function (or bound method) to call
            'ip', # entity type
            ('!NEW','!every1w'), # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('shodan.ports','shodan.os','shodan.devicetype','shodan.linktype','shodan.tags',) # tuple/list/set of attributes the method may change
        )
        self.log.info("Shodan module initialized")


    def getShodanInfo(self, ekey, rec, updates):
        """
        Query Shodan via its API for the IP address. Get basic information - 
        list of opened ports, OS, device type, link type and tags.
        
        Arguments:
        ekey -- two-tuple of entity type and key, e.g. ('ip', '192.0.2.42')
        rec -- record currently assigned to the key
        updates -- list of all attributes whose update triggered this call and  
          their new values (or events and their parameters) as a list of 
          2-tuples: [(attr, val), (!event, param), ...]
        
        Returns:
        List of the following update requests (some may not be present):
          ('set', 'shodan.ports', [list_of_numbers])
          ('set', 'shodan.os', 'os_name')
          ('set', 'shodan.devicetype', 'device_type')
          ('set', 'shodan.linktype', 'link_type')
          ('set', 'shodan.tags', 'tags')  # e.g. "vpn" or "tor"
        """
        if not self.enabled:
            return None
        
        etype, key = ekey
        if etype != 'ip':
            return None
        
        ip = key

        self.log.debug("Querying Shodan for {}".format(ip))
        
        try:
            with shodan_api_lock: # This ensures only one thread can process the query at a time
                data = self.client.host(ip, minify=True)
        except shodan.exception.APIError as e:
            if str(e) == "No information available for that IP.":
                self.log.debug("Shodan info for {}: Not found".format(ip))
                # Store empty dict into "shodan" key to mark that the info was queried but the IP is not in Shodan DB
                return [('set', 'shodan', dict())]
            else:
                self.log.error("Error when querying '{}': {}".format(ip, str(e)))
                self.errors += 1
                if self.errors > 10:
                    self.log.critical("More than 10 API errors -> stopping module".format(ip, str(e)))
                    self.enabled = False
            return None
        
        self.log.debug("Shodan info for {}: {}".format(ip, data))
        
        update_requests = []

        # Check presence of various fields and check whether they have expected format
        # If it is OK, add its value to our IP record.
        # TODO: remove fields that may be set before but are no longer returned by Shodan
        if 'ports' in data and data['ports']:
            ports = data['ports']
            if isinstance(ports, list) and all(map(lambda x: isinstance(x, int), ports)):
                update_requests.append(('set', 'shodan.ports', ports))
            else:
                self.log.error("Error when querying '{}': Unexpected format of 'ports': {}".format(ip, repr(ports)))

        if 'os' in data and data['os']:
            os = data['os']
            if isinstance(os, str):
                update_requests.append(('set', 'shodan.os', os))
            else:
                self.log.error("Error when querying '{}': Unexpected format of 'os': {}".format(ip, repr(os)))

        if 'devicetype' in data and data['devicetype']:
            devicetype = data['devicetype']
            if isinstance(devicetype, str):
                update_requests.append(('set', 'shodan.devicetype', devicetype))
            else:
                self.log.error("Error when querying '{}': Unexpected format of 'devicetype': {}".format(ip, repr(devicetype)))
        
        if 'linktype' in data and data['linktype']:
            linktype = data['linktype']
            if isinstance(linktype, str):
                update_requests.append(('set', 'shodan.linktype', linktype))
            else:
                self.log.error("Error when querying '{}': Unexpected format of 'linktype': {}".format(ip, repr(linktype)))
        
        if 'tags' in data and data['tags']:
            tags = data['tags']
            if isinstance(tags, list) and all(map(lambda x: isinstance(x, str), tags)):
                update_requests.append(('set', 'shodan.tags', tags))
            else:
                self.log.error("Error when querying '{}': Unexpected format of 'tags': {}".format(ip, repr(tags)))
        
        
        self.log.debug("Shodan update requests for {}: {}".format(ip, update_requests))
        
        return update_requests
