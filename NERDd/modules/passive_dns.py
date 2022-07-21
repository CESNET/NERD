"""
NERD module that queries PassiveDNS and check returned domains for their presence in blacklists 
"""
from core.basemodule import NERDModule
import common.config 
import g

import logging
import redis
from datetime import datetime 
import requests
import json
import os.path

class Blacklist:
    def __init__(self, redis, id):
        self.id = id
        self._redis = redis
        self._key_list = "dbl:"+id+":list"
        self._key_time = "dbl:"+id+":time"
    
    def check(self, ip):
        # TODO - it would be fine if time needn't be loaded every time again
        # Options:
        # - time chached locally with notification on change (needs pub/sub, check for message needs a query);
        # - make date part of key and reload when key doesn't exist (but again, checking if key exists needs a separate query)
        time = self._redis.get(self._key_time).decode('ascii')
        time = datetime.strptime(time, "%Y-%m-%dT%H:%M:%S")
        present = self._redis.sismember(self._key_list, ip)
        return time, present
    

class PassiveDNSResolver(NERDModule):
    """
    PassiveDNSResolver module.

    Query PassiveDNS about given IP and check returned domains against blacklists from Redis.

    Event flow specification:
      [ip] !NEW -> passive_dns_query() -> dbl.id,
    """

    def __init__(self):
        self.log = logging.getLogger("PassiveDNS")
        #self.log.setLevel("DEBUG")

        # Load configuration of passive DNS
        pdns_config = g.config.get("pdns", None)
        if not (pdns_config and pdns_config.get("url") and pdns_config.get("token")):
            self.log.warning("Configuration of Passive DNS (URL and API token) is missing, module disabled.")
            return
        self.base_url = pdns_config.get("url")
        self.token = pdns_config.get("token")

        # Load configuration of blacklists to get Redis connection params
        bl_config_file = os.path.join(g.config_base_path, g.config.get("bl_config", "blacklists.yml"))
        self.log.debug("Loading blacklists configuration from {}".format(bl_config_file))
        bl_config = common.config.read_config(bl_config_file)

        # Connect to Redis
        redis_host = bl_config.get("redis.host", "localhost")
        redis_port = bl_config.get("redis.port", 6379)
        redis_db_index = bl_config.get("redis.db", 0)
        redis_password = bl_config.get("redis.password", None)

        self.log.debug("Connecting to Redis: {}:{}/{}".format(redis_host, redis_port, redis_db_index))
        self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db_index, password=redis_password)
        
        # List of blacklists is get automatically from Redis
        # Domain blacklist format:
        #   dbl:<id>:name -> human readable name of the blacklist (shown in web interface)
        #   dbl:<id>:time -> time of last blacklist update (in ISO format)
        #   dbl:<id>:list -> SET of IPs that are on the blacklist
        # where <id> is unique name of the blacklist (should't contains spaces ' ' or colons ':')
        blnames = [key[4:-5].decode('ascii') for key in self.redis.keys("dbl:*:name")]
        self.blacklists = [Blacklist(self.redis, blname) for blname in blnames]
        
        self.log.info("Loaded {} domain blacklists: {}".format(len(blnames), ', '.join(blnames)))

        itemlist = ['dbl.' + id for id in blnames]
        self.log.debug("Registering {0}".format(itemlist))
        g.um.register_handler(
            self.passive_dns_query,
            'ip',
            ('!NEW','!every1d'),
            itemlist
        )

    def passive_dns_query(self, ekey, rec, updates):
        """
        Query all loaded blacklists for the domains from Passive DNS. Store blacklist
        ID and domain to the IP's record for each blacklist the domain is present on.

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

        # Get all domain names related to the IP
        actions = []
        response = None
        url = "{}ip/{}?token={}".format(self.base_url, key, self.token)
        try:
            response = requests.get(url, timeout=5)
        except Exception as e: # Connection error
            self.log.error("Can't query '{}': {}".format(url, e)) 
            return None

        #self.log.debug('Passive DNS query: ' + key + ', status code: ' + str(response.status_code))
        if response.status_code != 200:
            return None

        # Filter results
        #   'reply' key indicates a "negative" answer (e.g. NXDOMAIN, NODATA).
        #   set() is used to remove duplicates (which may occur since records observed at different servers are stored separately).
        domains = set(rec['domain'] for rec in response.json() if 'domain' in rec and 'reply' not in rec)
        if domains:
            self.log.debug('Passive DNS match: {} -> {}'.format(key, domains))

        # Check each domain against all available blacklists
        for domain in domains:
            domain = domain[:-1] # Domains on Passive DNS are stored in fully qualified format, here we remove the trailing dot.
            for dbl in self.blacklists:
                time, present = dbl.check(domain)
                blname = dbl.id
                if present:
                    self.log.debug("Domain ({0}) is on blacklist {1}.".format(domain, blname))
                    actions.append( ('array_upsert', 'dbl', {'n': blname, 'd': domain}, [('set', 'v', 1), ('set', 't', time), ('append', 'h', time)]) )
                else:
                    # Domain is not on blacklist
                    #self.log.debug("Domain ({0}) is not on blacklist {1}.".format(domain, blname))
                    actions.append( ('array_update', 'dbl', {'n': blname, 'd': domain}, [('set', 'v', 0), ('set', 't', time)]) )
        return actions
