"""
NERD module that queries PassiveDNS and check returned domains for their presence in blacklists 
"""
from core.basemodule import NERDModule 
import g

import logging
import redis
from datetime import datetime 
import requests
import json

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
        self.log = logging.getLogger("redis_bl")
        # Connect to Redis
        redis_host = g.config.get("redis.host", "localhost")
        redis_port = g.config.get("redis.port", 6379)
        redis_db_index = g.config.get("redis.db_index", 0)
        self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db_index)
        
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

        actions = []  
        response = None
        try:
            response = requests.get('https://passivedns.cesnet.cz/pdns/ip/{}'.format(key))
        except gaierror: # Connection error 
            return None

        if response.status_code != 200:
            return None   
             
        domains = [x['domain'] for x in response.json()]
        for domain in domains: # Check domain against all available blacklists 
            domain = domain[:-1] # Remove dot, beacuse domains on Passive DNS are stored in fully qualified format.
            for dbl in self.blacklists:
                print (domain)
                time, present = dbl.check(domain)
                blname = dbl.id
                if present:
                    print ("domena je na blacklistu {}".format(blname))
                    self.log.debug("Domain ({0}) is on {1}.".format(domain, blname))
                    actions.append( ('array_upsert', 'dbl', ({'n': blname, 'd': domain}, [('set', 'v', 1), ('set', 't', now), ('append', 'h', now)])) )                    
                else:
                    print ("domena neni na blacklistu{}".format(blname))
                    # Domain is not on blacklist
                    self.log.debug("Domain ({0}) is not on {1}.".format(domain, blname))
                    actions.append( ('array_update', 'dbl', ({'n': blname, 'd': domain}, [('set', 'v', 0), ('set', 't', time)])) )
        return actions
