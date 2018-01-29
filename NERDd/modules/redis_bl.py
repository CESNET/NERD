"""
NERD module that queries blacklists chached locally in Reids.
"""
if __name__ == '__main__':
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..')))

from core.basemodule import NERDModule
import g

import logging
import redis
from datetime import datetime

# TODO: check for errors (redis connection error, blacklist data not present)

class Blacklist:
    def __init__(self, redis, id):
        self.id = id
        self._redis = redis
        self._key_list = "bl:"+id+":list"
        self._key_time = "bl:"+id+":time"
    
    def check(self, ip):
        # TODO - it would be fine if time needn't be loaded every time again
        # Options:
        # - time chached locally with notification on change (needs pub/sub, check for message needs a query);
        # - make date part of key and reload when key doesn't exist (but again, checking if key exists needs a separate query)
        time = self._redis.get(self._key_time).decode('ascii')
        time = datetime.strptime(time, "%Y-%m-%dT%H:%M:%S")
        present = self._redis.sismember(self._key_list, ip)
        return time, present
    

class RedisBlacklist(NERDModule):
    """
    RedisBlacklist module.

    Queries blacklists cached in Redis (downloaded by external scripts)

    Event flow specification:
      [ip] !NEW -> search_ip() -> bl.id
    """

    def __init__(self):
        self.log = logging.getLogger("redis_bl")
        # Connect to Redis
        redis_host = g.config.get("redis.host", "localhost")
        redis_port = g.config.get("redis.port", 6379)
        redis_db_index = g.config.get("redis.db_index", 0)
        self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db_index)
        
        # List of blacklists is get automatically from Redis
        # Blacklist format:
        #   bl:<id>:name -> human readable name of the blacklist (shown in web interface)
        #   bl:<id>:time -> time of last blacklist update (in ISO format)
        #   bl:<id>:list -> SET of IPs that are on the blacklist
        # where <id> is unique name of the blacklist (should't contains spaces ' ' or colons ':')
        blnames = [key[3:-5].decode('ascii') for key in self.redis.keys("bl:*:name")]
        self.blacklists = [Blacklist(self.redis, blname) for blname in blnames]
        
        self.log.info("Loaded {} blacklists: {}".format(len(blnames), ', '.join(blnames)))
        
        itemlist = ['bl.' + id for id in blnames]
        self.log.debug("Registering {0}".format(itemlist))
        g.um.register_handler(
            self.search_ip,
            'ip',
            ('!NEW','!every1d'),
            itemlist
        )

    def search_ip(self, ekey, rec, updates):
        """
        Query all loaded blacklists for the given IP address. Store blacklist
        ID to the IP's record for each blacklist the IP is present on.

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

        for bl in self.blacklists:
            time, present = bl.check(key)
            blname = bl.id
            if present:
                # IP is on blacklist
                self.log.debug("IP address ({0}) is on {1}.".format(key, blname))
                actions.append( ('array_upsert', 'bl', ({'n': blname}, [('set', 'v', 1), ('set', 't', time), ('append', 'h', time)])) )
            else:
                # IP is not on blacklist
                self.log.debug("IP address ({0}) is not on {1}.".format(key, blname))
                actions.append( ('array_update', 'bl', ({'n': blname}, [('set', 'v', 0), ('set', 't', time)])) )

        return actions


if __name__ == '__main__':
    # Create minimal environment for testing
    import common.config
    import core.update_manager
    g.config = config.HierarchicalDict({})
    g.um = object()
    g.um.register_handler = lambda a,b,c,d: None
    
    module = RedisBlacklist()
    for ip in ['1.2.3.4', '6.6.6.6', '10.0.0.1']:
        print("Checking {} ...".format(ip))
        actions = module.search_ip(('ip',ip), {}, [])
        print(actions)

