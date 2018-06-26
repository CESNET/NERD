"""
NERD module that queries blacklists chached locally in Reids.
"""
if __name__ == '__main__':
    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../..')))

from core.basemodule import NERDModule
import common.config
import g

import logging
import os.path
import redis
from datetime import datetime

# TODO: check for errors (redis connection error, blacklist data not present)

class BlacklistNotFound(RuntimeError):
    pass

class Blacklist:
    def __init__(self, redis, id):
        self.id = id
        self._redis = redis
        self._key_list = "bl:"+id+":list"
        self._key_time = "bl:"+id+":time"
    
    def check(self, ip):
        # TODO - load both time and presence in a transaction (and/or use WATCH)
        time = self._redis.get(self._key_time)
        if time is None:
            raise BlacklistNotFound() # Blacklist disappeared from Redis
        time = datetime.strptime(time.decode('ascii'), "%Y-%m-%dT%H:%M:%S")
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
        #self.log.setLevel("DEBUG")
        # Load configuration of blacklists (separate from main config)
        bl_config_file = os.path.join(g.config_base_path, g.config.get("bl_config", "blacklists.yml"))
        self.log.debug("Loading blacklists configuration from {}".format(bl_config_file))
        bl_config = common.config.read_config(bl_config_file)
        
        # Connect to Redis
        redis_host = bl_config.get("redis.host", "localhost")
        redis_port = bl_config.get("redis.port", 6379)
        redis_db_index = bl_config.get("redis.db", 0)
        self.log.debug("Connecting to Redis: {}:{}/{}".format(redis_host, redis_port, redis_db_index))
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
        
        itemlist = ['bl:' + id for id in blnames]
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
        bl_to_remove = []

        for bl in self.blacklists:
            try:
                time, present = bl.check(key)
            except BlacklistNotFound:
                # Blacklist disappeared from Redis - remove from list of blacklists and tell admin that it's needed to reload the daemon
                # TODO: reload automatically, but this would need to re-register the handler function with new 'changes', which is currently not supported by UpdateManager.
                bl_to_remove.append(bl) # we can't remove from list while iterating it - do it after loop ends
                self.log.warning("Blacklist {} not found in Redis. Configuration has probably changed - RELOAD NERD TO APPLY NEW CONFIGURATION!")
                # TODO: Should also remove corresponding 'bl' entry from IP record?
                continue
            blname = bl.id
            if present:
                # IP is on blacklist
                self.log.debug("IP address ({0}) is on {1}.".format(key, blname))
                actions.append( ('array_upsert', 'bl', {'n': blname}, [('set', 'v', 1), ('set', 't', time), ('append', 'h', time)]) )
            else:
                # IP is not on blacklist
                #self.log.debug("IP address ({0}) is not on {1}.".format(key, blname))
                actions.append( ('array_update', 'bl', {'n': blname}, [('set', 'v', 0), ('set', 't', time)]) )

        # In case of error, remove blaklists not already present
        for bl in bl_to_remove:
            self.blacklists.remove(bl)
            
        return actions


if __name__ == '__main__':
    # Create minimal environment for testing
    import core.update_manager
    g.config = config.HierarchicalDict({})
    g.um = object()
    g.um.register_handler = lambda a,b,c,d: None
    
    module = RedisBlacklist()
    for ip in ['1.2.3.4', '6.6.6.6', '10.0.0.1']:
        print("Checking {} ...".format(ip))
        actions = module.search_ip(('ip',ip), {}, [])
        print(actions)

