#!/usr/bin/env python3
from __future__ import print_function
import time
import redis

# Redis format:
# <id>.c    - number of tokens in <id>'s bucket
# <id>.t    - timestamp of last addition of tokens into the bucket
# <id>.bs   - bucket size of given user (<id>)
# <id>.tps  - tokens-per-sec of given used (<id>)
#
# Tokens are not being added periodically, as in basic definition of token
# bucket algorithm. Instead, timestamp of last addition is stored and on each
# query, the number of tokens that would be added to bucket since the last time
# is added to the current number.
# Redis keys expire when the number of tokens would reach the bucket size.
#
# Bucket size and tokens-per-sec (.bs, .tps) per user is queried via a function
# passed to constructor and cached in Redis for 1 minute.
# If no user-specific rate-limits params are set, defaults are used.
#
# To disable rate-limiting for some user, set it's tokens-per-sec to infinity.

# TODO support for wait parameter

LIMITS_CACHE_EXPIRE = 60

INF = float('inf')

class RateLimiter:
    def __init__(self, config, get_user_limits=lambda id: None):
        """
        Initialize RateLimiter.
        
        config - HierarchicalDict containing 'rate-limit' section with config
        get_user_limits - function used to get bucket-size and tokens-per-sec
          for given user. Takes user ID as parameter, returns two tuple
          bucket-size, tokens-per-sec or None (in which case defaults are used)
        """
        # Load default rate-limit parameters
        # If nothing is cofingured, the following is used:
        #    1 request per second, bucket size 50 (i.e. bursts of up to 50 requests are allowed)
        self.def_bucket_size = float(config.get('rate-limit.bucket-size', 50))
        self.def_tokens_per_sec = float(config.get('rate-limit.tokens-per-sec', 1))
        
        self.get_user_limits = get_user_limits
        
        # Redis connection
        redis_host = config.get("rate-limit.redis.host", "localhost")
        redis_port = config.get("rate-limit.redis.port", 6379)
        redis_db_index = config.get("rate-limit.redis.db_index", 1)
        self.redis = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db_index) 

    def get_tokens(self, id):
        """Get the current number of tokens available for the given user"""
        # Get user's rate-limit params
        bs,tps = self.get_user_params(id)
        if tps == INF:
            return bs

        current_time = time.time()
        # Read count and last update time from Redis
        # (do it in transaction, so both values are read at the same time)
        with self.redis.pipeline() as pipe:
            pipe.multi()
            pipe.get(id+':c')
            pipe.get(id+':t')
            r_count, r_time = pipe.execute()
        # Compute current number of tokens
        if r_count is None or r_time is None:
            # If no record is found, no query has been made recently - bucket is full
            return bs
        else:
            # Otherwise, add tokens_per_sec * time_from_last_update to the bucket
            return min(float(r_count) + (current_time - float(r_time)) * tps, bs)

    def try_request(self, id, cost=1, wait=False):
        """
        Check if request can be made, return True or False.
        
        If given user have at least 'cost' tokens, return True and remove the
        tokens from the bucket, otherwise return False.
        If wait is True, ... (TODO)
        
        id      Identification of user (username or src IP, always as string)
        cost    Number of tokens to remove from bucket
        wait    Block code execution until enough tokens are available
        
        Return True/False (if request can be made)
        """
        return self._check_and_set_tokens(id, cost, wait)[0]

    def get_user_params(self, id):
        """Get user's rate-limit params, return (bucket-size, tokens-per-sec)"""
        key_bs = id+':bs'
        key_tps = id+':tps'
        # Try to load cached params from redis
        bs = self.redis.get(key_bs) # bucket-size
        tps = self.redis.get(key_tps) # tokens-per-sec
        if bs is None or tps is None:
            # Nothing cached, load user-specific params or use defaults
            bs, tps = self.get_user_limits(id) or (self.def_bucket_size, self.def_tokens_per_sec)
            # Sotre params to cache
            pipe = self.redis.pipeline()
            pipe.set(key_bs, bs)
            pipe.set(key_tps, tps)
            pipe.expire(key_bs, LIMITS_CACHE_EXPIRE)
            pipe.expire(key_tps, LIMITS_CACHE_EXPIRE)
            pipe.execute()
        return float(bs), float(tps)

    def _check_and_set_tokens(self, id, cost=1, wait=False):
        """
        Same as try_request, but also return remaining tokens.
        
        Return two tuple:
        - True/False (if request can be made) 
        - remaining number of tokens
        """
        key_c = id+':c'
        key_t = id+':t'
        
        # Get user's rate-limit params
        bs,tps = self.get_user_params(id)
        if tps == INF:
            return True, INF
        
        # Token-bucket algorithm
        current_time = time.time()
        while True:
            with self.redis.pipeline() as pipe:
                # Watch id:c and id:t for changes by someone else
                #print("watch:", key_c, key_t)
                pipe.watch(key_c, key_t)
                # Read count and last update time from Redis
                r_count = pipe.get(key_c)
                r_time = pipe.get(key_t)
                # Compute current number of tokens
                if r_count is None or r_time is None:
                    # If no record is found, no query has been made recently - bucket is full
                    tokens = bs
                else:
                    # Otherwise, add tokens_per_sec * time_from_last_update to the bucket
                    tokens = min(float(r_count) + (current_time - float(r_time)) * tps, bs)
                # Try to consume tokens
                if tokens >= cost:
                    # If the number of tokens is greater than the cost, substract the cost
                    # from the tokens, result is True
                    tokens -= cost
                    result = True
                elif tokens < cost and tokens >= 0:
                    # If the number of tokens is less than cost and greater than or equal to zero,
                    # substract the cost from the tokens, wait is True
                    tokens -= cost
                    wait = True
                else:
                    # Otherwise, the number of tokens is a negative number, which means that 
                    # one process is waiting 
                    return False, tokens
                # Set new number of tokens (in transaction)
                pipe.multi()
                pipe.set(key_c, tokens)
                pipe.set(key_t, current_time)
                # Set expiration (keys should expire when the bucket would be filled,
                # i.e. after remaining_space / tokens_per_sec
                ttl = (bs - tokens) / tps
                ttl = int(ttl) + 1 # Round up (it's not a problem if it expire later)
                pipe.expire(key_c, ttl)
                pipe.expire(key_t, ttl)
                #print("sleep 5")
                #time.sleep(5)
                if wait:
                    # If wait is True, then will sleep until the number of tokens becomes
                    # greater than or equal to zero
                    wait = False
                    time.sleep(-tokens/tps)
                    result = True
                try:
                    #print("execute")
                    pipe.execute()
                    #print("ok")
                    break
                except redis.WatchError:
                    #print("watch error")
                    continue # Someone else modified the number of tokens, try again
        #print("[RateLimiter] ID: {}, tokens: {}, tps: {}, result: {}".format(id, tokens, tps, result))
        return result, tokens

# Simple non-automated unit test
if __name__ == '__main__':
    import sys
    config = {
        'rate-limit.bucket-size': 5,
        'rate-limit.tokens-per-sec': 0.2,
        'rate-limit.redis.db_index': 1, # Use Redis DB which is not used for anything else!!!
    }
    
    print("Going to use Redis at localhost:6379, DB index {}.".format(config['rate-limit.redis.db_index']))
    print("!! Check that this Redis DB is not used for anything else !!")
    print("   (Hint: Run 'redis-cli -n {}' and enter 'keys *')".format(config['rate-limit.redis.db_index']))
    i = input("Can we continue? [y/N] ")
    if i.lower() != 'y':
        sys.exit(0)
    
    user_params = {
        'a': (10, 0.5),
        'b': (1, 0.333),
    }
    rl = RateLimiter(config, lambda id: user_params.get(id, None))
    print("Enter some ID (random string) to make a request. Empty ID prints current number of tokens of last ID. Press Ctrl-C to exit")
    last_id = ''
    while True:
        id = input()
        if id:
            last_id = id
            result, tokens = rl._check_and_set_tokens(id)
            print("Request sucessful" if result else "Too many requests")
            print("Remaining tokens:", tokens)
        else:
            tokens = rl.get_tokens(last_id)
            print("Remaining tokens:", tokens)
    
