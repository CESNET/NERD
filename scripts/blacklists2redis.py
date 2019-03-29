#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

# TODO
# - pøi spuštìní zkontrolovat èas posledního updatu v DB
#   - pokud tam bl není, ihned stáhnout
#   - pokud tam je, ale se starou èasovou známkou, ihned stáhnout

# Najit vsechny listy v Redis a pokud nejaky neni v configu, smazat z Redis
# INFO: Blacklist '{}' was found in Redis, but not in current configuration. Removing from Redis.
# INFO: Blacklist '{}' is not in Redis yet, downloading now.
# VERBOSE: Blacklist '{}' is already in Redis, nothing to do now.


"""
Config format:

redis:
  host: localhost
  port: 6379
  db: 0

iplists:
- - list_id  # unique list ID, should't contains spaces ' ' or colons ':'
  - list_name
  - url
  - regex_or_empty # emtpy string or None ('~' in yaml)
  - hour: xx
    minute: xx  # dictionary specifying refresh time
- - list_id
  - ...

domainlists:
- - ... # same format as iplists

Format of IP lists in Redis:
  bl:<id>:name -> human readable name of the blacklist (shown in web interface)
  bl:<id>:time -> time of last blacklist update (in ISO format)
  bl:<id>:list -> SET of IPs that are on the blacklist
where <id> is unique name of the blacklist (should't contains spaces ' ' or colons ':')

Domain lists are stored in the same way, using prefix "dbl" instead of "bl".
"""

import sys
import argparse
import yaml
import redis
import requests
import re
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.executors.pool import ThreadPoolExecutor
from datetime import datetime
import time
import signal

parser = argparse.ArgumentParser(description="Download blacklists and put them into Redis to be used by NERD workers. Runs permanently and downloads blacklists at times specified in config file.")
parser.add_argument("-c", metavar="FILE", dest='cfg_file', default="/etc/nerd/blacklists.yml",
                    help="Path to configuration file (defualt: /etc/nerd/blacklists.yml)")
parser.add_argument("-f", "--force-refresh", action="store_true",
                    help="Force redownload of all blacklists upon start even if they already exist in Redis.")
parser.add_argument("-o", "--one-shot", action="store_true",
                    help="Only download lists not already present in Redis (or all if -f is specified) and exit.")
parser.add_argument("-q", "--quiet", action="store_true",
                    help="No verbose output (print only errors)")

args = parser.parse_args()

def vprint(*_args, **kwargs):
    # Verbose print
    if not args.quiet:
        print("[{}] ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end="")
        print(*_args, **kwargs)


def get_blacklist(id, name, url, regex, domain=False):
    # Download given blacklist and store it into Redis
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    vprint("Getting {} blacklist '{}' from '{}'".format("domain" if domain else "IP", id, url))
    
    # Download via HTTP(S)
    if url.startswith("http://") or url.startswith("https://"):
        data = None
        try:
            resp = requests.get(url)
            data = resp.content.decode('utf-8', 'ignore')
        except requests.exceptions.ConnectionError as e:
            print("ERROR: Can't download list '{}' from '{}': {}".format(id, url, str(e)))
            data = ""
    # Load from local file
    elif url.startswith("file://"):
        with open(url[7:], encoding='utf-8', errors='ignore') as f:
            data = f.read()
    else:
        print("ERROR: Unknown URL scheme for blacklist {0}: {}".format(id, url), file=sys.stderr)
        data = ""

    # Parse the list
    if regex:
        cregex = re.compile(regex)
        ips = []
        for line in data.split('\n'):
            match = cregex.search(line)
            if match:
                ips.append(match.group(1))
    else:
        ips = [line.strip() for line in data.split('\n') if not line.startswith('#') and line.strip()]
    
    # TODO: Check that all parsed items are indeed IPv4 addresses in correct format    

    key_prefix = ("dbl:" if domain else "bl:") + id + ":"
    # Put the list into Redis    
    # Buffer all Redis commands into a Pipeline, so they're all send in a 
    # single request and as a transaction (i.e. as an atomic operation)
    try:
        pipe = r.pipeline()
        pipe.set(key_prefix+"name", name)
        pipe.set(key_prefix+"time", now)
        pipe.delete(key_prefix+"list")
        if ips:
            pipe.sadd(key_prefix+"list", *ips)
        pipe.execute()
        vprint("Done, {} {} stored into Redis under '{}list'".format(len(ips), "domains" if domain else "IPs", key_prefix))
    except redis.exceptions.ConnectionError as e:
        print("ERROR: Can't connect to Redis DB ({}:{}): {}".format(redis_host, redis_port, str(e)), file=sys.stderr)


# Signal handler to gracefully shutdown the program (on SIGINT or SIGTERM)
def stop_program(signum, frame):
    vprint("Signal received, going to exit")
    scheduler.shutdown()


vprint("Loading configuration from", args.cfg_file)
config = yaml.safe_load(open(args.cfg_file))

# Create scheduler
if not args.one_shot:
    scheduler = BlockingScheduler(timezone='UTC')

# Open connection to Redis
redis_host = config.get("redis",{}).get("host", "localhost")
redis_port = config.get("redis",{}).get("port", 6379)
redis_db = config.get("redis",{}).get("db", 0)
r = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)
try:
    r.ping()
except redis.exceptions.ConnectionError as e:
    print("ERROR: Can't connect to Redis DB ({}:{}): {}".format(redis_host, redis_port, str(e)), file=sys.stderr)
    sys.exit(1)


# Look up lists in Redis that are no longer in configuration and delete them
# IP lists
keys = r.keys('bl:*')
redis_lists = set(key.decode().split(':')[1] for key in keys)
config_lists = set(cfg_item[0] for cfg_item in config['iplists'])
for id in redis_lists - config_lists:
    vprint("IP blacklist '{}' was found in Redis, but not in current configuration. Removing from Redis.".format(id))
    r.delete(*r.keys('bl:'+id+':*'))
# Domain lists
keys = r.keys('dbl:*')
redis_lists = set(key.decode().split(':')[1] for key in keys)
config_lists = set(cfg_item[0] for cfg_item in config['domainlists'])
for id in redis_lists - config_lists:
    vprint("Domain blacklist '{}' was found in Redis, but not in current configuration. Removing from Redis.".format(id))
    r.delete(*r.keys('dbl:'+id+':*'))


# Download all blacklists that are not in Redis yet
# IP lists
for id, name, url, regex, refresh_time in config['iplists']:
    # TODO: check how old the list is and re-download if it's too old (complicated since cron-spec may be very complex)
    if args.force_refresh:
        get_blacklist(id, name, url, regex, domain=False)
    elif r.get("bl:"+id+":time") is None:
        vprint("IP blacklist '{}' is not in Redis yet, downloading now.".format(id))
        get_blacklist(id, name, url, regex)
    else:
        vprint("IP blacklist '{}' is already in Redis, nothing to do for now.".format(id))
# Domain lists
for id, name, url, regex, refresh_time in config['domainlists']:
    # TODO: check how old the list is and re-download if it's too old (complicated since cron-spec may be very complex)
    if args.force_refresh:
        get_blacklist(id, name, url, regex, domain=True)
    elif r.get("dbl:"+id+":time") is None:
        vprint("Domain blacklist '{}' is not in Redis yet, downloading now.".format(id))
        get_blacklist(id, name, url, regex, domain=True)
    else:
        vprint("Domain blacklist '{}' is already in Redis, nothing to do for now.".format(id))


# Schedule periodic updates of blacklists
if not args.one_shot:
    for id, name, url, regex, refresh_time in config['iplists']:
        trigger = CronTrigger(**refresh_time)
        job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, False),
            trigger=trigger, coalesce=True, max_instances=1)
        vprint("IP blacklist '{}' scheduled to be downloaded at every: {}".format(id, refresh_time))

    for id, name, url, regex, refresh_time in config['domainlists']:
        trigger = CronTrigger(**refresh_time)
        job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, True),
            trigger=trigger, coalesce=True, max_instances=1)
        vprint("Domain blacklist '{}' scheduled to be downloaded at every: {}".format(id, refresh_time))
    
signal.signal(signal.SIGINT, stop_program)
signal.signal(signal.SIGTERM, stop_program)
    
if not args.one_shot:
    vprint("Starting scheduler to periodically update the blacklists ...")
    scheduler.start()

vprint("All work done, exiting")
