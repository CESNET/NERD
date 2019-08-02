#!/usr/bin/env python3
#-*- encoding: utf-8 -*-

# TODO
# - p�i spu�t�n� zkontrolovat �as posledn�ho updatu v DB
#   - pokud tam bl nen�, ihned st�hnout
#   - pokud tam je, ale se starou �asovou zn�mkou, ihned st�hnout


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
  - regex_or_empty # empty string or None ('~' in yaml)
  - hour: xx
    minute: xx  # dictionary specifying refresh time
- - list_id
  - ...

prefixiplists:
- - ... # same format as iplists except regex. If the prefix is formatted as start and end of IP network, then start
of IP network should be catched as group 1 in regex and end of IP network should be catched as group 2 in regex.

domainlists:
- - ... # same format as iplists

Format of IP lists in Redis:
  bl:<id>:name -> human readable name of the blacklist (shown in web interface)
  bl:<id>:time -> time of last blacklist update (in ISO format)
  bl:<id>:list -> SET of IPs that are on the blacklist
where <id> is unique name of the blacklist (should't contains spaces ' ' or colons ':')

Prefix IP lists are stored in the same way, using prefix "pbl" (prefix) instead of "bl".

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
import ipaddress
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.utils import ipstr2int

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

# dictionary of supported blacklist types
# 'db_prexix' is used, when inserting to Redis
# 'singular' and 'plural' is just for correct printing purposes
bl_all_types = {
    'ip': {'db_prefix': "bl:", 'singular': "IP", 'plural': "IPs"},
    'prefixIP': {'db_prefix': "pbl:", 'singular': "IP range", 'plural': "IP ranges"},
    'domain': {'db_prefix': "dbl:", 'singular': "domain", 'plural': "domains"}
}


def vprint(*_args, **kwargs):
    # Verbose print
    if not args.quiet:
        print("[{}] ".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), end="")
        print(*_args, **kwargs)


def get_blacklist(id, name, url, regex, bl_type="ip"):
    """
    Download the blacklist, parse all its records, try to validate them and insert it into Redis
    :param id: id of the blacklist
    :param name: name of the blacklist
    :param url: url, where can the blacklist be downloaded
    :param regex: regex for correct parsing of blacklist records
    :param bl_type: type of blacklist (ip|prefixIP|domain)
    :return:
    """
    # Download given blacklist and store it into Redis
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    vprint("Getting {} blacklist '{}' from '{}'".format(bl_all_types[bl_type]['singular'], id, url))

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
        print("ERROR: Unknown URL scheme for blacklist {}: {}".format(id, url), file=sys.stderr)
        data = ""

    # Parse the list
    bl_records = []
    if regex:
        cregex = re.compile(regex)
        if cregex.groups == 0:
            # if there are no groups in regex (most probably blacklist with multiple records on one line), try to find
            # all occurrences
            all_records = cregex.finditer(data)
            for ip_match in all_records:
                # for every occurrence found, check if IP address valid and add it to bl_records
                record_start = ip_match.span()[0]
                record_end = ip_match.span()[1]
                try:
                    if "/" in data[record_start:record_end] and bl_type == "prefixIP":
                        # range IP blacklist
                        bl_records.append(ipaddress.IPv4Network(data[record_start:record_end]))
                    elif bl_type == "ip":
                        # classic IP address blacklist
                        bl_records.append(str(ipaddress.IPv4Address(data[record_start:record_end])))
                    else:
                        # domain blacklist
                        bl_records.append(data[record_start:record_end])
                except ipaddress.AddressValueError:
                    continue
        else:
            for line in data.split('\n'):
                match = cregex.search(line)
                if match:
                    # there may be two groups for capturing start IP and end IP of prefix IP BL, depends on BL format
                    try:
                        if cregex.groups == 2 and bl_type == "prefixIP":
                            range_start = ipaddress.IPv4Address(match.group(1))
                            range_end = ipaddress.IPv4Address(match.group(2))
                            # save in cidr notation to later better handle prefix overlaps
                            prefix_in_cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(range_start, range_end)]
                            bl_records += prefix_in_cidr
                        else:
                            if "/" in match.group(1) and bl_type == "prefixIP":
                                # prefix BL in CIDR format, get ip_network instance, which creates list of included IP
                                # addresses
                                prefix_network = ipaddress.IPv4Network(match.group(1))
                                bl_records.append(prefix_network)
                            else:
                                bl_records.append(match.group(1) if bl_type == "domain" else str(ipaddress.IPv4Address(match.group(1))))
                    except ipaddress.AddressValueError:
                        continue
    else:
        if bl_type == "prefixIP":
            # prefix BL in CIDR format, get ip_network instance, which creates list of included IP addresses
            all_data = [line.strip() for line in data.split('\n') if not line.startswith('#') and line.strip()]
            for ip in all_data:
                try:
                    prefix_network = ipaddress.IPv4Network(ip)
                except ipaddress.AddressValueError:
                    continue
                bl_records.append(prefix_network)
        else:
            # records of blacklist are formatted as one IP record per line and does not need additional parsing
            bl_records_non_validated = [line.strip() for line in data.split('\n') if not line.startswith('#') and
                                        line.strip()]
            if bl_type == "ip":
                for record in bl_records_non_validated:
                    try:
                        ipaddr = ipaddress.IPv4Address(record)
                    except ipaddress.AddressValueError:
                        continue
                    bl_records.append(str(ipaddr))
            else:
                # domain is not validated yet
                bl_records = bl_records_non_validated

    if bl_type == "prefixIP":
        prefix_bl_len = len(bl_records)
        # remove overlaps from range IP blacklists
        bl_records = ipaddress.collapse_addresses(bl_records)

    key_prefix = bl_all_types[bl_type]['db_prefix'] + id + ":"
    # Put the list into Redis    
    # Buffer all Redis commands into a Pipeline, so they're all send in a 
    # single request and as a transaction (i.e. as an atomic operation)
    try:
        pipe = r.pipeline()
        pipe.set(key_prefix+"name", name)
        pipe.set(key_prefix+"time", now)
        pipe.delete(key_prefix+"list")
        if bl_records and bl_type != "prefixIP":
            pipe.sadd(key_prefix+"list", *bl_records)
        elif bl_records and bl_type == "prefixIP":
            # save every IP range as sorted set:
            # first value = IP address as integer
            # second value = IP address (add '/' prefix if it is range end to distinguish start from end)
            for record in bl_records:
                pipe.zadd(key_prefix + "list", {str(record.network_address): int(record.network_address)})
                pipe.zadd(key_prefix + "list", {'/' + str(record.broadcast_address): int(record.broadcast_address)})
        else:
            vprint("{} blacklist {} is empty! Maybe the service stopped working.".format(
                bl_all_types[bl_type]['singular'], id))
        pipe.execute()
        vprint("Done, {} {} stored into Redis under '{}list'".format(len(bl_records) if isinstance(bl_records, list)
                                                    else prefix_bl_len, bl_all_types[bl_type]['plural'], key_prefix))
    except redis.exceptions.ConnectionError as e:
        print("ERROR: Can't connect to Redis DB ({}:{}): {}".format(redis_host, redis_port, str(e)), file=sys.stderr)


# Signal handler to gracefully shutdown the program (on SIGINT or SIGTERM)
def stop_program(signum, frame):
    vprint("Signal received, going to exit")
    scheduler.shutdown()


def process_blacklist_type(config_path, bl_type):
    """
    Process one type of blacklists from IP, prefix IP and domain blacklists. First look up all blacklists in Redis and
    delete those, which are no longer in configuration. Then download all blacklists, which are not in Redis yet.
    :param config_path: path to blacklist type settings in configuration file
    :param bl_type: type of blacklist (ip|prefixIP|domain)
    :return: None
    """
    # Get list of blacklists (their IDs) in configuration
    config_lists = set(cfg_item[0] for cfg_item in config.get(config_path, []))
    # Get list of blacklists present in Redis
    keys = r.keys(bl_all_types[bl_type]['db_prefix'] + '*')
    redis_lists = set(key.decode().split(':')[1] for key in keys)

    for id in redis_lists - config_lists:
        vprint(
            "IP blacklist '{}' was found in Redis, but not in current configuration. Removing from Redis.".format(id))
        r.delete(*r.keys(bl_all_types[bl_type]['db_prefix'] + id + ':*'))

    for id, name, url, regex, refresh_time in config.get(config_path, []):
        # TODO: check how old the list is and re-download if it's too old (complicated since cron-spec may be very complex)
        if args.force_refresh:
            get_blacklist(id, name, url, regex, bl_type=bl_type)
        elif r.get(bl_all_types[bl_type]['db_prefix'] + id + ":time") is None:
            vprint("{} blacklist '{}' is not in Redis yet, downloading now.".format(bl_all_types[bl_type]['singular'],
                                                                                    id))
            get_blacklist(id, name, url, regex, bl_type=bl_type)
        else:
            vprint("{} blacklist '{}' is already in Redis, nothing to do for now.".format(
                bl_all_types[bl_type]['singular'], id))


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

# Look up lists in Redis that are no longer in configuration and delete them followed by downloading all blacklists that
# are not in Redis yet
# IP lists
process_blacklist_type("iplists", "ip")
# Prefix IP lists
process_blacklist_type("prefixiplists", "prefixIP")
# Domain lists
process_blacklist_type("domainlists", "domain")

# Schedule periodic updates of blacklists
if not args.one_shot:
    for id, name, url, regex, refresh_time in config.get('iplists', []):
        trigger = CronTrigger(**refresh_time)
        job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, 'ip'),
            trigger=trigger, coalesce=True, max_instances=1)
        vprint("IP blacklist '{}' scheduled to be downloaded at every: {}".format(id, refresh_time))

    for id, name, url, regex, refresh_time in config.get('prefixiplists', []):
        trigger = CronTrigger(**refresh_time)
        job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, 'prefixIP'),
            trigger=trigger, coalesce=True, max_instances=1)
        vprint("IP blacklist '{}' scheduled to be downloaded at every: {}".format(id, refresh_time))

    for id, name, url, regex, refresh_time in config.get('domainlists', []):
        trigger = CronTrigger(**refresh_time)
        job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, 'domain'),
            trigger=trigger, coalesce=True, max_instances=1)
        vprint("Domain blacklist '{}' scheduled to be downloaded at every: {}".format(id, refresh_time))
    
signal.signal(signal.SIGINT, stop_program)
signal.signal(signal.SIGTERM, stop_program)
    
if not args.one_shot:
    vprint("Starting scheduler to periodically update the blacklists ...")
    scheduler.start()

vprint("All work done, exiting")
