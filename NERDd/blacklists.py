#!/usr/bin/env python3

import os
import logging
import signal
import sys
from datetime import datetime, timedelta

import argparse
import yaml
import requests
import re
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
import ipaddress


# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.utils import parse_rfc_time
import common.config
import common.task_queue

scheduler = None

LOGFORMAT = " %(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

log = logging.getLogger('Blacklists')

# set higher logging level for apscheduler messages
logging.getLogger('apscheduler.scheduler').setLevel('WARNING')

# dictionary of supported blacklist types
# 'singular' and 'plural' is just for correct printing purposes
bl_all_types = {
    'ip': {'singular': "IP", 'plural': "IPs"}
}


###############################################################################

def compile_regex(regex):
    if "\\A" in regex:
        # replace "special" configuration character for IP address
        regex = regex.replace("\\A", "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
    if "\\CA" in regex:
        # replace "special" configuration character for CIDR IP address (192.168.0.0/16)
        regex = regex.replace("\\CA", "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}")
    if "\\P" in regex:
        # replace "special" configuration character for IP or CIDR
        regex = regex.replace("\\P", "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(\/\d{1,2})?")
    return re.compile(regex)


def parse_bl_with_regex(bl_data, cregex):
    bl_records = []
    if cregex.groups == 0:
        # if there are no groups in regex (most probably blacklist with multiple records on one line), try to find
        # all occurrences
        all_records = cregex.finditer(bl_data)
        for ip_match in all_records:
            # for every occurrence found, check if IP address valid and add it to bl_records
            record_start = ip_match.span()[0]
            record_end = ip_match.span()[1]
            try:
                # classic IP address blacklist
                bl_records.append(str(ipaddress.IPv4Address(bl_data[record_start:record_end])))
            except ipaddress.AddressValueError:
                continue
    else:
        for line in bl_data.split('\n'):
            match = cregex.search(line)
            if match:
                bl_records.append(str(ipaddress.IPv4Address(match.group(1))))
    return bl_records


def parse_bl_without_regex(bl_data):
    bl_records = []

    # records of blacklist are formatted as one IP record per line and does not need additional parsing
    bl_records_non_validated = [line.strip() for line in bl_data.split('\n') if not line.startswith('#') and
                                line.strip() and not line.startswith("//")]
    for record in bl_records_non_validated:
        try:
            ipaddr = ipaddress.IPv4Address(record)
        except ipaddress.AddressValueError:
            continue
        bl_records.append(str(ipaddr))
    return bl_records


def parse_blacklist(bl_data, bl_type, regex=None):
    """
    Parses downloaded blacklist to the list of individual blacklist records
    :param bl_data: Blacklist data, which will be parsed
    :param bl_type: Type of blacklist (ip|prefixIP|domain) - currently not used
    :param regex: Regular expression, which may be used for parsing records
    :return: List of individual blacklist records
    """
    if regex:
        cregex = compile_regex(regex)
        bl_records = parse_bl_with_regex(bl_data, cregex)
    else:
        bl_records = parse_bl_without_regex(bl_data)

    return bl_records


def download_blacklist(blacklist_url, params=None):
    """
    Downloads desired blacklist and returns it as string
    :param blacklist_url: URL of the blacklist
    :param params: Additional HTTP request parameters. May consist of 'url_params' (GET parameters in URL), '
        headers' (HTTP headers), ...
    :return: Downloaded blacklist as string
    """
    if params is None:
        params = {}
    if blacklist_url.startswith("http://") or blacklist_url.startswith("https://"):
        data = None
        try:
            resp = requests.get(blacklist_url, params=params.get('url_params'), headers=params.get('headers'))
            return resp.content.decode('utf-8', 'ignore')
        except requests.exceptions.ConnectionError as e:
            print("ERROR: Can't download list '{}' from '{}': {}".format(id, blacklist_url, str(e)))
            return ""
    # Load from local file
    elif blacklist_url.startswith("file://"):
        with open(blacklist_url[7:], encoding='utf-8', errors='ignore') as f:
            return f.read()
    else:
        print("ERROR: Unknown URL scheme for blacklist {}: {}".format(id, blacklist_url), file=sys.stderr)
        return ""


def get_blacklist(id, name, url, regex, bl_type, params):
    """
    Download the blacklist, parse all its records, and create worker task for each IP in current blacklist.
    :param id: id of the blacklist
    :param name: name of the blacklist
    :param url: url, where can the blacklist be downloaded
    :param regex: regex for correct parsing of blacklist records
    :param bl_type: type of blacklist (ip|prefixIP|domain)
    :param params: dict of other parameters from config, may contain keys 'url_params' and 'headers'
    :return:
    """

    log.info("Getting {} blacklist '{}' from '{}'".format(bl_all_types[bl_type]['singular'], id, url))
    data = download_blacklist(url, params)
    bl_records = parse_blacklist(data, bl_type, regex)

    download_time = datetime.utcnow()
    now_plus_3days = download_time + timedelta(days=3)

    log.info("{} IPs found, sending tasks to NERD workers".format(len(bl_records)))

    for ip in bl_records:
        task_queue_writer.put_task('ip', ip, [
            ('setmax', '_ttl.bl', now_plus_3days),
            ('array_upsert', 'bl', {'n': id},
                [('set', 'v', 1), ('set', 't', download_time), ('append', 'h', download_time)])
        ], "blacklists")


def stop(signal, frame):
    """
    Stop receiving events.
    Will be evoked on catching SIGINT signal.
    """
    log.info("exiting")
    if scheduler is not None and scheduler.running:
        scheduler.shutdown()



###############################################################################

# Main module code

if __name__ == "__main__":

    # Parse arguments
    parser = argparse.ArgumentParser(
        prog="blacklists.py",
        description="Primary module of the NERD system for downloading and processing blacklists as main source."
    )
    parser.add_argument('-c', '--config', metavar='FILE', default='/etc/nerd/nerdd.yml',
                        help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
    parser.add_argument('-s', '--source', metavar="FILE", dest='cfg_file', default='/etc/nerd/blacklists.yml',
                        help='Path to file with blacklists to download (default: /etc/nerd/blacklists.yml)')
    parser.add_argument("-o", "--one-shot", action="store_true",
                        help="Download and process all blacklists immediately after start and exit.")
    parser.add_argument("--now", action="store_true",
                        help="Download and process all blacklists immediately after start, then continue with periodic "
                             "processing as configured.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="No verbose output (print only errors)")

    args = parser.parse_args()

    if args.verbose:
        log.setLevel('DEBUG')

    # Read config
    log.info("Loading config file {}".format(args.config))
    config = common.config.read_config(args.config)

    config_base_path = os.path.dirname(os.path.abspath(args.config))
    common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
    log.info("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))

    rabbit_config = config.get("rabbitmq")

    # Get number of processes from config
    num_processes = config.get('worker_processes')
    assert (isinstance(num_processes, int) and num_processes > 0),\
        "Number of processes ('num_processes' in config) must be a positive integer"

    # Read config for blacklists
    config = yaml.safe_load(open(args.cfg_file))

    # Create main task queue
    task_queue_writer = common.task_queue.TaskQueueWriter(num_processes, rabbit_config)
    task_queue_writer.connect()

    # Only plain IP lists are supported by this module
    config_path = 'iplists'
    bl_type = 'ip'

    # Process all blacklists now
    if args.now or args.one_shot:
        for bl in config.get(config_path, []):
            id = bl['id']
            name = bl['name']
            url = bl['url']
            regex = bl.get('regex', '')
            refresh_time = bl['time']
            other_params = bl.get('params', {})
            assert isinstance(other_params, dict), "The additional parameter must be a dict (in config of {}.{})".format(
                config_path, id)
            # Process the blacklist
            get_blacklist(id, name, url, regex, bl_type, other_params)

    # Schedule periodic processing...
    if not args.one_shot:
        scheduler = BlockingScheduler(timezone='UTC')

        # Load config of each blacklist and schedule its processing
        # (other_params should be empty or a dict containing optional parameters such as 'url_params' or 'headers')
        for bl in config.get(config_path, []):
            id = bl['id']
            name = bl['name']
            url = bl['url']
            regex = bl.get('regex', '')
            refresh_time = bl['time']
            other_params = bl.get('params', {})

            trigger = CronTrigger(**refresh_time)
            job = scheduler.add_job(get_blacklist, args=(id, name, url, regex, bl_type, other_params),
                                    trigger=trigger, coalesce=True, max_instances=1)

            log.info("{} blacklist '{}' scheduled to be downloaded at every: {}".format(
                   bl_all_types[bl_type]['singular'], id, refresh_time))

        log.info("Starting scheduler to periodically update the blacklists ...")
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        scheduler.start()

    log.info("All work done, exiting")