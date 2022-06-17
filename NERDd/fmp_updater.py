#!/usr/bin/env python3

"""
FMP updater module - periodically updates the FMP score of each entity.

For each known entity a feature vector is assembled and inserted into the trained model, which yields FMP score.
The FMP score is then logged along with the feature vector.
The module also logs whether an attack was observed from an entity in the last 24 hours for the purpose of retraining data models in the future.
To improve performance all updates are executed directly by the database (at once), rather than issuing many new update requests.

Currently supported features:
[alert metadata]
 0 alerts_1d
 1 nodes_1d
 2 conns_1d
 3 alerts_7d
 4 nodes_7d
 5 conns_7d
 6 alerts_ewma
 7 conns_ewma
 8 binalerts_ewma
 9 last_alert_age
[prefix alert metadata]
 10 intervals_avg
 11 intervals_med
 12 prefix_alerts_1d
 13 prefix_nodes_1d
 14 prefix_conns_1d
 15 prefix_ips_1d
 16 prefix_alerts_7d
 17 prefix_nodes_7d
 18 prefix_conns_7d
 19 prefix_ips_7d
 20 prefix_alerts_ewma
 21 prefix_conns_ewma
 22 prefix_binalerts_ewma
[blacklists]
 23 tor_project_org_ips
 24 blocklist-de-ssh
 25 uceprotect
 26 sorbs-dul
 27 sorbs-noserver
 28 sorbs-spam
 29 spamcop
 30 spamhaus-pbl
 31 spamhaus-pbl-isp
 32 spamhaus-xbl-cbl
[tags]
 33 hostname_exists
 34 dynamic_static
 35 dsl
 36 ip_in_hostname
[geolocation]
 37 ctry_badness
 38 asn_badness
"""

import argparse
import sys
import os
import fcntl
import signal
import datetime
import logging
import pandas
import numpy as np
import xgboost as xgb
from collections import Counter
from pymongo import UpdateOne
from pymongo.errors import BulkWriteError
from apscheduler.schedulers.background import BlockingScheduler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import common.config
import common.task_queue
import core.mongodb
from common.utils import ipstr2int, int2ipstr

EWMA_ALPHA = 0.25 # a parameter (there's no strong reason for the value selected, I just feel that 0.25 gives reasonable weights for the 7 day long period)
EWMA_WEIGHTS = [(EWMA_ALPHA * (1 - EWMA_ALPHA)**i) for i in range(7)]


def stop(signal, frame):
    """
    Stop the module.

    Will be evoked on catching SIGINT signal.
    """
    scheduler.shutdown()


def get_asn_sizes(geo_data_dir):
    """
    Parse the GeoLite2 database file(s) and convert them into a dict.

    :return: dict containing ASNs as keys and corresponding number of IP addresses as values
    """
    file_path = f"{geo_data_dir}/GeoLite2-ASN-Blocks-IPv4.csv"
    asn_size_map = Counter()

    # Get total sizes of ASNs from GeoLite database
    first_skipped = False
    for line in open(file_path, encoding='utf-8'):
        if not first_skipped:
            assert line.startswith("network,autonomous_system_number,"), "Unexpected data in '{}'".format(sys.argv[1])
            first_skipped = True
            continue
        if line.strip() == "":
            continue
        net,asn,_ = line.split(',', 2)
        _,prefixlen = net.split('/')
        size = 2**(32-int(prefixlen))
        asn_size_map[asn] += size
    return asn_size_map


def get_ctry_sizes(geo_data_dir):
    """
    Parse the GeoLite2 database file(s) and convert them into a dict.

    :return: dict containing country codes as keys and corresponding number of IP addresses as values
    """
    file_path = f"{geo_data_dir}/GeoLite2-Country-Locations-en.csv"
    ctry_size_map = Counter()
    geoid_ctry_map = dict()

    # Load mapping of geoid to country code
    first_skipped=False
    for line in open(file_path).readlines():
        if not first_skipped:
            assert line.startswith("geoname_id,"), "Unexpected data in '{}'".format(sys.argv[2])
            first_skipped = True
            continue
        if line.strip() == "":
            continue
        geoid,_,_,_,ctry,_ = line.split(',', 5)
        geoid_ctry_map[geoid] = ctry

    # Get total sizes of countries from GeoLite database
    file_path = f"{geo_data_dir}/GeoLite2-Country-Blocks-IPv4.csv"
    first_skipped = False
    for line in open(file_path).readlines():
        if not first_skipped:
            assert line.startswith("network,geoname_id,"), "Unexpected data in '{}'".format(sys.argv[1])
            first_skipped = True
            continue
        if line.strip() == "":
            continue
        net,geoid,geoid2,_,_,_ = line.split(',', 5)
        if geoid == "":
            geoid = geoid2
        ctry = geoid_ctry_map.get(geoid, None)
        if not ctry:
            continue
        _,prefixlen = net.split('/')
        size = 2**(32-int(prefixlen))
        ctry_size_map[ctry] += size
    return ctry_size_map


def get_ctry_badness(ctry, records, geo_data):
    """
    :param ctry: country identifier
    :param records: pandas data frame containing all current records
    :param geo_data: dict containing external geolocation data

    :return: float between 0 and 1 representing the "badness" of given country
    """
    if ctry not in geo_data['badness']['ctry']:
        total_entities_count = geo_data['sizes']['ctry'][ctry]
        known_entities_count = records[records['geo'].apply(lambda x: check_ctry(x, ctry)) == True].index.size
        geo_data['badness']['ctry'][ctry] = known_entities_count / total_entities_count
    return geo_data['badness']['ctry'][ctry]


def get_asn_badness(asn_list, records, geo_data):
    """
    :param asn_list: list of AS identifiers
    :param records: pandas data frame containing all current records
    :param geo_data: dict containing external geolocation data

    :return: float between 0 and 1 representing the average "badness" of given ASNs
    """
    s = 0.0
    for asn in asn_list:
        if asn not in geo_data['badness']['asn']:
            try:
                total_entities_count = geo_data['sizes']['asn'][asn]
                known_entities_count = records[records['asn'].apply(lambda x: contains(x, asn)) == True].index.size
                geo_data['badness']['asn'][asn] = known_entities_count / total_entities_count
            except (KeyError, ZeroDivisionError):
                geo_data['badness']['asn'][asn] = 0
        s += geo_data['badness']['asn'][asn]
    return s / len(asn_list)


def contains(array, value):
    """
    Check whether array contains given value.
    """
    try:
        _ = array.index(value)
        return True
    except ValueError:
        return False


def check_ctry(geo_data, ctry):
    try:
        return geo_data['ctry'] == ctry
    except Exception:
        return False


def bgppref_to_asn(bgppref, records_bgppref):
    """
    Map given BGP prefix to corresponding ASN(s).
    """
    try:
        return list(records_bgppref[records_bgppref['_id'] == bgppref].iloc[0]['asn'])
    except Exception:
        return []


def get_intervals_from_timestamps(timestamps):
    """
    :param timestamps: List of timestamps

    :return: list of floats representing intervals between given timestamps (in days)
    """
    timestamps = sorted(timestamps)
    intervals = []
    for i in range(1, len(timestamps)):
        intervals.append((timestamps[i] - timestamps[i-1]).total_seconds() / 86400)
    return intervals


def get_events_meta(rec, today):
    """
    Count total number of events in last 1 and 7 days for given IP address.

    :param rec: Record of given IP address
    :param today: Time of the update

    :return: Dict containing event counts and other metadata
    """
    total1 = 0
    total7 = 0
    conns1 = 0
    conns7 = 0
    nodes1 = set()
    nodes7 = set()
    alerts_per_day_n = [0]*7;
    alerts_per_day_conns = [0]*7;

    for evtrec in rec['events']:
        n = evtrec['n']
        conns = evtrec.get('conns', 0)
        date = evtrec['date']
        date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
        days_diff = (today - date).days

        if days_diff <= 1:
            total1 += n
            conns1 += conns
            nodes1.add(evtrec['node'])
        if days_diff <= 7:
            total7 += n
            conns7 += conns
            nodes7.add(evtrec['node'])

        if days_diff < 7:
            alerts_per_day_n[days_diff] += n
            alerts_per_day_conns[days_diff] += conns

    return {
        'total1': total1,
        'total7': total7,
        'conns_1d': conns1,
        'conns_7d': conns7,
        'nodes_1d': len(nodes1),
        'nodes_7d': len(nodes7),
        'ewma': sum(n*w for n,w in zip(alerts_per_day_n, EWMA_WEIGHTS)),
        'conns_ewma': sum(conns*w for conns,w in zip(alerts_per_day_conns, EWMA_WEIGHTS)),
        'bin_ewma': sum((w if n else 0) for n,w in zip(alerts_per_day_n, EWMA_WEIGHTS))
    }


def get_prefix_meta(prefix, today, records, prefix_meta):
    """
    Count total number of events in last 1 and 7 days for given IP prefix (/24).

    :param prefix: prefix identifier
    :param today: time of the update
    :param records: pandas data frame containing all current records
    :param prefix_meta: dict containing metadata for each prefix (used as a cache)

    :return: dict containing event counts and other metadata
    """
    if prefix not in prefix_meta:
        total1 = 0
        total7 = 0
        conns1 = 0
        conns7 = 0
        ips1 = set()
        ips7 = set()
        nodes1 = set()
        nodes7 = set()
        alerts_per_day_n = [0]*7;
        alerts_per_day_conns = [0]*7;

        records_from_prefix = records[records['_id'].apply(int2ipstr).str.startswith(prefix)]
        for index, rec in records_from_prefix.iterrows():
            if 'events' not in rec or type(rec['events']) is not list:
                continue
            for evtrec in rec['events']:
                n = evtrec['n']
                conns = evtrec.get('conns', 0)
                date = evtrec['date']
                date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
                days_diff = (today - date).days

                if days_diff <= 1:
                    total1 += n
                    conns1 += conns
                    nodes1.add(evtrec['node'])
                    ips1.add(index)
                if days_diff <= 7:
                    total7 += n
                    conns7 += conns
                    nodes7.add(evtrec['node'])
                    ips7.add(index)

                if days_diff < 7:
                    alerts_per_day_n[days_diff] += n
                    alerts_per_day_conns[days_diff] += conns

        prefix_meta[prefix] = {
            'total1': total1,
            'total7': total7,
            'conns_1d': conns1,
            'conns_7d': conns7,
            'nodes_1d': len(nodes1),
            'nodes_7d': len(nodes7),
            'ips_1d': len(ips1),
            'ips_7d': len(ips7),
            'ewma': sum(n*w for n,w in zip(alerts_per_day_n, EWMA_WEIGHTS)),
            'conns_ewma': sum(conns*w for conns,w in zip(alerts_per_day_conns, EWMA_WEIGHTS)),
            'bin_ewma': sum((w if n else 0) for n,w in zip(alerts_per_day_n, EWMA_WEIGHTS))
        }
    return prefix_meta[prefix]


def update_record(rec, model, records, records_bgppref, updates, prefix_meta, geo_data, today, log):
    """
    Assemble feature vector of given IP, feed it to the model and update its current FMP score.

    :param rec: record of given IP address
    :param model: trained FMP prediction model (currently xgb classifier)
    :param records: pandas data frame containing all current records
    :param records_bgppref: pandas data frame containing BGP prefix records
    :param updates: dict of FMP score update requests (executed at once by the DB)
    :param prefix_meta: dict containing metadata for each prefix (used as a cache)
    :param geo_data: dict containing external geolocation data
    :param today: time of the update
    :param log: global logger
    """
    watched_bl = {
            'tor_project_org_ips' : 0,
            'blocklist-de-ssh' : 1,
            'uceprotect' : 2,
            'sorbs-dul' : 3,
            'sorbs-noserver' : 4,
            'sorbs-spam' : 5,
            'spamcop' : 6,
            'spamhaus-pbl' : 7,
            'spamhaus-pbl-isp' : 8,
            'spamhaus-xbl-cbl': 9
    }

    featV = np.zeros(39)
    transFeatV = np.zeros(39)
    attacked = 0
    i = 0

    # Events metadata
    if 'events' in rec and type(rec['events']) is list:
        metadata = get_events_meta(rec, today)
        featV[i] = attacked = metadata.get('total1', 0)
        i += 1
        featV[i] = metadata.get('conns_1d', 0)
        i += 1
        featV[i] = metadata.get('nodes_1d', 0)
        i += 1
        featV[i] = metadata.get('total7', 0)
        i += 1
        featV[i] = metadata.get('conns_7d', 0)
        i += 1
        featV[i] = metadata.get('nodes_7d', 0)
        i += 1
        featV[i] = metadata.get('ewma', 0)
        i += 1
        featV[i] = metadata.get('conns_ewma', 0)
        i += 1
        featV[i] = metadata.get('bin_ewma', 0)
        i += 1
        np.log1p(featV[:i], out=transFeatV[:i])
    else:
        i += 9

    # Last alert age
    if 'last_warden_event' in rec and type(rec['last_warden_event']) is datetime:
        featV[i] = (datetime.datetime.utcnow() - rec['last_warden_event']).total_seconds() / 86400
        if featV[i] > 7.0:
            featV[i] = float("inf")
        transFeatV[i] = np.exp(-featV[i])
    i += 1

    # Intervals between events
    if 'intervals_between_events' in rec and type(rec['intervals_between_events']) is list:
        intervals = get_intervals_from_timestamps(rec['intervals_between_events'])
        # Average
        featV[i] = np.mean(intervals)
        transFeatV[i] = np.exp(-featV[i])
        i += 1
        # Median
        featV[i] = np.median(intervals)
        transFeatV[i] = np.exp(-featV[i])
        i += 1
    else:
        i += 2

    # Prefix metadata (aggregated events metadata across the whole /24 prefix)
    ipv4 = int2ipstr(rec['_id'])
    prefix = ipv4[:ipv4.rfind('.')]
    metadata = get_prefix_meta(prefix, today, records, prefix_meta)
    j = i
    featV[i] = metadata.get('total1', 0)
    i += 1
    featV[i] = metadata.get('conns_1d', 0)
    i += 1
    featV[i] = metadata.get('ips_1d', 0)
    i += 1
    featV[i] = metadata.get('nodes_1d', 0)
    i += 1
    featV[i] = metadata.get('total7', 0)
    i += 1
    featV[i] = metadata.get('conns_7d', 0)
    i += 1
    featV[i] = metadata.get('ips_7d', 0)
    i += 1
    featV[i] = metadata.get('nodes_7d', 0)
    i += 1
    featV[i] = metadata.get('ewma', 0)
    i += 1
    featV[i] = metadata.get('conns_ewma', 0)
    i += 1
    featV[i] = metadata.get('bin_ewma', 0)
    i += 1
    np.log1p(featV[j:i], out=transFeatV[j:i])

    # Blacklists
    if 'bl' in rec and type(rec['bl']) is list:
        present_blacklists = rec['bl']
        for bl in present_blacklists:
            if bl['n'] in watched_bl.keys() and bl['v'] == 1:
                index = i + watched_bl[bl['n']]
                transFeatV[index] = featV[index] = 1
    i += len(watched_bl)

    # Hostname exists
    if 'hostname' in rec and rec['hostname'] is not None:
        transFeatV[i] = featV[i] = 1
        i += 1

        if 'tags' in rec and type(rec['tags']) is dict:
            tags = rec['tags']

            # Static / dynamic IP
            if 'staticIP' in tags:
                transFeatV[i] = featV[i] = 1
            elif 'dynamicIP' in tags:
                transFeatV[i] = featV[i] = -1

            i += 1

            # DSL
            if 'dsl' in tags:
                transFeatV[i] = featV[i] = 1

            i += 1

            # IP in hostname
            if 'ip_in_hostname' in tags:
                transFeatV[i] = featV[i] = 1

            i += 1
        else:
            i += 3
    else:
        i += 4

    # Ctry badness
    if 'geo' in rec and type(rec['geo']) is dict and 'ctry' in rec['geo']:
        transFeatV[i] = featV[i] = get_ctry_badness(rec['geo']['ctry'], records, geo_data)
    i += 1

    # ASN badness
    if 'asn' in rec and type(rec['asn']) is list:
        transFeatV[i] = featV[i] = get_asn_badness(rec['asn'], records, geo_data)
    i += 1

    # Insert transformed feature vector to the trained model.
    dtest = xgb.DMatrix(np.array([transFeatV]))
    fmp = float(model.predict(dtest))

    # Update fmp.general in the IP record.
    updates.append(UpdateOne({'_id': rec['_id']}, {'$set': {'fmp.general': fmp}}))

    # Log the feature vector and the information whether the IP address was reported in the last 24 hours.
    logFMP(ipv4, featV, fmp, attacked, "/data/fmp/general/", log)


def logFMP(ip, fv, fmp, attacked, path, log):
    """
    :param ip: IP identifier
    :param fv: feature vector
    :param fmp: current fmp score
    :param attacked: information whether the entity was reported in the last 24 hours
    :param path: path to the log file
    :param log: global logger
    """
    # Acquire current UTC time.
    curTime = datetime.datetime.utcnow()
    logTime = curTime.strftime("%Y-%m-%dT%H:%M:%S")
    fileSuffix = curTime.strftime("%Y_%m_%d")

    # Create strings to be inserted into log files.
    attackedBin = '1' if attacked > 0 else '0'
    prefix = logTime + ',' + ip + ','
    suffix = ",{:.4f}".format(fmp)

    # Log feature vector and current FMP score.
    try:
        f = open(os.path.join(path, fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix +
            ','.join(
                [str(int(f)) for f in fv[0:6]] +            # first 6 features are integers
                ['{:.4f}'.format(f) for f in fv[6:12]] +    # next 6 features are floats
                [str(int(f)) for f in fv[12:20]] +          # next 8 features are integers
                ['{:.4f}'.format(f) for f in fv[20:23]] +   # next 3 features are floats
                [str(int(f)) for f in fv[23:37]] +          # next 14 features are integers
                ['{:.4f}'.format(f) for f in fv[37:]]       # the rest are floats
            )
            + suffix + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
    except IOError as e:
        log.warning(f"Unable to log feature vector \'{fv}\' to \'{os.path.join(path, fileSuffix)}\': {e}")


    # Log the information whether the entity was reported in the last 24 hours.
    try:
        f = open(os.path.join(path, 'results', fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + attackedBin + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
    except IOError as e:
        log.warning(f"Unable to log to \'{os.path.join(path, 'results', fileSuffix)}\': {e}")


def fmp_global_update(db, model, geo_data_dir, log):
    """
    Read all current records from the DB and apply the update_record() function to each one.
    Resulting updates are written to DB using bulk_write() (instead of issuing new tasks) to improve performance.

    :param db: database connection
    :param model: trained FMP prediction model (currently xgb classifier)
    :param log: global logger
    """
    log.info("Launching FMP update script")

    t_beg = datetime.datetime.utcnow()
    today = datetime.datetime.utcnow().date()
    updates = []
    prefix_meta = {}
    geo_data = {
        'sizes': {
            'ctry': get_ctry_sizes(geo_data_dir),
            'asn': get_asn_sizes(geo_data_dir)
        },
        'badness': {
            'ctry': {},
            'asn': {}
        }
    }

    # Set print format of feature vectors.
    np.set_printoptions(formatter={'float_kind': lambda x: "{:.4f}".format(x)})

    # Get all current records from DB (ip, bgppref)
    attrs = {'_id': 1, 'events': 1, 'last_warden_event': 1, 'intervals_between_events': 1, 'bl': 1, 'tags': 1, 'hostname': 1, 'geo': 1, 'bgppref': 1}
    records = pandas.DataFrame(list(db._db["ip"].find(filter={}, projection=attrs)))
    records_bgppref = pandas.DataFrame(list(db._db["bgppref"].find(filter={}, projection=attrs)))
    log.info(f"Records to process: {records.index.size}")

    # Map BGP prefix of each record to corresponding list of ASNs
    log.info("Mapping BGP prefixes to ASNs")
    records['asn'] = records['bgppref'].apply(lambda prefix: bgppref_to_asn(prefix, records_bgppref))

    # Update FMP score of each entity
    log.info("Processing records")
    records.apply(lambda rec: update_record(rec, model, records, records_bgppref, updates, prefix_meta, geo_data, today, log), axis=1)

    # Write updates to DB
    log.info("Writing updates to DB")
    try:
        db._db["ip"].bulk_write(updates, ordered=False)
    except BulkWriteError as e:
        log.error(f"bulk_write(): {e.details}")

    t_end = datetime.datetime.utcnow()
    log.info(f"FMP update script finished ({t_end - t_beg})")


if __name__ == "__main__":
    # Parse arguments
    ap = argparse.ArgumentParser(description="FMP updater module - periodically updates the FMP score of each entity.")
    ap.add_argument('-n', '--now', action='store_true', help="Launch the update script immediately and exit once it finishes. By default, it is ran each day at midnight.")
    ap.add_argument("-c", "--config", help="Path to config file", type=str, default="/etc/nerd/nerd.yml")
    ap.add_argument("-m", "--model", help="Path to trained model file", type=str, default="/data/fmp/models/model_general_aoptc_xg200_7.bin")
    ap.add_argument("-g", "--geo_data", help="Path to directory containing geoip data", type=str, default="/data/geoip")
    args = ap.parse_args()
    config_path = args.config
    model_path = args.model
    geo_data_dir = args.geo_data

    # Configure logging
    LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
    LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
    log = logging.getLogger("FMP updater")
    log.setLevel('INFO')
    logging.getLogger("apscheduler.scheduler").setLevel("ERROR")
    logging.getLogger("apscheduler.executors.default").setLevel("WARNING")

    log.info("**** FMP updater started *****")

    # Establish DB connection
    config = common.config.read_config(config_path)
    db = core.mongodb.MongoEntityDatabase(config)

    # Load trained model.
    if os.path.exists(model_path):
        model = xgb.Booster({'nthread': 4})
        model.load_model(model_path)
        log.info("Successfully loaded xgBoost model")
    else:
        log.error(f"Unable to find model file \'{model_path}\'")
        exit()

    if args.now:
        # Run the update function once and exit
        fmp_global_update(db, model, geo_data_dir, log)
    else:
        # Create scheduler
        scheduler = BlockingScheduler(timezone="UTC")

        # Register the update function to run each day at midnight
        scheduler.add_job(lambda: fmp_global_update(db, model, geo_data_dir, log), trigger='cron', day_of_week ='mon-sun', hour=0, minute=0)

        # Register SIGINT handler to stop the updater
        signal.signal(signal.SIGINT, stop)

        scheduler.start()
