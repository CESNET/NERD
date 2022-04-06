import sys
import os
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

# Currently supported features:
# [alert metadata]
#  0 alerts_1d
#  1 nodes_1d
#  2 conns_1d
#  3 alerts_7d
#  4 nodes_7d
#  5 conns_7d
#  6 alerts_ewma
#  7 conns_ewma
#  8 binalerts_ewma
#  9 last_alert_age
# [prefix alert metadata]
#  10 intervals_avg
#  11 intervals_med
#  12 prefix_alerts_1d
#  13 prefix_nodes_1d
#  14 prefix_conns_1d
#  15 prefix_ips_1d
#  16 prefix_alerts_7d
#  17 prefix_nodes_7d
#  18 prefix_conns_7d
#  19 prefix_ips_7d
#  20 prefix_alerts_ewma
#  21 prefix_conns_ewma
#  22 prefix_binalerts_ewma
# [blacklists]
#  23 tor
#  24 blocklist-de-ssh
#  25 uceprotect
#  26 sorbs-dul
#  27 sorbs-noserver
#  28 sorbs-spam
#  29 spamcop
#  30 spamhaus-pbl
#  31 spamhaus-pbl-isp
#  32 spamhaus-xbl-cbl
# [tags]
#  33 hostname_exists
#  34 dynamic_static
#  35 dsl
#  36 ip_in_hostname
# [geolocation]
#  37 ctry_badness
#  38 asn_badness


def stop(signal, frame):
    scheduler.shutdown()


def get_asn_sizes():
    file_path = '/data/geo_data/GeoLite2-ASN-Blocks-IPv4.csv'
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


def get_ctry_sizes():
    file_path = "/data/geo_data/GeoLite2-Country-Locations-en.csv"
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
    file_path = "/data/geo_data/GeoLite2-Country-Blocks-IPv4.csv"
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


def get_badness(attr, value, records, geo_data):
    if value not in geo_data['badness'][attr]:
        total_entities_count = geo_data['sizes'][attr][value]
        known_entities_count = records[records[attr] == value].index.size
        geo_data['badness'][attr][value] = known_entities_count / total_entities_count
    return geo_data['badness'][attr][value]


def get_intervals_from_timestamps(timestamps):
    timestamps = sorted(timestamps)
    intervals = []
    for i in range(1, len(timestamps)):
        intervals.append((timestamps[i] - timestamps[i-1]).total_seconds() / 86400)
    return intervals


def get_events_meta(rec, today):
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
        conns = evtrec['conns']
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
            for evtrec in rec['events']:
                n = evtrec['n']
                conns = evtrec['conns']
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


def update_record(rec, model, records, updates, prefix_meta, geo_data, today, log):
    watched_bl = {
            'tor' : 0,
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
    if 'events' in rec:
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
    if 'last_warden_event' in rec
        featV[i] = (datetime.datetime.utcnow() - rec['last_warden_event']).total_seconds() / 86400
        if featV[i] > 7.0:
            featV[i] = float("inf")
        transFeatV[i] = np.exp(-featV[i])
    i += 1

    # Intervals between events
    if 'intervals_between_events' in rec:
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
    if 'bl' in rec:
        present_blacklists = rec['bl']
        for bl in present_blacklists:
            if bl['n'] in watched_bl.keys() and bl['v'] == 1:
                index = i + watched_bl[bl['n']]
                transFeatV[index] = featV[index] = 1
    i += len(watched_bl)

    # Hostname exists
    if 'hostname' in rec and rec['hostname'] != None:
        transFeatV[i] = featV[i] = 1
        i += 1

        if 'tags' in rec:
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
    if 'geo.ctry' in rec:
        transFeatV[i] = featV[i] = get_badness('geo.ctry', rec['geo.ctry'], records, geo_data)
    i += 1

    # ASN badness
    if 'asn' in rec:
        transFeatV[i] = featV[i] = get_badness('asn', rec['asn'], records, geo_data)
    i += 1

    # Insert transformed feature vector to the trained model.
    dtest = xgb.DMatrix(np.array([transFeatV]))
    fmp = float(model.predict(dtest))

    # Update fmp.general in the IP record.
    updates.append(UpdateOne({'_id': rec['_id']}, {'$set': {'fmp.general': fmp}}))

    # Log the feature vector and the information whether the IP address was reported in the last 24 hours.
    logFMP(ipv4, featV, fmp, attacked, "/data/fmp/general/", log)


def logFMP(ip, fv, fmp, attacked, path, log):
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
                [str(int(f)) for f in fv[0:4]] +  # first 4 features are integers
                ['{:.4f}'.format(f) for f in fv[4:7]] +  # next 3 featerues are floats
                [str(int(f)) for f in fv[7:]]  # the rest are integers
            )
            + suffix + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
    except IOError:
        log.warning(f"Unable to log feature vector \'{fv}\' to \'{os.path.join(path, fileSuffix)}\'.")


    # Log the information whether the entity was reported in the last 24 hours.
    try:
        f = open(os.path.join(path, 'results', fileSuffix), 'a')
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(prefix + attackedBin + '\n')
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
    except IOError:
        log.warning(f"Unable to log to \'{os.path.join(path, 'results', fileSuffix)}\'.")


def fmp_global_update(db, model, log):
    log.info("Launching FMP update script")

    t_beg = datetime.datetime.utcnow()
    today = datetime.datetime.utcnow().date()
    updates = []
    prefix_meta = {}
    geo_data = {
        'sizes': {
            'geo.ctry': get_ctry_sizes(),
            'asn': get_asn_sizes()
        },
        'badness': {
            'geo.ctry': {},
            'asn': {}
        }
    }

    # Set print format of feature vectors.
    np.set_printoptions(formatter={'float_kind': lambda x: "{:.4f}".format(x)})

    # Get all IP records from DB
    records = pandas.DataFrame(list(db._db["ip"].find(filter={}, projection={})))

    # Update FMP score of each entity
    records.apply(lambda rec: update_record(rec, model, records, updates, prefix_meta, geo_data, today, log), axis=1)

    # Write updates to DB
    try:
        db._db["ip"].bulk_write(updates, ordered=False)
    except BulkWriteError as e:
        log.error(f"bulk_write(): {e.details}")

    t_end = datetime.datetime.utcnow()
    log.info(f"FMP update script finished ({t_end - t_beg})")


if __name__ == "__main__":
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
    config = common.config.read_config("/etc/nerd/nerd.yml")
    db = core.mongodb.MongoEntityDatabase(config)

    # Load trained model.
    model_path = "/data/fmp/models/general.bin"
    if os.path.exists(model_path):
        model = xgb.Booster({'nthread': 4})
        model.load_model(model_path)
        log.info("Successfully loaded xgBoost model")
    else:
        log.error(f"Unable to find model file \'{model_path}\'")
        exit()

    # Create scheduler
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(lambda: fmp_global_update(db, model, log), trigger='cron', day_of_week ='mon-sun', hour=0, minute=0)

    # Register SIGINT handler to stop the updater
    signal.signal(signal.SIGINT, stop)

    scheduler.start()