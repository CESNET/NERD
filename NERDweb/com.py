import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import common.config
from flask_mail import Mail
from flask import Flask, Response
from flask_pymongo import PyMongo
from event_count_logger import EventCountLogger, EventGroup, DummyEventGroup
from flask_wtf import FlaskForm
from wtforms import validators, StringField, TextAreaField, FloatField, IntegerField, BooleanField, HiddenField, SelectField, SelectMultipleField, PasswordField
from common.utils import ipstr2int, int2ipstr, parse_rfc_time
from datetime import datetime, timedelta, timezone

DEFAULT_CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "/etc/nerd/nerdweb.yml"))

# TODO parse arguments using ArgParse
if len(sys.argv) >= 2:
    cfg_file = sys.argv[1]
else:
    cfg_file = DEFAULT_CONFIG_FILE
cfg_dir = os.path.dirname(os.path.abspath(cfg_file))

# Read web-specific config (nerdweb.cfg)
config = common.config.read_config(cfg_file)

# Read EventCountLogger config (to separate dict) and initialize loggers
ecl_cfg_filename = config.get('event_logging_config', None)
if ecl_cfg_filename:
    # Load config
    config_ecl = common.config.read_config(os.path.join(cfg_dir, ecl_cfg_filename))
    # Initialize EventCountLogger
    ecl = EventCountLogger(config_ecl.get('groups'), config_ecl.get('redis', {}))
    # Get instances of EventGroups (if specified in configuration, otherwise, DummyEventGroup is used, so logging is no-op)
    # (it's recommended to enable local counters for both groups for better performance)
    log_ep = ecl.get_group('web_endpoints') or DummyEventGroup()  # log access to individual endpoints
    log_err = ecl.get_group('web_errors') or DummyEventGroup()  # log error replies
else:
    print("WARNING: nerd_main: Path to event logging config ('event_logging_config' key) not specified, EventCountLogger disabled.")
    log_ep = DummyEventGroup()
    log_err = DummyEventGroup()

app = Flask(__name__)

app.secret_key = config.get('secret_key')

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Configuration of PyMongo
mongo_dbname = config.get('mongodb.dbname', 'nerd')
mongo_host = config.get('mongodb.host', 'localhost:27017')
if isinstance(mongo_host, list):
    mongo_host = ','.join(mongo_host)
mongo_uri = "mongodb://{}/{}".format(mongo_host, mongo_dbname)
mongo_rs = config.get('mongodb.rs', None)
if mongo_rs:
    mongo_uri += '?replicaSet='+mongo_rs
app.config['MONGO_URI'] = mongo_uri
print("MongoDB: Connecting to: {}".format(mongo_uri))

mongo = PyMongo(app)

# Configuration of MAIL extension
app.config['MAIL_SERVER'] = config.get('mail.server', 'localhost')
app.config['MAIL_PORT'] = config.get('mail.port', '25')
app.config['MAIL_USE_TLS'] = config.get('mail.tls', False)
app.config['MAIL_USE_SSL'] = config.get('mail.ssl', False)
app.config['MAIL_USERNAME'] = config.get('mail.username', None)
app.config['MAIL_PASSWORD'] = config.get('mail.password', None)
app.config['MAIL_DEFAULT_SENDER'] = config.get('mail.sender', 'NERD <noreply@nerd.example.com>')

mailer = Mail(app)

def validator_optional(form, field):
    if not field.data:
        field.errors[:] = []
        raise validators.StopValidation()

def strip_whitespace(s):
    if isinstance(s, str):
        s = s.strip()
    return s


def clean_secret_data(data):
    """Remove all keys starting with '_' (except '_id') from dict."""
    if data is not None:
        for i in list(data):
            if i.startswith("_") and i != "_id":
                del data[i]
    return data

def attach_whois_data(ipinfo, full):
    """
    Attach records of related entities to given IP record.

    If full==True, attach full records of BGP prefix, ASNs, IP block, Org entities (as 'bgppref, 'asn', 'ipblock' and 'org' keys),
    otherwise only attach list of ASN numbers (as 'asn' key).
    """
    if not full:
        # Only attach ASN number(s)
        if 'bgppref' in ipinfo:
            bgppref_rec = mongo.db.bgppref.find_one({'_id': ipinfo['bgppref']}, {'asn': 1})
            if bgppref_rec is None:
                print("ERROR: Can't find BGP prefix '{}' in database (trying to enrich IP {})".format(ipinfo['bgppref'], ipinfo['_id']))
                return
            if 'asn' in bgppref_rec:
                ipinfo['asn'] = bgppref_rec['asn']
        return

    # Full - attach full records of related BGP prefix, ASNs, IP block, Org
    # IP->BGPpref
    if 'bgppref' in ipinfo:
        bgppref_rec = clean_secret_data(mongo.db.bgppref.find_one({'_id': ipinfo['bgppref']}))
        if bgppref_rec is None:
            print("ERROR: Can't find BGP prefix '{}' in database (trying to enrich IP {})".format(ipinfo['bgppref'], ipinfo['_id']))
        else:
            # BGPpref->ASN(s)
            asn_list = []
            for asn in bgppref_rec['asn']:
                asn_rec = clean_secret_data(mongo.db.asn.find_one({'_id': asn}))
                if asn_rec is None:
                    print("ERROR: Can't find ASN '{}' in database (trying to enrich IP {}, bgppref {})".format(asn, ipinfo['_id'], bgppref_rec['_id']))
                else:
                    # ASN->Org
                    if 'org' in asn_rec:
                        org_rec = clean_secret_data(mongo.db.org.find_one({'_id': asn_rec['org']}))
                        if org_rec is None:
                            print(
                                "ERROR: Can't find Org '{}' in database (trying to enrich IP {}, bgppref {}, ASN {})".format(
                                    asn_rec['org'], ipinfo['_id'], bgppref_rec['_id'], asn))
                        else:
                            conv_dates(org_rec)
                            asn_rec['org'] = org_rec

                    del asn_rec['bgppref']
                    conv_dates(asn_rec)
                    asn_list.append(asn_rec)

            del bgppref_rec['asn']
            conv_dates(bgppref_rec)
            ipinfo['bgppref'] = bgppref_rec
            ipinfo['asn'] = asn_list

    # IP->ipblock
    if 'ipblock' in ipinfo:
        ipblock_rec =  (mongo.db.ipblock.find_one({'_id': ipinfo['ipblock']}))
        if ipblock_rec is None:
            print("ERROR: Can't find IP block '{}' in database (trying to enrich IP {})".format(ipinfo['ipblock'],
                                                                                                ipinfo['_id']))
        else:
            # ipblock->org
            if "org" in ipblock_rec:
                org_rec = clean_secret_data(mongo.db.org.find_one({'_id': ipblock_rec['org']}))
                if org_rec is None:
                    print("ERROR: Can't find Org '{}' in database (trying to enrich IP {}, ipblock '{}')".format(
                        ipblock_rec['org'], ipinfo['_id'], ipblock_rec['_id']))
                else:
                    conv_dates(org_rec)
                    ipblock_rec['org'] = org_rec

            conv_dates(ipblock_rec)
            ipinfo['ipblock'] = ipblock_rec

def conv_dates(rec):
    """Convert datetimes in a record to YYYY-MM-DDTMM:HH:SS string"""
    for key in ('ts_added', 'ts_last_update'):
        if key in rec and isinstance(rec[key], datetime):
            rec[key] = rec[key].strftime("%Y-%m-%dT%H:%M:%S")

class SingleIPForm(FlaskForm):
    ip = StringField('IP address', [validator_optional, validators.IPAddress(message="Invalid IPv4 address")], filters=[strip_whitespace])

def get_ip_info(ipaddr, full):
    data = {
        'err_n': 400,
        'error': "No IP address specified",
        'ip': ipaddr
    }

    if not ipaddr:
        log_err.log('400_bad_request')
        return False, Response(json.dumps(data), 400, mimetype='application/json')

    form = SingleIPForm(ip=ipaddr)
    if not form.validate():
        log_err.log('400_bad_request')
        data['error'] = "Bad IP address"
        return False, Response(json.dumps(data), 400, mimetype='application/json')

    ipint = ipstr2int(form.ip.data)  # Convert string IP to int

    if full:
        ipinfo = mongo.db.ip.find_one({'_id': ipint})
    else:
        ipinfo = mongo.db.ip.find_one({'_id': ipint},
                                      {'rep': 1, 'fmp': 1, 'hostname': 1, 'bgppref': 1, 'ipblock': 1, 'geo': 1, 'bl': 1,
                                       'tags': 1})
    if not ipinfo:
        log_err.log('404_api_ip_not_found')
        data['err_n'] = 404
        data['error'] = "IP address not found"
        return False, Response(json.dumps(data), 404, mimetype='application/json')

    ipinfo['_id'] = int2ipstr(ipinfo['_id'])  # Convert int IP to string

    attach_whois_data(ipinfo, full)
    return True, ipinfo

# ***** NERD API BasicInfo - helper funcs *****
def get_basic_info_dic(val):
    geo_d = {}
    if 'geo' in val.keys():
        geo_d['ctry'] = val['geo'].get('ctry', "unknown")

    bl_l = []
    for l in val.get('bl', []):
        bl_l.append(l['n'])  # TODO: shouldn't there be a check for v=1?

    tags_l = []
    for l in val.get('tags', []):
        d = {
            'n': l,
            'c': val['tags'][l]['confidence']
        }

        tags_l.append(d)

    data = {
        'ip': val['_id'],
        'rep': val.get('rep', 0.0),
        'fmp': val.get('fmp', {'general': 0.0}),
        'hostname': (val.get('hostname', '') or '')[::-1],
        'ipblock': val.get('ipblock', ''),
        'bgppref': val.get('bgppref', ''),
        'asn': val.get('asn', []),
        'geo': geo_d,
        'bl': bl_l,
        'tags': tags_l
    }

    return data


def get_basic_info_dic_short(val):
    # only 'rep' and 'tags' fields
    tags_l = []
    for l in val.get('tags', []):
        d = {
            'n': l,
            'c': val['tags'][l]['confidence']
        }
        tags_l.append(d)

    data = {
        'ip': val['_id'],
        'rep': val.get('rep', 0.0),
        'tags': tags_l
    }
    return data

def get_basic_info_dic_v2(val):
    geo_d = {}
    if 'geo' in val.keys():
        geo_d['ctry'] = val['geo'].get('ctry', "unknown")

    bl_l = []
    for l in val.get('bl', []):
        bl_l.append(l['n']) # TODO: shouldn't there be a check for v=1?

    tags_l = []
    for l in val.get('tags', []):
        d = {
            'n' : l,
            'c' : val['tags'][l]['confidence']
        }

        tags_l.append(d)

    data = {
        'ip' : val['_id'],
        'rep' : val.get('rep', 0.0),
        'fmp' : val.get('fmp', {'general': 0.0}),
        'hostname' : (val.get('hostname', '') or '')[::-1],
        'ipblock' : val.get('ipblock', ''),
        'bgppref' : val.get('bgppref', ''),
        'asn' : val.get('asn',[]),
        'geo' : geo_d,
        'bl'  : bl_l,
        'tags'  : tags_l,
        'ts_last_update'  : val.get('ts_last_update', ''),
        'ts_added'  : val.get('ts_added', ''),
    }

    return data


def find_ip_data(query, skip_n, limit):
    return mongo.db.ip.find(query).skip(skip_n).limit(limit)

def ip_to_warden_data(ipaddr):
    ipint = ipstr2int(ipaddr)
    ipinfo = mongo.db.ip.aggregate(pipeline = [
    { '$match': { '_id': ipint } }, 
    { '$unwind': '$events' },
    { '$group': {
        '_id': {
            'date': '$events.date',
            'cat': '$events.cat'
        },
        'n_sum': { '$sum': '$events.n' },
        'conns_sum': { '$sum': '$events.conns' },
        }
    },
    { '$group': {
        '_id': '$_id.date',
        'categories': {
            "$push": {
                "k": "$_id.cat",
                "v": {
                    "n_sum": "$n_sum",
                    "conns_sum": "$conns_sum",
                    "nodes": "$nodes"
                }
            }
        }
        }
    },
    { '$project': {
        '_id': 0,
        'date': '$_id',
        "categories": {"$arrayToObject": "$categories"}
        }
    },
    { '$sort': { 'date': 1 } }
    ])

    ipinfo_list = [doc for doc in ipinfo]
    #ipinfo_list['_id'] = int2ipstr(ipinfo_list['_id'])
    return ipinfo_list


def create_query_v2(data):
    # Prepare 'find' part of the query
    queries = []
    if data is None: 
        return None
    
    if "subnet" in data and data["subnet"] is not None and len(data["subnet"]) != 0:
        subqueries = []
        for subnet in data["subnet"]:
            subnet = ipaddress.IPv4Network(subnet, strict=False)
            subnet_start = int(subnet.network_address) # IP addresses are stored as int
            subnet_end = int(subnet.broadcast_address)
            subqueries.append( {'$and': [{'_id': {'$gte': subnet_start}}, {'_id': {'$lte': subnet_end}}]} )
        queries.append({'$or': subqueries})

    if "hostname" in data and data["hostname"] is not None and len(data["hostname"]) != 0:
        subqueries = []
        for hostname in data["hostname"]:
            hn = hostname[::-1] # Hostnames are stored reversed in DB to allow search by suffix as a range search
            hn_end = hn[:-1] + chr(ord(hn[-1])+1)
            subqueries.append( {'$and': [{'hostname': {'$gte': hn}}, {'hostname': {'$lt': hn_end}}]} )
        queries.append({'$or': subqueries})

    if "country" in data and data["country"] is not None and len(data["country"]) != 0:
        queries.append( { '$or': [{'geo.ctry': c.upper() } for c in data["country"]]} )

    if "asn" in data and data["asn"] is not None and len(data["asn"]) != 0 :
        subqueries = []
        for asn in data["asn"]:
            # ASN is not stored in IP records - get list of BGP prefixes of the ASN and filter by these
            asn = int(asn.lstrip("ASas"))
            asrec = mongo.db.asn.find_one({'_id': asn})
            if asrec and 'bgppref' in asrec:
                subqueries.append( {'bgppref': {'$in': asrec['bgppref']}} )
            else:
                subqueries.append( {'_id': {'$exists': False}} ) # ASN not in DB, add query which is always false to get no results
        op = '$and' if (data["asn_op"] == "AND") else '$or'
        queries.append({op: subqueries})

    if "source" in data and data["source"] is not None and len(data["source"]) != 0:
        op = '$and' if (data["source_op"] == "AND") else '$or'
        queries.append( {op: [{'_ttl.' + s.lower(): {'$exists': True}} for s in data["source"]]} )

    if "cat" in data and data["cat"] is not None and len(data["cat"]) != 0:
        op = '$and' if (data["cat_op"] == "AND") else '$or'
        queries.append( {op: [{'events.cat': cat} for cat in data["cat"]]} )

    if "node" in data and data["node"] is not None and len(data["node"]) != 0:
        op = '$and' if (data["node_op"] == "AND") else '$or'
        queries.append( {op: [{'events.node': node} for node in data["node"]]} )

    if "blacklist" in data and data["blacklist"] is not None and len(data["blacklist"]) != 0:
        op = '$and' if (data["bl_op"] == "AND") else '$or'
        array = [{('dbl' if t == 'd' else 'bl'): {'$elemMatch': {'n': id, 'v': 1}}} for t,_,id in map(lambda s: s.partition(':'), data["blacklist"])]
        queries.append( {op: array} )

    if "tag" in data and data["tag"] is not None and len(data["tag"]) != 0:
        op = '$and' if (data["tag_op"] == "AND") else '$or'
        queries.append( {op: [{'tags.'+ tag_id: {'$exists': True}} for tag_id in data["tag"]]} )

    if "whitelisted" in data and data["whitelisted"]:
        queries.append( {'tags.whitelist': {'$exists': False}} )

    query = {'$and': queries} if queries else None
    return query