#!/usr/bin/env python
import sys
import random
import json
import time
import os
import re
import pytz

from flask import Flask, request, render_template, make_response, g, jsonify, json
from flask.ext.pymongo import PyMongo, ASCENDING, DESCENDING
from flask_wtf import Form
from wtforms import validators, TextField, IntegerField, BooleanField, SelectField

#import db
import ctrydata

# TODO put this into some config file
if os.name == 'posix':
    WARDEN_DROP_PATH = "/data/warden_filer/warden_receiver/incoming"
    EVENTDB_PATH = "/data/eventdb"
    sys.path.insert(0,'/home/current/washek/NERDd/core')
    import eventdb
else:
    WARDEN_DROP_PATH = "f:/CESNET/RepShield/NERD/NERDd/warden_filer/incoming"
    EVENTDB_PATH = "f:/CESNET/RepShield/NERD/NERDd/eventdb"
    sys.path.insert(0,'f:/CESNET/RepShield/NERD/NERDd/core')
    import eventdb


app = Flask(__name__)

# Configuration (variables prefixed with MONGO_ are automatically used by PyMongo)
app.config['MONGO_HOST'] = 'localhost'
app.config['MONGO_PORT'] = 27017
app.config['MONGO_DBNAME'] = 'nerd'

app.secret_key = '\xc3\x05pt[Tn\xe3\xed\x97\xe4l\xf3\x1fB\xe2 Nz\xacc\xca\xad\x06'

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

mongo = PyMongo(app)

event_db = eventdb.FileEventDatabase({'eventdb_path': EVENTDB_PATH})

# ***** Jinja2 filters *****

# Datetime filters
def format_datetime(val, format="%Y-%m-%d %H:%M:%S"):
    return val.strftime(format)

app.jinja_env.filters['datetime'] = format_datetime

# ***** Main page *****
@app.route('/')
def main():
    return ""
    
# ***** List of IP addresses *****

class IPFilterForm(Form):
    subnet = TextField('IP prefix', [validators.Optional()])
    country = TextField('Country code', [validators.Optional(), validators.length(2, 2)])
    asn = TextField('ASN', [validators.Optional(),
        validators.Regexp('^((AS)?\d+|\?)+$', re.IGNORECASE,
        message='Must be a number, optionally preceded by "AS", or "?".')])
    sortby = SelectField('Sort by', choices=[
                ('events','Events'),
                ('ts_update','Last update'),
                ('ts_added','Time added'),
                ('ip','IP address'),
             ], default='events')
    asc = BooleanField('Ascending', default=False)
    limit = IntegerField('Max number of addresses', [validators.NumberRange(1, 1000)], default=20)

sort_mapping = {
    'events': 'events.total',
    'ts_update': 'ts_last_update',
    'ts_added': 'ts_added',
    'ip': '_id',
}

def create_query(form):
    # Prepare 'find' part of the query
    queries = []
    if form.subnet.data:
        subnet = form.subnet.data
        subnet_end = subnet[:-1] + chr(ord(subnet[-1])+1)
        queries.append( {'$and': [{'_id': {'$gte': subnet}}, {'_id': {'$lt': subnet_end}}]} )
    if form.country.data:
        queries.append( {'geo.ctry': form.country.data.upper() } )
    if form.asn.data:
        if form.asn.data[0] == '?':
            queries.append( {'$and': [{'as_maxmind.num': {'$exists': True}},
                                      {'as_rw.num': {'$exists': True}},
                                      {'$where': 'this.as_maxmind.num != this.as_rw.num'} # This will be probably very slow
                                     ]} )
        else:
            asn = int(form.asn.data.lstrip("ASas"))
            queries.append( {'$or': [{'as_maxmind.num': asn}, {'as_rw.num': asn}]} )
    
    query = {'$and': queries} if queries else None
    return query

@app.route('/ips')
@app.route('/ips/')
def ips():
    title = "IP search"
    form = IPFilterForm(request.args, csrf_enabled=False)
    if form.validate():
        timezone = pytz.timezone('Europe/Prague') # TODO autodetect (probably better in javascript)
        sortby = sort_mapping[form.sortby.data]
        
        query = create_query(form)
        
        # Query parameters to be used in AJAX requests
        query_params = json.dumps(form.data)
        
        # Perform DB query
        #print("Query: "+str(query))
        results = mongo.db.ip.find(query).limit(form.limit.data).sort(sortby, 1 if form.asc.data else -1)
        results = list(results) # Load all data now, so we are able to get number of results in template
        
        # Add metainfo about evetns for easier creation of event table in the template
        date_regex = re.compile('^[0-9]{4}-[0-9]{2}-[0-9]{2}$')
        for ip in results:
            events = ip.get('events', {})
            dates = set()
            cats = set()
            nodes = set()
            for key,val in events.items():
                if date_regex.match(key):
                    dates.add(key)
                    for cat,val in val.items():
                        if cat == 'nodes':
                            nodes.update(val)
                        else:
                            cats.add(cat)
            dates = sorted(dates)
            cats = sorted(cats)
            nodes = sorted(nodes)
            date_cat_table = [ [ events.get(d, {}).get(c, 0) for c in cats ] for d in dates ]
            
            MAX_DAYS = 5
            if len(dates) > MAX_DAYS:
                dates = dates[-MAX_DAYS:]
                dates.insert(0, '...')
                date_cat_table = date_cat_table[-MAX_DAYS:]
                date_cat_table.insert(0, ['...' for c in cats])
            
            events['_dates'] = ','.join(dates)
            events['_cats'] = ','.join(cats)
            events['_nodes'] = ','.join(nodes)
            events['_date_cat_table'] = ';'.join( [','.join(map(str,c)) for c in date_cat_table] )
    else:
        results = None

    return render_template('ips.html', ctrydata=ctrydata, **locals())

@app.route('/_ips_count', methods=['GET', 'POST'])
def ips_count():
    form = IPFilterForm(request.values, csrf_enabled=False)
    print("Count requested")
    print(form.data)
    if form.validate():
        query = create_query(form)
        return make_response(str(mongo.db.ip.find(query).count()))
    else:
        return make_response("ERROR")


# ***** List of alerts *****

# class AlertFilterForm(Form):
#     limit = IntegerField('Max number of results', [])
# 
# @app.route('/events')
# def events():
#     title = "Events"
#     limit = get_int_arg('limit', 10, min=1, max=1000)
#     skip = get_int_arg('skip', 0, min=0)
#     num_alerts = mongo.db.alerts.count()
#     num_ips = mongo.db.ips.count()
#     alerts = mongo.db.alerts.find().sort("$natural", DESCENDING).skip(skip).limit(limit)
#     form = AlertFilterForm(limit=limit)
#     return render_template('events.html', **locals())


# ***** Detailed info about individual IP *****

class SingleIPForm(Form):
    ip = TextField('IP address', [validators.IPAddress(message="Invalid IPv4 address")])


@app.route('/ip/')
@app.route('/ip/<ipaddr>')
def ip(ipaddr=None):
    form = SingleIPForm(ip=ipaddr)
    #if form.validate():
    if ipaddr:
        title = ipaddr
        ipinfo = mongo.db.ip.find_one({'_id':form.ip.data})
        events = event_db.get('ip', form.ip.data, limit=100)
        num_events = str(len(events))
        if len(events) >= 100:
            num_events = "&ge;100, only first 100 shown"
    else:
        title = 'IP detail search'
        ipinfo = {}
    return render_template('ip.html', ctrydata=ctrydata, ip=form.ip.data, **locals())


# ***** NERD status information *****

@app.route('/status')
def get_status():
    ips = mongo.db.ip.count()
    idea_queue_len = len(os.listdir(WARDEN_DROP_PATH))
    return jsonify(
        ips=ips,
        idea_queue=idea_queue_len
    )


# **********

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

