#!/usr/bin/env python
import random
import json
import time
import os
import pytz

from flask import Flask, request, render_template, g, jsonify
from flask.ext.pymongo import PyMongo, ASCENDING, DESCENDING
from flask_wtf import Form
from wtforms import validators, TextField, IntegerField, BooleanField, SelectField

#import db
import ctrydata

#WARDEN_DROP_PATH = "/data/warden_filer/warden_receiver/incoming"
WARDEN_DROP_PATH = "f:/CESNET/RepShield/NERD/NERDd/warden_filer/incoming"

app = Flask(__name__)

# Configuration (variables prefixed with MONGO_ are automatically used by PyMongo)
app.config['MONGO_HOST'] = 'localhost'
app.config['MONGO_PORT'] = 27017
app.config['MONGO_DBNAME'] = 'nerd'

app.secret_key = '\xc3\x05pt[Tn\xe3\xed\x97\xe4l\xf3\x1fB\xe2 Nz\xacc\xca\xad\x06'

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

mongo = PyMongo(app)


# ***** Main page *****
@app.route('/')
def main():
    return ""
    
# ***** List of IP addresses *****

class IPFilterForm(Form):
    subnet = TextField('IP prefix', [validators.Optional()])
    country = TextField('Country code', [validators.Optional(), validators.length(2, 2)])
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

@app.route('/ips')
@app.route('/ips/')
def ips():
    title = "IP search"
    form = IPFilterForm(request.args, csrf_enabled=False)
    if form.validate():
        print("Validation OK")
        print(form.asc.data)
        timezone = pytz.timezone('Europe/Prague') # TODO autodetect (probably better in javascript)
        sortby = sort_mapping[form.sortby.data]
        # Prepare 'find' part of the query
        queries = []
        if form.subnet.data:
            subnet = form.subnet.data
            subnet_end = subnet[:-1] + chr(ord(subnet[-1])+1)
            queries.append( {'$and': [{'_id': {'$gte': subnet}}, {'_id': {'$lt': subnet_end}}]} )
        if form.country.data:
            queries.append( {'geo.ctry': form.country.data.upper() } )
        query = {'$and': queries} if queries else None
        # Perform DB query
        print("Query: "+str(query))
        ipinfo = mongo.db.ip.find(query).limit(form.limit.data).sort(sortby, 1 if form.asc.data else -1)
    else:
        ipinfo = None
    return render_template('ips.html', ctrydata=ctrydata, sorted=sorted, **locals())


# ***** List of alerts *****

class AlertFilterForm(Form):
    limit = IntegerField('Max number of results', [])

@app.route('/events')
def events():
    title = "Events"
    limit = get_int_arg('limit', 10, min=1, max=1000)
    skip = get_int_arg('skip', 0, min=0)
    num_alerts = mongo.db.alerts.count()
    num_ips = mongo.db.ips.count()
    alerts = mongo.db.alerts.find().sort("$natural", DESCENDING).skip(skip).limit(limit)
    form = AlertFilterForm(limit=limit)
    return render_template('events.html', **locals())


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
    else:
        title = 'IP detail search'
        ipinfo = {}
    return render_template('ip.html', ctrydata=ctrydata, sorted=sorted, ip=form.ip.data, **locals())


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
    app.run(debug=True)

