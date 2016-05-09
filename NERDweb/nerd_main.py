#!/usr/bin/env python
import random
import json

from flask import Flask, request, render_template, g
from flask.ext.pymongo import PyMongo, ASCENDING, DESCENDING
from flask_wtf import Form
from wtforms import validators, StringField, IntegerField, BooleanField

import db
import ctrydata


app = Flask(__name__)

# Configuration (variables prefixed with MONGO_ are automatically used by PyMongo)
app.config['MONGO_HOST'] = 'localhost'
app.config['MONGO_PORT'] = 27017
app.config['MONGO_DBNAME'] = 'nerd'

app.secret_key = '\xc3\x05pt[Tn\xe3\xed\x97\xe4l\xf3\x1fB\xe2 Nz\xacc\xca\xad\x06'

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

mongo = PyMongo(app)

def get_int_arg(argname, default=None, min=None, max=None):
    """Get argument from request and convert it to int. If argument is not 
    present or it can't be converted to int, return default.
    If min or max is specified and value is lower/greater than min/max, return
    value of min/max instead."""
    try:
        val = int(request.args.get(argname, default))
        if min is not None and val < min:
            return min
        elif max is not None and val > max:
            return max
        return val
    except ValueError:
        return default


# ***** Main page *****
@app.route('/')
def main():
    return ""
    
# ***** List of IP addresses *****

class IPFilterForm(Form):
    limit = IntegerField('Max number of addresses', [])

@app.route('/ips')
@app.route('/ips/')
def ips():
    limit = get_int_arg('limit', 20, min=1, max=1000)
    form = IPFilterForm(limit=limit)
    ipinfo = [db.getIPInfo('.'.join(str(random.randint(0,255)) for _ in range(4))) for _ in range(limit)]
    return render_template('ips.html', ctrydata=ctrydata, **locals())


# ***** List of alerts *****

class AlertFilterForm(Form):
    limit = IntegerField('Max number of results', [])

@app.route('/events')
def events():
    limit = get_int_arg('limit', 10, min=1, max=1000)
    skip = get_int_arg('skip', 0, min=0)
    num_alerts = mongo.db.alerts.count()
    num_ips = mongo.db.ips.count()
    alerts = mongo.db.alerts.find().sort("$natural", DESCENDING).skip(skip).limit(limit)
    form = AlertFilterForm(limit=limit)
    return render_template('events.html', **locals())


# ***** Detailed info about individual IP *****

@app.route('/ip/')
@app.route('/ip/<ipaddr>')
def ip(ipaddr=None):
    return render_template('ip.html', ipaddr=ipaddr)


# **********

if __name__ == "__main__":
    app.run(debug=True)

