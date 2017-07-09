#!/usr/bin/env python
from __future__ import print_function
import sys
import random
import json
import time
from datetime import datetime, timedelta
import os
import subprocess
import re
import pytz

from flask import Flask, request, render_template, make_response, g, jsonify, json, flash, redirect, session, Response
from flask_pymongo import pymongo, PyMongo, ASCENDING, DESCENDING
from flask_wtf import Form
from flask_mail import Mail, Message
from wtforms import validators, TextField, FloatField, IntegerField, BooleanField, HiddenField, SelectField, SelectMultipleField, PasswordField

# Add to path the "one directory above the current file location"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
import common.eventdb_psql
import common.config

#import db
import ctrydata
import userdb
from userdb import get_user_info, authenticate_with_token

# ***** Load configuration *****

DEFAULT_CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../etc/nerdweb.cfg"))

# TODO parse arguments using ArgParse
if len(sys.argv) >= 2:
    cfg_file = sys.argv[1]
else:
    cfg_file = DEFAULT_CONFIG_FILE
cfg_dir = os.path.dirname(os.path.abspath(cfg_file))

# Read web-specific config (nerdweb.cfg)
config = common.config.read_config(cfg_file)
# Read common config (nerd.cfg) and combine them together
common_cfg_file = os.path.join(cfg_dir, config.get('common_config'))
config.update(common.config.read_config(common_cfg_file))
# Read tags config and combine it with previous config
tags_cfg_file = os.path.join(cfg_dir, config.get('tags_config'))
config.update(common.config.read_config(tags_cfg_file))

BASE_URL = config.get('base_url', '')

WARDEN_DROP_PATH = os.path.join(config.get("warden_filer_path", "/data/warden_filer/warden_receiver"), "incoming")

config.testing = False

userdb.init(config, cfg_dir)

# **** Create and initialize Flask application *****

app = Flask(__name__)

app.secret_key = config.get('secret_key')

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Configuration of PyMongo
app.config['MONGO_HOST'] = config.get('mongodb.host', 'localhost')
app.config['MONGO_PORT'] = config.get('mongodb.port', 27017)
app.config['MONGO_DBNAME'] = config.get('mongodb.dbname', 'nerd')

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


eventdb = common.eventdb_psql.PSQLEventDatabase(config)


# ***** Jinja2 filters *****

# Datetime filters
def format_datetime(val, format="%Y-%m-%d %H:%M:%S"):
    return val.strftime(format)

app.jinja_env.filters['datetime'] = format_datetime

    

# ***** Login handlers *****
# A handler function is created for each configured login method
# (config.login.<method>) with URL path set to config.login.<method>.loc.
# 
# Each of these paths should have a login mechanism configured in web server.
# (e.g. HTTP basic authentication or Shibboleth).
# The handler expect a valid user information in environent variables set by 
# the server.
# The user info (id and optionally name and email) is taken from environment 
# variables specified in config.login.<method>.{id_field,user_field,email_field}. 

def create_login_handler(method_id, id_field, name_field, email_field, return_path):
    def login_handler():
        # DEBUG: print whole environ to see what fields IdP has provided
        if method_id == 'shibboleth':
            print("Shibboleth login, metadata provided: "+str(request.environ))
        
        # Check presence of the only mandatory field (id)
        if id_field not in request.environ:
            flash("ERROR: Login failed - '"+id_field+"' not defined (either your IdP is not providing this field or there is a problem with server configuration).", "error")
            return redirect(return_path)
        session['user'] = {
            'login_type': method_id,
            'id': request.environ[id_field].decode('utf-8'),
        }
        # Name may be present in various fields, try all specified in the config and use the first present
        for field in (name_field if isinstance(name_field, list) else ([name_field] if name_field else [])):
            # Name may be a combination of more fields, specified using "+" symbol (e.g. )
            if "+" in field and all(f in request.environ for f in field.split('+')):
                session['user']['name'] = " ".join(map(lambda f: request.environ[f].decode('utf-8'), field.split('+')))
                break
            elif field in request.environ:
                session['user']['name'] = request.environ[field].decode('utf-8')
                break
        # Email
        if email_field and email_field in request.environ:
            session['user']['email'] = request.environ[email_field]
        flash("Login successful", "success")
        return redirect(return_path)
    return login_handler

# Register the login handlers
for method_id, method_cfg in config.get('login.methods', {}).items():
    app.add_url_rule(
        method_cfg['loc'],
        'login_'+method_id,
        create_login_handler(method_id,
                             method_cfg.get('id_field', 'REMOTE_USER'),
                             method_cfg.get('name_field', None),
                             method_cfg.get('email_field', None),
                             config['login']['return-path']
        )
    )


@app.route('/logout')
def logout():
    redir_path = config['login']['return-path']
    if 'user' in session:
        # If there is logout-path defined for the login_type, redirect to this instead of the default
        login_type = session['user']['login_type']
        if 'logout_path' in config['login']['methods'][login_type]:
            redir_path = config['login']['methods'][login_type]['logout_path']
        # Cancel local NERD session
        del session['user']
        flash("You have been logged out", "info")
    return redirect(redir_path)


# ***** Functions called for each request *****

# TODO: use g.user and g.ac everywhere
@app.before_request
def store_user_info():
    """Store user info to 'g' (request-wide global variable)"""
    g.user, g.ac = get_user_info(session)

@app.after_request
def add_user_header(resp):
    # Set user ID to a special header, it's used to put user ID to Apache logs
    if g.user:
        resp.headers['X-UserID'] = g.user['fullid']
    return resp


# ***** Main page *****
# TODO: rewrite as before_request (to check for this situation at any URL)
@app.route('/')
def main():
    user, ac = get_user_info(session)
    
    # User is authenticated but has no account
    if user and ac('notregistered'):
        return redirect(BASE_URL+'/noaccount')
    
    return redirect(BASE_URL+'/ips/')


# ***** Request for new account *****
class AccountRequestForm(Form):
    email = TextField('Contact email', [validators.Required()], description='Used to send information about your request and in case admins need to contact you.')

@app.route('/noaccount', methods=['GET','POST'])
def noaccount():
    user, ac = get_user_info(session)
    if not user:
        return make_response("ERROR: no user is authenticated")
    if not ac('notregistered'):
        return redirect(BASE_URL+'/ips/')
    if user['login_type'] != 'shibboleth':
        return make_response("ERROR: You've successfully authenticated to web server but there is no matching user account. This is probably a configuration error. Contact NERD administrator.")
    
    form = AccountRequestForm(request.values)
    # Prefill user's default email from his/her account info (we expect a list of emails separated by ';')
    if not form.email.data and 'email' in user:
        form.email.data = user['email'].split(';')[0]
    
    request_sent = False
    if form.validate():
        # TODO check presence of config login.request-email
        # if not config.get()
        # Send email
        name = user.get('name', '[name not available]').encode('ascii', 'replace')
        id = user['id']
        email = form.email.data.decode('utf-8')
        msg = Message(subject="[NERD] New account request from {} ({})".format(name,id),
                      #recipients=[email],
                      recipients=[config.get('login.request-email')],
                      reply_to=email,
                      body="A user with the following ID has requested creation of a new account in NERD.\n\nid: {}\nname: {}\nemails: {}\nselected email: {}".format(id,name,user.get('email',''),email),
                     )
        mailer.send(msg)
        request_sent = True
        
    return render_template('noaccount.html', config=config, **locals())


# ***** Account info & password change *****

class PasswordChangeForm(Form):
    old_passwd = PasswordField('Old password', [validators.InputRequired()])
    new_passwd = PasswordField('New password', [validators.InputRequired(), validators.length(8, -1, 'Password must have at least 8 characters')])
    new_passwd2 = PasswordField('Repeat password', [validators.InputRequired(), validators.EqualTo('new_passwd', message='Passwords must match')])


@app.route('/account')
@app.route('/account/set_password', endpoint='set_password', methods=['POST'])
def account_info():
    user, ac = get_user_info(session)
    if not user:
        return make_response("ERROR: no user is authenticated")
    if user and ac('notregistered'):
        return redirect(BASE_URL+'/noaccount')
    
    # Handler for /account/set_password
    if request.endpoint == 'set_password':
        if user['login_type'] != 'local':
            return make_response("ERROR: Password can be changed for local accounts only")
        passwd_form = PasswordChangeForm(request.form)
        if passwd_form.validate():
            htpasswd_file = os.path.join(cfg_dir, config.get('login.methods.local.htpasswd_file', '.htpasswd'))
            try:
                # Verify old password
                cmd = ['htpasswd', '-v', '-i', htpasswd_file, user['id']]
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)#, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p.communicate(passwd_form.old_passwd.data.encode('utf-8'))
                if p.returncode != 0:
                    if p.returncode == 3: # Bad password
                        flash('ERROR: Bad password', 'error')
                        return render_template('account_info.html', config=config, **locals())
                    else:
                        print("ERROR: htpasswd check error '{}': retcode: {}".format(' '.join(cmd), p.returncode), file=sys.stderr)
                        return make_response('ERROR: Cannot change password: error '+str(p.returncode),  'error')
                
                # Set new password
                # (-i: read password from stdin, -B: use bcrypt, -C: bcrypt cost factor (12 should be quite secure and takes approx. 0.3s on my server)
                cmd = ['htpasswd', '-i', '-B', '-C', '12', htpasswd_file, user['id']]
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)#, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p.communicate(passwd_form.new_passwd.data.encode('utf-8'))
                if p.returncode != 0:
                    print("ERROR: htpasswd set error '{}': retcode: {}".format(' '.join(cmd), p.returncode), file=sys.stderr)
                    return make_response('ERROR: Cannot change password: error '+str(p.returncode),  'error')
            except OSError as e:
                p.kill()
                print("ERROR: htpasswd OSError '{}': {}".format(' '.join(cmd), str(e)), file=sys.stderr)
                return make_response('ERROR: Cannot change password: OSError.', 'error')
            
            # If we got there, passward was successfully changed
            flash('Password changed. Please, <b><a href="'+BASE_URL+'/logout">log out</a></b> and then log back in using the new password.', 'safe success')
            return redirect(BASE_URL+'/account')
        else:
            flash('ERROR: Password not changed.', 'error')

    # Handler for /account
    else:
        if user['login_type'] == 'local':
            passwd_form = PasswordChangeForm()
    
    return render_template('account_info.html', config=config, **locals())


# def set_password():
#     form = PasswordChangeForm(request.form)
#     if form.validate():
#         
#     return redirect(BASE_URL+'/account')


# ***** List of IP addresses *****

def get_blacklists():
    # Get the list of all configured blacklists
    # DNSBL
    blacklists = [bl_name for bl_group in config.get('dnsbl.blacklists', []) for bl_name in bl_group[2].values()]
    # Locally downloaded blacklists
    blacklists += [bl[0] for bl in config.get('local_bl.lists', [])]
    blacklists.sort()
    return blacklists

def get_tags():
    tags = [ (tag_id, tag_param.get('name', tag_id)) for tag_id, tag_param in config.get('tags', {}).items()]
    tags.sort()    
    return tags

class IPFilterForm(Form):
    subnet = TextField('IP prefix', [validators.Optional()])
    hostname = TextField('Hostname suffix', [validators.Optional()])
    country = TextField('Country code', [validators.Optional(), validators.length(2, 2)])
    asn = TextField('ASN', [validators.Optional(),
        validators.Regexp('^((AS)?\d+|\?)+$', re.IGNORECASE,
        message='Must be a number, optionally preceded by "AS", or "?".')])
    blacklist = SelectMultipleField('Blacklist', [validators.Optional()],
        choices=[(bl,bl) for bl in get_blacklists()])
    bl_op = HiddenField('', default="or")
    tag_op = HiddenField('', default="or")
    tag = SelectMultipleField('Tag', [validators.Optional()],
        choices = get_tags()
        )
    tag_conf = FloatField('Min tag confidence', [validators.Optional(), validators.NumberRange(0, 1, 'Must be a number between 0 and 1')], default=0.5)
    sortby = SelectField('Sort by', choices=[
                ('none',"--"),
                ('rep','Reputation score'),
                ('events','Events'),
                ('ts_last_event','Time of last event'),
                ('ts_added','Time added'),
                ('ip','IP address'),
             ], default='rep')
    asc = BooleanField('Ascending', default=False)
    limit = IntegerField('Max number of addresses', [validators.NumberRange(1, 1000)], default=20)

sort_mapping = {
    'none': 'none',
    'rep': 'rep',
    'events': 'events.total',
    'ts_last_event': 'ts_last_event',
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
    if form.hostname.data:
        hn = form.hostname.data[::-1] # Hostnames are stored reversed in DB to allow search by suffix as a range search
        hn_end = hn[:-1] + chr(ord(hn[-1])+1)
        queries.append( {'$and': [{'hostname': {'$gte': hn}}, {'hostname': {'$lt': hn_end}}]} )
    if form.country.data:
        queries.append( {'geo.ctry': form.country.data.upper() } )
    if form.asn.data:
        if form.asn.data[0] == '?':
            queries.append( {'$and': [{'as_maxmind.num': {'$exists': True}},
                                      {'as_rv.num': {'$exists': True}},
                                      {'$where': 'this.as_maxmind.num != this.as_rv.num'} # This will be probably very slow
                                     ]} )
        else:
            asn = int(form.asn.data.lstrip("ASas"))
            queries.append( {'$or': [{'as_maxmind.num': asn}, {'as_rv.num': asn}]} )
    if form.blacklist.data:
        op = '$and' if (form.bl_op.data == "and") else '$or'
        queries.append( {op: [{'bl': {'$elemMatch': {'n': blname, 'v': 1}}} for blname in form.blacklist.data]} )
    if form.tag.data:
        op = '$and' if (form.tag_op.data == "and") else '$or'
        confidence = form.tag_conf.data if form.tag_conf.data else 0
        queries.append( {op: [{'$and': [{'tags.'+ tag_id: {'$exists': True}}, {'tags.'+ tag_id +'.confidence': {'$gte': confidence}}]} for tag_id in form.tag.data]} )
         
    query = {'$and': queries} if queries else None
    return query

@app.route('/ips')
@app.route('/ips/')
def ips():
    title = "IP search"
    user, ac = get_user_info(session)

    form = IPFilterForm(request.args, csrf_enabled=False)

    if ac('ipsearch') and form.validate():
        timezone = pytz.timezone('Europe/Prague') # TODO autodetect (probably better in javascript)
        sortby = sort_mapping[form.sortby.data]
        
        query = create_query(form)
        # Query parameters to be used in AJAX requests
        query_params = json.dumps(form.data)
        
        # Perform DB query
        #print("Query: "+str(query))
        try:
            results = mongo.db.ip.find(query).limit(form.limit.data)
            if sortby != "none":
                results.sort(sortby, 1 if form.asc.data else -1)
            results = list(results) # Load all data now, so we are able to get number of results in template
        except pymongo.errors.ServerSelectionTimeoutError:
            results = []
            error = 'mongo_error'
        
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
                        elif "Test" not in cat: # Ignore categories containing "Test"
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
            events['_n_cats'] = len(cats)
            events['_n_nodes'] = len(nodes)
            
#             # Experimental reputation computation
#             def nonlin(val, coef=0.5, max=20):
#                 if val > max:
#                     return 1.0
#                 else:
#                     return (1 - coef**val)
#             today = datetime.utcnow().date()
#             DATE_RANGE = 14
#             sum_weight = 0
#             rep = 0
#             for n in range(0,DATE_RANGE): # n - iterating dates from now back to history
#                 d = today - timedelta(days=n)
#                 dstr = d.strftime("%Y-%m-%d")
#                 # reputation at day 'd'
#                 if dstr in events:
#                     d_events = events[dstr]
#                     d_n_nodes = len(d_events['nodes'])
#                     d_n_events = sum(val for cat,val in d_events.items() if cat != 'nodes')
#                     daily_rep = nonlin(d_n_events) * nonlin(d_n_nodes)
#                     #print(ip['_id'], dstr, d_n_nodes, d_n_events, nonlin(d_n_events), nonlin(d_n_nodes), daily_rep)
#                 else:
#                     daily_rep = 0.0
#                 # total reputation as weighted avergae with linearly decreasing weight
#                 weight = float(DATE_RANGE - n) / DATE_RANGE
#                 sum_weight += weight
#                 rep += daily_rep * weight
#                 #print(daily_rep, weight, sum_weight, rep)
#             rep /= sum_weight
#             ip['rep_frontend'] = rep
    else:
        results = None
        if user and not ac('ipsearch'):
            flash('Only registered users may search IPs.', 'error')
    
    return render_template('ips.html', config=config, ctrydata=ctrydata, **locals())


@app.route('/_ips_count', methods=['POST'])
def ips_count():
    user, ac = get_user_info(session)
    #Excepts query as JSON encoded POST data.
    form_values = request.get_json()
    form = IPFilterForm(obj=form_values, csrf_enabled=False)
    if ac('ipsearch') and form.validate():
        query = create_query(form)
        print("query: " + str(query))
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
    user, ac = get_user_info(session)
    
    form = SingleIPForm(ip=ipaddr)
    #if form.validate():
    if ipaddr:
        if ac('ipsearch'):
            title = ipaddr
            ipinfo = mongo.db.ip.find_one({'_id':form.ip.data})
        else:
            flash('Only registered users may search IPs.', 'error')
    else:
        title = 'IP detail search'
        ipinfo = {}
    return render_template('ip.html', config=config, ctrydata=ctrydata, ip=form.ip.data, **locals())


@app.route('/ajax/ip_events/<ipaddr>')
def ajax_ip_events(ipaddr):
    """Return events related to given IP (as HTML snippet to be loaded via AJAX)"""
    user, ac = get_user_info(session)

    if not ipaddr:
        return make_response('ERROR')
    if not ac('ipsearch'):
        return make_response('ERROR: Insufficient permissions')

    events = eventdb.get('ip', ipaddr, limit=100)
    num_events = str(len(events))
    if len(events) >= 100:
        num_events = "&ge;100, only first 100 shown"
    return render_template('ip_events.html', config=config, **locals())



# ***** Detailed info about individual AS *****

class SingleASForm(Form):
    asn = TextField('AS number', [validators.Regexp('^(AS)?\d+$', re.IGNORECASE,
            message='Must be a number, optionally preceded by "AS".')])


@app.route('/as/')
@app.route('/as/<asn>')
def asn(asn=None): # Can't be named "as" since it's a Python keyword
    user, ac = get_user_info(session)
    
    form = SingleASForm(asn=asn, csrf_enabled=False)
    print(asn,form.data)
    title = 'ASN detail search'
    if asn is None:
        # No ASN passed
        asinfo = {}
    elif form.validate():
        # Passed correct ASN
        asn = int(asn.lstrip("ASas")) # strip AS at the beginning
        if ac('assearch'):
            title = 'AS'+str(asn)
            asinfo = mongo.db.asn.find_one({'_id':asn})
        else:
            flash('Only registered users may search ASNs.', 'error')
    else:
        # Wrong format of passed ASN
        asn = None
        asinfo = {}
    return render_template('as.html', config=config, ctrydata=ctrydata, **locals())



# ***** NERD status information *****

@app.route('/status')
def get_status():
    ips = mongo.db.ip.count()
    idea_queue_len = len(os.listdir(WARDEN_DROP_PATH))
    
    if "upd_cnt_file" in config:
        try:
            upd_cnt = open(config.get("upd_cnt_file")).read().split("\n")
            upd_processed = sum(map(int, upd_cnt[10:20]))
            upd_queue = int(upd_cnt[20])
        except Exception as e:
            upd_processed = "(error) " + str(e)
            upd_queue = 0
    else:
        upd_processed = "(N/A)"
        upd_queue = 0
    
    try:
        if "data_disk_path" in config:
            disk_usage = subprocess.check_output(["df", config.get("data_disk_path"), "-P"]).decode('ascii').splitlines()[1].split()[4]
        else:
            disk_usage = "(N/A)"
    except Exception as e:
        disk_usage = "(error) " + str(e);
    
    return jsonify(
        ips=ips,
        idea_queue=idea_queue_len,
        update_queue=upd_queue,
        updates_processed=upd_processed,
        disk_usage=disk_usage
    )


# ***** Plain-text list of IP addresses *****
# (gets the same parameters as /ips/)

@app.route('/iplist')
@app.route('/iplist/')
def iplist():
    user, ac = get_user_info(session)

    form = IPFilterForm(request.args, csrf_enabled=False)
    
    if not user or not ac('ipsearch'):
        return Response('ERROR: Unauthorized', 403, mimetype='text/plain')
    
    if not form.validate():
        return Response('ERROR: Bad parameters: ' + '; '.join('{}: {}'.format(name, ', '.join(errs)) for name, errs in form.errors.items()), 400, mimetype='text/plain')
    
    sortby = sort_mapping[form.sortby.data]
    
    query = create_query(form)
    
    # Perform DB query
    try:
        results = mongo.db.ip.find(query).limit(form.limit.data)
        if sortby != "none":
            results.sort(sortby, 1 if form.asc.data else -1)
        results = list(results) # Load all data now, so we are able to get number of results in template
    except pymongo.errors.ServerSelectionTimeoutError:
        return Response('ERROR: Database connection error', 503, mimetype='text/plain')
    
    return Response('\n'.join(res['_id'] for res in results), 200, mimetype='text/plain')

def validate_api_request(authorization):
    data = {
        'err_n' : 403,
        'error' : "Unauthorized",
    }

    auth = request.headers.get("Authorization")
    if not auth:
        return Response(json.dumps(data), 403, mimetype='application/json')

    vals = auth.split()
    user, ac = authenticate_with_token(vals[1])
    if vals[0] != "token" or not user or not ac('ipsearch'):
        return Response(json.dumps(data), 403, mimetype='application/json')

    return None

def get_ip_info(ipaddr):
    data = {
        'err_n' : 400,
        'error' : "No IP address specified",
        'ip' : ipaddr
    }

    if not ipaddr:
        return False, Response(json.dumps(data), 400, mimetype='application/json')

    form = SingleIPForm(ip=ipaddr, csrf_enabled=False)
    if not form.validate():
        data['error'] = "Bad IP address"
        return False, Response(json.dumps(data), 400, mimetype='application/json')

    ipinfo = mongo.db.ip.find_one({'_id':form.ip.data})
    if not ipinfo:
        data['err_n'] = 404
        data['error'] = "IP address not found"
        return False, Response(json.dumps(data), 404, mimetype='application/json')

    return True, ipinfo

# ***** NERD API BasicInfo *****
def get_basic_info_dic(val):
    asn_d = {}
    if 'as_maxmind' in val.keys():
        asn_d['num'] = val['as_maxmind'].get('num', 0)

    geo_d = {}
    if 'geo' in val.keys():
        geo_d['ctry'] = val['geo'].get('ctry', "unknown")

    bl_l = []
    for l in val.get('bl', []):
        bl_l.append(l['n'])

    tags_l = []
    for l in val.get('tags', []):
        d = {
            'n' : l,
            'c' : val['tags'][l]['confidence']
        }

        tags_l.append(d)

    data = {
        'ip' : val['_id'],
        'rep' : val['rep'],
        'hostname' : val['hostname'],
        'asn' : asn_d,
        'geo' : geo_d,
        'bl'  : bl_l,
        'tags'  : tags_l
    }

    return data

@app.route('/nerd/api/v1/ip/<ipaddr>')
def get_basic_info(ipaddr=None):
    ret = validate_api_request(request.headers.get("Authorization"))
    if ret:
        return ret

    ret, val = get_ip_info(ipaddr)
    if not ret:
        return val

    binfo = get_basic_info_dic(val)

    return Response(json.dumps(binfo), 200, mimetype='application/json')

# ***** NERD API FullInfo *****

@app.route('/nerd/api/v1/ip/<ipaddr>/full')
def get_full_info(ipaddr=None):
    ret = validate_api_request(request.headers.get("Authorization"))
    if ret:
        return ret

    ret, val = get_ip_info(ipaddr)
    if not ret:
        return val

    asn_d = {}
    if 'as_maxmind' in val.keys():
        asn_d['num'] = val['as_maxmind'].get('num', 0)
        asn_d['name'] = val['as_maxmind'].get('description', "")
    elif 'as_rv' in val.keys():
        asn_d['num'] = val['as_rv'].get('num', 0)
        asn_d['name'] = val['as_rv'].get('description', "")

    evts = val['events']
    del evts['total1']
    del evts['total30']
    del evts['total7']
    del evts['types']

    data = {
        'ip' : val['_id'],
        'rep' : val['rep'],
        'hostname' : val['hostname'],
        'asn' : asn_d,
        'geo' : val['geo'],
        'ts_added' : val['ts_added'],
        'ts_last_update' : val['ts_last_update'],
        'ts_last_event' : val['ts_last_event'],
        'events' : evts
    }

    return Response(json.dumps(data), 200, mimetype='application/json')

# ***** NERD API IPSearch *****

@app.route('/nerd/api/v1/search/ip/')
def ip_search():
    err = {}

    ret = validate_api_request(request.headers.get("Authorization"))
    if ret:
        return ret

    form = IPFilterForm(request.args, csrf_enabled=False)
    if not form.validate():
        err['err_n'] = 400
        err['error'] = 'Bad parameters: ' + '; '.join('{}: {}'.format(name, ', '.join(errs)) for name, errs in form.errors.items())
        return Response(json.dumps(err), 400, mimetype='application/json')

    sortby = sort_mapping[form.sortby.data]
    query = create_query(form)
    
    try:
        results = mongo.db.ip.find(query).limit(form.limit.data)
        if sortby != "none":
            results.sort(sortby, 1 if form.asc.data else -1)
        results = list(results)
    except pymongo.errors.ServerSelectionTimeoutError:
        err['err_n'] = 503
        err['error'] = 'Database connection error'
        return Response(json.dumps(data), 503, mimetype='application/json')

    output = request.args.get('o', "json")
    if output == "json":
        lres = []
        for res in results:
            lres.append(get_basic_info_dic(res))
        return Response(json.dumps(lres), 200, mimetype='text/plain')

    elif output == "list":
        return Response('\n'.join(res['_id'] for res in results), 200, mimetype='application/json')
    else:
        err['err_n'] = 400
        err['error'] = 'Unrecognized value of output parameter: ' + output
        return Response(json.dumps(err), 400, mimetype='application/json')

# **********

if __name__ == "__main__":
    config.testing = True
    app.run(host="0.0.0.0", debug=True)

