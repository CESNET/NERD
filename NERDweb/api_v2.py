from flask import Blueprint, flash, redirect, session, g, make_response, \
    current_app, url_for, request, make_response, Response, jsonify, url_for
import requests
from flask_pymongo import pymongo, PyMongo
from datetime import datetime, timedelta, timezone
import jwt
from jwt import PyJWKClient
from jwt.exceptions import DecodeError
from werkzeug.exceptions import InternalServerError, Unauthorized
import os
import sys
import common.config
from auth import token_required
from common.utils import ipstr2int, int2ipstr, parse_rfc_time
import json
from bcrypt import hashpw, checkpw, gensalt
import subprocess
import re
from flasgger import swag_from
from flask_mail import Mail, Message
from requests_oauthlib import OAuth1Session, OAuth2Session

from user_management import get_hashed_password, generate_token, verify_email_token, \
    generate_jwt_token, confirm_jwt_token
    
from com import attach_whois_data, get_ip_info, mailer, mongo, get_basic_info_dic, get_basic_info_dic_short, get_basic_info_dic_v2, find_ip_data, ip_to_warden_data, create_query_v2
from userdb import get_user_info, authenticate_with_token, generate_unique_token, \
    get_user_by_id, create_user, verify_user, set_last_login, get_user_name,  \
    set_new_password, get_users_admin, set_verification_email_sent, set_new_roles, \
    delete_user, just_verify_user_by_id, set_api_v1_token, get_user_by_email

DEFAULT_CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "/etc/nerd/nerdweb.yml"))

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

config.testing = True

# url for redirects
APP_BASE_URL = config.get('app_base_url')

api_v2 = Blueprint("api_v2", __name__, static_folder="static", template_folder="templates")

def check_email(email):
    return re.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', email)

def send_password_reset_email(user_email):
    if not config.get('login.request-email', None):
         return dict(message='Error while sendig email.'), 402
    token = generate_jwt_token(user_email)
    password_reset_url = url_for('api_v2.password_reset', token=token, _external=True)
    msg = Message(subject="[NERD] Password reset request",
                  recipients=[user_email],
                  reply_to=current_app.config.get('MAIL_DEFAULT_SENDER'),
                  body=f"Dear user,\n\nyou can reset your password by clicking on this link:"
                       f"\n\n{password_reset_url}\n\nThank you,\nNERD administrator",
                  )
    mailer.send(msg)

########################################################
#                   NERD ENDPOINTS                     #
########################################################

# ***** NERD API BasicInfo *****
@api_v2.route('/ip/<ipaddr>', methods=['GET'])
def get_basic_info_v2(ipaddr=None):
    """Basic info for a single IP address
    ---
    parameters:
      - name: ipaddr
        in: path
        type: string
        required: true
        description: IP address in IPv4 format
    responses:
      200:
        description: An object containing basic info about IP
    """
    ret, val = get_ip_info(ipaddr, False)
    if not ret:
        return val # val is an error Response

    binfo = get_basic_info_dic(val)

    return Response(json.dumps(binfo), 200, mimetype='application/json')

# ***** NERD API IPSearch *****
@api_v2.route('/search/ip', methods=['POST'])
@swag_from('./api_v2_swag/search.yml', validation=True)
def ip_search_v2(full = False):
    err = {}

    # Get output format
    output = request.json
    query = create_query_v2(output)

    if "page" not in output:
        output["page"] = 1
    
    if "limit" not in output:
        output["limit"] = 20
    
    if "order" not in output:
        output["order"] = "desc"
    
    if "sort" not in output or output["sort"] is None:
        output["sort"] = "rep"
    elif output["sort"] == "ip":
        output["sort"] = "_id"

    try:
        results = find_ip_data(query, (output["page"] - 1) * output["limit"], output["limit"]) # note: limit=0 means no limit
        results.sort(output["sort"], 1 if output["order"] == "asc" else -1)
        results = list(results)
    except pymongo.errors.ServerSelectionTimeoutError:
        log_err.log('503_db_error')
        err['err_n'] = 503
        err['error'] = 'Database connection error'
        resp = Response(json.dumps(err), 503, mimetype='application/json')
        return resp

    # Return results
    if output == "list":
        resp = Response(''.join(int2ipstr(res['_id'])+'\n' for res in results), 200, mimetype='text/plain')
        return resp

    # Convert _id from int to dotted-decimal string        
    for res in results:
        res['_id'] = int2ipstr(res['_id'])

    lres = []
    if output == "short":
        for res in results:
            lres.append(get_basic_info_dic_short(res))
    else:    
        for res in results:
            attach_whois_data(res, full)
            lres.append(get_basic_info_dic_v2(res))

    resp = Response(json.dumps(lres, default=str), 200, mimetype='application/json')
    return resp

# ***** NERD API Details *****
@api_v2.route('/details/<ipaddr>', methods=['GET'])
def get_full_info(ipaddr=None):
    """Detailed info for a single IP address
    ---
    parameters:
      - name: ipaddr
        in: path
        type: string
        required: true
        description: IP address in IPv4 format
    responses:
      200:
        description: An object containing detailed info about IP
    """
    ret, val = get_ip_info(ipaddr, True)
    if not ret:
        return val # val is an error Response

    data = {
        'ip' : val['_id'],
        'rep' : val.get('rep', 0.0),
        'fmp' : val.get('fmp', {'general': 0.0}),
        'hostname' : (val.get('hostname', '') or '')[::-1],
        'ipblock' : val.get('ipblock', ''),
        'bgppref' : val.get('bgppref', ''),
        'asn' : val.get('asn',[]),
        'geo' : val.get('geo', None),
        'ts_added' : val['ts_added'].strftime("%Y-%m-%dT%H:%M:%S"),
        'ts_last_update' : val['ts_last_update'].strftime("%Y-%m-%dT%H:%M:%S"),
        'last_activity' : val['last_activity'].strftime("%Y-%m-%dT%H:%M:%S") if 'last_activity' in val else None,
        'bl' : [ {
                'name': bl['n'],
                'last_check': bl['t'].strftime("%Y-%m-%dT%H:%M:%S"),
                'last_result': True if bl['v'] else False,
                'history': [t.strftime("%Y-%m-%d") for t in bl['h']]
            } for bl in val.get('bl', []) ],
        'events' : ip_to_warden_data(ipaddr),
        'misp_events' : val.get('misp_events', []),
        'events_meta' : {
            'total': val.get('events_meta', {}).get('total', 0.0),
            'total1': val.get('events_meta', {}).get('total1', 0.0),
            'total7': val.get('events_meta', {}).get('total7', 0.0),
            'total30': val.get('events_meta', {}).get('total30', 0.0),
        },
        'dshield' : val.get('dshield', []),
        'otx_pulses' : val.get('otx_pulses', []),
        'tags': val.get('tags', []),

    }

    return Response(json.dumps(data, default=str), 200, mimetype='application/json')



########################################################
#                   USER ENDPOINTS                     #
########################################################
@api_v2.route('/login/devel')
def login_devel_v2():
    if not config.testing:
        return flask.abort(404)
    out = {}
    out['user'] = {
        'login_type': 'devel',
        'id': 'devel_admin',
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    encoded_jwt = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    return encoded_jwt

# User login
@api_v2.route('/login', methods=['POST'])
@swag_from('./api_v2_swag/login.yml', validation=True)
def login_user_v2():
    try:
        data = request.json
        if not data:
            return {
                "message": "Please provide user details",
                "data": None,
                "error": "Bad request"
            }, 400
        user = get_user_by_id("local:" + data["email"])

        if user is None:
            user = get_user_by_email(data["email"])
            if user is None:
                return dict(message='User does not exist.'), 404
            return dict(message='Local user does not exist but provided email is associated with provider: ' + user['id'].split(":")[0]), 404
        
        if not checkpw(data["password"].encode('utf-8'), user['password'].encode('utf-8')):
            return dict(message='Bad password.'), 400
        try:
            out = {}
            out['user'] = {
                'login_type': 'local',
                'id': user['id'],
                'email': user['email'],
            }
            out['exp'] = datetime.utcnow()+timedelta(hours=4)
            token = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
            out2 = {}
            out2['user'] = {
                'login_type': 'local',
                'id': user['id'],
                'email': user['email'],
            }
            out2['exp'] = datetime.utcnow()+timedelta(hours=72)
            refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
            set_last_login(datetime.utcnow(), user['id'])
            return Response(json.dumps([token, refreshToken], default=str), 200, mimetype='application/json')
            
        except Exception as e:
            return {
                "error": "Something went wrong",
                "message": str(e)
            }, 500
        return {
            "message": "Error fetching auth token!, invalid email or password",
            "data": None,
            "error": "Unauthorized"
        }, 404
    except Exception as e:
        return {
                "message": "Something went wrong!",
                "error": str(e),
                "data": None
        }, 500

@api_v2.route('/register', methods=['POST'])
@swag_from('./api_v2_swag/register.yml', validation=True)
def register_user_v2():
    data = request.json
    if not check_email(data["email"]):
        return dict(message='Wrong email format.'), 400
    if len(data["password"]) < 8:
        return dict(message='Password not long enough.'), 400

    hashed_password = get_hashed_password(data["password"])
    res = create_user(data["email"], hashed_password, "local", data["name"], data["organization"])
    if isinstance(res, Exception):
        if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]: #TODO? neexistuje lep�� zp�sob kontroly typu cyhby? Pr� na to speci�ln� typ Exc asi nen�
            return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                    f"reset your password in log-in section."), 400
        else:
            return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
    else:        
        out = {}
        out['user'] = {
            'email': data['email'],
        }
        out['exp'] = datetime.utcnow()+timedelta(hours=24)
        encoded_jwt = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
        msg = Message(subject="[NERD] Account created",
                  recipients=[data["email"]],
                  reply_to=current_app.config.get('MAIL_DEFAULT_SENDER'),
                  )
        msg.body = f"NERD - Network Entity Reputation Database \nEmail address verification \n>Dear user {data['email']}, \nyou can activate your NERD account by clicking the link below (the link is valid for 24 hours): \n{config.get('email_web')}/verify?accessToken={encoded_jwt} \nNERD administrator"
        msg.html = f"<h1>NERD</h1><p><small>Network Entity Reputation Database</small><br></p><h2>Email address verification</h2><p>Dear user {data['email']},</p><p>you can activate your NERD account by clicking this <b><a href='{config.get('email_web')}/verify?accessToken={encoded_jwt}'>LINK</a></b> (the link is valid for 24 hours).</p><p></p><br><p>NERD administrator</p>"
        mailer.send(msg)
        set_verification_email_sent(datetime.utcnow(), "local:" + data["email"])
        return dict(message=f"Account created for {data['email']}!"), 200

@api_v2.route('/verify', methods=['POST'])      
def verify_email_address():
    """Email verification after registration
    ---
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            accessToken:
              type: string
              description: Email token provided after user registration
              example: "ey...."
    responses:
      200:
        description: Successful email verification
      400:
        description: accessToken missing
      500:
        description: Internal server error
    """
    data = request.json
    if not data["accessToken"]:
        return dict(message='No access token.'), 400
    try:
        out = jwt.decode(data["accessToken"], config.get('secret_key'), algorithms=["HS256"])
    except Exception as e:
        return {
            "message": "Something went wrong",
            "data": None,
            "error": str(e)
        }, 500
    try:
        verify_user("local:" + out["user"]["email"])
    except Exception as e:
        return {
            "message": "Something went wrong",
            "data": None,
            "error": str(e)
        }, 500
    return dict(message=f"Email verified for {out['user']['email']}!"), 200


# gets user info extracted from JWT
@api_v2.route('/me', methods=['GET'])
@token_required
def me_info(current_user):
    """User profile info
    ---
    security:
        - OAuth2: [user]
    responses:
      200:
        description: User info fetched
    """
    return jsonify({ "email": current_user["email"], "groups": current_user["groups"], "name": current_user["name"], "org": current_user["org"], "type": current_user["id"].split(":")[0], "api_v1_token": current_user["api_token"]}), 200


@api_v2.route('/reset_password', methods=['POST'])
def password_reset_request():
    """Local user password reset request
    ---
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Local user email
              example: "user@email.com"
    responses:
      200:
        description: Password reset email sent
    """
    data = request.json
    user = get_user_by_id("local:" + data["email"])
    if user is None:
        return dict(message='User with this email does not exist.'), 401
    else:
        send_password_reset_email(data["email"])
        return dict(message='Email with password reset link was sent!'), 200

@api_v2.route("/password_reset_request/<token>", methods=['GET'])
def password_reset(token):
    """Password reser redirect URI form email
    ---
    parameters:
      - name: token
        in: path
        type: string
        required: true
        description: Token form email
    responses:
      401:
        description: User not found
    """
    user = confirm_jwt_token(token)
    if user is None or user['email'] is None:
        return dict(message='User not found'), 401
    
    return redirect(APP_BASE_URL + "/nerd2/password-reset?token=" + token)

@api_v2.route("/password_reset_from_token", methods=['POST'])
def password_reset_token():
    """Local user password reset action
    ---
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
              description: Token from email
              example: "ey..."
    responses:
      200:
        description: Password has been successfully changed
      400:
        description: Problem when reseting password
      404: 
        description: User not found
    """
    data = request.json
    token = data["token"]
    user = confirm_jwt_token(token)
    if user is None or user['email'] is None:
        return dict(message='User not found'), 404

    if len(data["password"]) < 8:
        return dict(message='Password not long enough'), 400

    result = set_new_password(get_hashed_password(data["password"]), "local:" + user['email'])
    if result is not None:
        # exception occurred
        return dict(message="Password reset failed. Please, try again and if the problem persists, contact NERD administrator."), 400
    else:
        return dict(message="Password has been successfully changed!"), 200


@api_v2.route("/change_password", methods=['POST'])
@token_required
def password_change(current_user):
    """Local user password change
    ---
    security:
        - OAuth2: [user]
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            passOld:
              type: string
              description: old passowrd
              example: "password123"
            password:
              type: string
              description: new password
              example: "password12"
    responses:
      200:
        description: Password has been successfully changed
      400:
        description: Problem when reseting password
      404: 
        description: Wrong user or password
    """
    data = request.json

    if len(data["password"]) < 8:
        return dict(message='Password not long enough'), 404

    user = get_user_by_id("local:" + current_user["email"])

    if user is None:
        return dict(message='User does not exist.'), 404

    try:
        if not checkpw(data["passOld"].encode('utf-8'), user["password"].encode('utf-8')):
            return dict(message='Bad password.'), 404
    except Exception as e:
        return {
                "message": "Something went wrong!",
                "error": str(e),
                "data": None
        }, 500

    result = set_new_password(get_hashed_password(data["password"]), "local:" + current_user["email"])
    if result is not None:
        # exception occurred
        return dict(message="Password change failed. Please, try again and if the problem persists, contact NERD administrator."), 400
    else:
        return dict(message="Password has been successfully changed!"), 200




@api_v2.route('/refreshToken', methods=['POST'])
def refreshToken():
    """Resresh login token
    ---
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
              description: refresh token
              example: "ey..."
    responses:
      200:
        description: Token refreshed
      400:
        description: wrong format
      403:
        description: Invalid Authentication token
      404: 
        description: Email address not verified
    """
    data = request.json
    try:
        out = jwt.decode(data["token"], config.get("secret_key"), algorithms=["HS256"])
    except Exception as e:
        return {
            "message": "Something went wrong",
            "data": None,
            "error": "wrong format"
        }, 400
    # check if anything changed in between token gens
    current_user = get_user_by_id(out["user"]["id"])
    if current_user is None:
        return {
        "message": "Invalid Authentication token!",
        "data": None,
        "error": "Unauthorized"
    }, 403
    if not "registered" in current_user["groups"]:
        return {
        "message": "Email address not verified",
        "data": None,
    }, 404
    out2 = out
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    out2['exp'] = datetime.utcnow()+timedelta(hours=72)
    accessToken = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
    return Response(json.dumps([accessToken, refreshToken], default=str), 200, mimetype='application/json')

########################################################
#                   ADMIN ENDPOINTS                    #
########################################################

@api_v2.route('/users', methods=['GET'])
@token_required
def users_info(current_user):
    """Gets all users
    ---
    security:
        - OAuth2: [admin]
    responses:
      200:
        description: Users
      500:
        description: Internal server error
    """
    # check if user accessing this endpoint is admin
    if 'admin' not in current_user["groups"]:
        return dict(message='Access denied.'), 500
    
    try:
        users = get_users_admin()
    except Exception as e:
         return {
                "message": "Something went wrong!",
                "error": str(e),
                "data": None
        }, 500
    
    return jsonify(users), 200


@api_v2.route('/roles', methods=['PUT'])
@token_required
def change_roles(current_user):
    """Change of user roles
    ---
    security:
        - OAuth2: [admin]
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            id:
              type: string
              description: user email
              example: "local:user@email.com"
            roles:
              type: array
              description: array of user roles
              example: ["registered", "admin"]
    responses:
      200:
        description: Roles changed successfully
      500:
        description: Internal server error
    """
    # check if user accessing this endpoint is admin
    if 'admin' not in current_user["groups"]:
        return dict(message='Access denied.'), 500

    data = request.json
    # user whose roles are to be changed
    ide = data["id"]   
    # new array of roles
    roles = data["roles"]   
    try:
        out = set_new_roles(ide, roles)
    except Exception as e:
         return {
                "message": "Something went wrong!",
                "error": str(e),
                "data": None
        }, 500
    if not out:
        return {
                "message": "Error while saving data to DB.",
                "error": "DB Error",
                "data": None
        }, 500
    
    return dict(message="Roles chaged successfully !"), 200

@api_v2.route('/delete_user/<ide>', methods=['DELETE'])
@token_required
def delete(current_user, ide):
    """Deletes user
    ---
    security:
        - OAuth2: [admin]
    parameters:
      - name: ide
        in: path
        type: string
        required: true
        description: ID of user to delete
    responses:
      200:
        description: User deleted successfully
      500:
        description: Internal server error
    """
    # check if user accessing this endpoint is admin
    if 'admin' not in current_user["groups"]:
        return dict(message='Access denied.'), 500
  
    try:
        delete_user(ide)
    except Exception as e:
         return {
                "message": "Something went wrong!",
                "error": str(e),
                "data": None
        }, 500
    
    return dict(message="User deleted successfully!"), 200

@api_v2.route('/add-user', methods=['POST'])
@token_required
def add_user(current_user):
    """Add new user
    ---
    security:
        - OAuth2: [admin]
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        description: Request body for endpoint
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: user email
              example: "local:user@email.com"
            password:
              type: string
              description: users passroed
              example: "password123"
            organization:
              type: string
              description: users organization
              example: "org"
            roles:
              type: array
              description: array of user roles
              example: ["registered", "admin"]
            verify:
              type: boolean
              description: mark email as verified
              example: true
    responses:
      200:
        description: User added succesfully
      400:
        description: Error while creating user
      500:
        description: Internal server error
    """
    # check if user accessing this endpoint is admin
    if 'admin' not in current_user["groups"]:
        return dict(message='Access denied.'), 500
    data = request.json
    hashed_password = get_hashed_password(data["password"])
    res = create_user(data["email"], hashed_password, "local", data["name"], data["organization"], data["roles"])
    if isinstance(res, Exception):
        if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]: #TODO? neexistuje lep�� zp�sob kontroly typu cyhby? Pr� na to speci�ln� typ Exc asi nen�
            return dict(message=f"User with email address {data['email']} already exists!"), 400
        else:
            return dict(message=f"ERROR in create_user(): Something has failed during user creation process: {res.args}"), 400
    if data["verify"]:
        just_verify_user_by_id("local:" + data["email"])
    else:
        out = {}
        out['user'] = {
            'email': data['email'],
        }
        out['exp'] = datetime.utcnow()+timedelta(hours=24)
        encoded_jwt = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
        msg = Message(subject="[NERD] Account cerated",
                  recipients=[data["email"]],
                  reply_to=current_app.config.get('MAIL_DEFAULT_SENDER'),
                  )
        msg.html = f"<h1>NERD</h1><p><small>Network Entity Reputation Database</small><br></p><h2>Email address verification</h2><p>Dear user {data['email']},</p><p>you can activate your NERD account by clicking the link below (the link is valid for 24 hours):</p><p><a href='{config.get('email_web')}/verify?accessToken={encoded_jwt}'>{config.get('email_web')}/verify</a></p><br><p>NERD administrator</p>"
        mailer.send(msg)
        set_verification_email_sent(datetime.utcnow(), data["email"])

    return dict(message=f"Account created for {data['email']}!"), 200


########################################################
#             EXTERNAL IDENTITY PROVIDERS              #
########################################################


@api_v2.route('/oauth/google', methods=['GET'])
def oauth_google():
    code = request.args.get("code")
    # Set the token endpoint URL
    token_url = "https://oauth2.googleapis.com/token"

    # Set the parameters for the POST request
    client_id = "864125509519-s4prljrk97usreg167i7de2rkppfa4re.apps.googleusercontent.com"
    client_secret = "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"
    redirect_uri = APP_BASE_URL + "/nerd/api/v2/oauth/google"
    grant_type = "authorization_code"

    # Make the POST request to exchange the authorization code for an access token
    response = requests.post(token_url, data={
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": grant_type
    })

    # Get the access token and user info from the response
    access_token = response.json()["access_token"]
    token_type = response.json()["token_type"]
    expires_in = response.json()["expires_in"]
    refresh_token = response.json()["refresh_token"]

    # Use the access token to get user info
    user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {"Authorization": f"{token_type} {access_token}"}
    user_info_response = requests.get(user_info_url, headers=headers)

    # Get the user info from the response
    user_info = user_info_response.json()

    created = "false"

    # Now you can check if the user's email is in your local DB
    if get_user_by_id("google:" + user_info["email"]) is None:
        res = create_user(user_info["email"], None, "google", "NoName", "NoOrg")
        if isinstance(res, Exception):
            if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]: #TODO? neexistuje lep�� zp�sob kontroly typu cyhby? Pr� na to speci�ln� typ Exc asi nen�
                return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                        f"reset your password in log-in section."), 400
            else:
                return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
        else:
            verify_user("google:" + user_info["email"])
            created = "true"
    out = {}
    out['user'] = {
        'login_type': 'google',
        'id': 'google:' + user_info["email"],
        'email': user_info["email"],
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    token = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    out2 = {}
    out2['user'] = {
        'login_type': 'google',
        'id': 'google:' + user_info["email"],
        'email': user_info["email"],
    }
    out2['exp'] = datetime.utcnow()+timedelta(hours=72)
    refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
    set_last_login(datetime.utcnow(), 'google:' + user_info["email"])
    return redirect(APP_BASE_URL + "/nerd2/auth?token=" + token + "&refreshToken=" + refreshToken + "&created=" + created, code=302)


@api_v2.route('/oauth/twitter/url', methods=['GET'])
def oauth_twitter_access():
    #create an object of OAuth1Session    
    request_token = OAuth1Session(client_key="pOVnN86c7LgVcPhtnbc2dpmpu", client_secret="cRacpbtBs87wx3uEHQ6aE04SmyS0JpwlZG8W5TfL9WElMp7hVq")
    # twitter endpoint to get request token
    url = 'https://api.twitter.com/oauth/request_token'
    # get request_token_key, request_token_secret and other details
    data = request_token.get(url)
    # split the string to get relevant data 
    data_token = str.split(data.text, '&')
    ro_key = str.split(data_token[0], '=')
    ro_secret = str.split(data_token[1], '=')
    resource_owner_key = ro_key[1]
    resource_owner_secret = ro_secret[1]
    return redirect("https://api.twitter.com/oauth/authenticate?oauth_token=" + resource_owner_key)

@api_v2.route('/oauth/twitter', methods=['GET'])
def oauth_twitter():
    token = request.args.get("oauth_token")
    verifier = request.args.get("oauth_verifier")
    oauth_token = OAuth1Session(client_key="pOVnN86c7LgVcPhtnbc2dpmpu", client_secret="cRacpbtBs87wx3uEHQ6aE04SmyS0JpwlZG8W5TfL9WElMp7hVq")
    url = 'https://api.twitter.com/oauth/access_token'
    data = {"oauth_verifier": verifier, "oauth_token": token}
   
    access_token_data = oauth_token.post(url, data=data)
    access_token_list = str.split(access_token_data.text, '&')

    access_token_key = str.split(access_token_list[0], '=')
    access_token_secret = str.split(access_token_list[1], '=')
    access_token_name = str.split(access_token_list[3], '=')
    access_token_id = str.split(access_token_list[2], '=')
    key = access_token_key[1]
    secret = access_token_secret[1]
    oauth_user = OAuth1Session(client_key="pOVnN86c7LgVcPhtnbc2dpmpu", client_secret="cRacpbtBs87wx3uEHQ6aE04SmyS0JpwlZG8W5TfL9WElMp7hVq",
                               resource_owner_key=key,
                               resource_owner_secret=secret)
    url_user = 'https://api.twitter.com/1.1/account/verify_credentials.json'
    params = {"include_email": 'true'}
    user_data = oauth_user.get(url_user, params=params)
    user_info = user_data.json()
    created = "false"
    if get_user_by_id('twitter:' + user_info["email"]) is None:
        res = create_user(user_info["email"], None, "twitter", "NoName", "NoOrg")
        if isinstance(res, Exception):
            if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]:
                return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                        f"reset your password in log-in section."), 400
            else:
                return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
        else:
            verify_user("twitter:" + user_info["email"])
            created = "true"
    out = {}
    out['user'] = {
        'login_type': 'twitter',
        'id': 'twitter:' + user_info["email"],
        'email': user_info["email"],
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    token = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    out2 = {}
    out2['user'] = {
        'login_type': 'twitter',
        'id': 'twitter:' + user_info["email"],
        'email': user_info["email"],
    }
    out2['exp'] = datetime.utcnow()+timedelta(hours=72)
    refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
    set_last_login(datetime.utcnow(), 'twitter:' + user_info["email"])
    return redirect(APP_BASE_URL + "/nerd2/auth?token=" + token + "&refreshToken=" + refreshToken + "&created=" + created, code=302)

@api_v2.route('/oauth/github', methods=['GET'])
def oauth_github():
    code = request.args.get("code")
    # Set the token endpoint URL
    token_url = "https://github.com/login/oauth/access_token"

    # Set the parameters for the POST request
    client_id = "b13789eb1250d5e77992"
    client_secret = "c9de015e91e288f96973b7aa95406c44284687b4"

    # Make the POST request to exchange the authorization code for an access token
    response = requests.post(token_url, data={
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret
    })

    access_token = 'token ' + response.text.split("&")[0].split("=")[1]
    url = 'https://api.github.com/user/emails'
    headers = {"Authorization": access_token}

    resp = requests.get(url=url, headers=headers)

    userData = resp.json()
    for email in userData:
        if email["primary"]:
            user_email =  email["email"]
            break
    created = "false"

    if get_user_by_id('github:' + user_email) is None:
        res = create_user(user_email, None, "github", "NoName", "NoOrg")
        if isinstance(res, Exception):
            if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]:
                return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                        f"reset your password in log-in section."), 400
            else:
                return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
        else:
            verify_user("github:" + user_email)
            created = "true"
    out = {}
    out['user'] = {
        'login_type': 'github',
        'id': 'github:' + user_email,
        'email': user_email,
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    token = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    out2 = {}
    out2['user'] = {
        'login_type': 'github',
        'id': 'github:' + user_email,
        'email': user_email,
    }
    out2['exp'] = datetime.utcnow()+timedelta(hours=72)
    refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
    set_last_login(datetime.utcnow(), 'github:' + user_email)
    return redirect(APP_BASE_URL + "/nerd2/auth?token=" + token + "&refreshToken=" + refreshToken + "&created=" + created, code=302)


def get_well_known_metadata():
    response = requests.get("https://login.cesnet.cz/oidc/.well-known/openid-configuration")
    response.raise_for_status()
    return response.json()


def get_oauth2_session(**kwargs):
    oauth2_session = OAuth2Session("029639e5-09f4-461d-859a-7b06aa29d61e",
                                   scope=["profile", "email", "openid"],
                                   redirect_uri=APP_BASE_URL + "/nerd/api/v2/oauth/eduid",
                                   **kwargs)
    return oauth2_session

@api_v2.route("/oauth/edugain/url")
def login_edugain():
    well_known_metadata = get_well_known_metadata()
    oauth2_session = get_oauth2_session()
    authorization_url, state = oauth2_session.authorization_url(well_known_metadata["authorization_endpoint"])
    session["oauth_state"] = state
    return redirect(authorization_url)

@api_v2.route("/oauth/eduid")
def edu_id_callback():
    well_known_metadata = get_well_known_metadata()
    oauth2_session = get_oauth2_session(state=request.args["state"])
    oauth_token = oauth2_session.fetch_token(well_known_metadata["token_endpoint"],
                                                        client_secret="73743e93-9560-4d5b-983f-33911afce589cb6c980a-4baa-47e0-8317-c11f786b4254",
                                                        code=request.args["code"])["id_token"]
    resp = oauth2_session.get(well_known_metadata["userinfo_endpoint"])
    data = resp.json()

    # if the user just created a profile
    created = "false"

    # EduGain user not in DB yet
    eduUser = get_user_by_id('edugain:' + data["email"])
    
    if eduUser is None:
        # check if user is in DB from old NERD system
        shiUser = get_user_by_id('shibboleth:' + data["email"])
        if shiUser is None:
            # new user create profile
            res = create_user(data["email"], None, "edugain", "NoName", "NoOrg")
            if isinstance(res, Exception):
                if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]:
                    return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                            f"reset your password in log-in section."), 400
                else:
                    return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
            else:
                verify_user("edugain:" + data["email"])
                created = "true"
        else:
            # user from old NERD merge profile
            res = create_user(data["email"], None, "edugain", shiUser["name"], shiUser["org"])
            if isinstance(res, Exception):
                if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]:
                    return dict(message=f"User with email address {data['email']} already exists! You can either log in or try to "
                            f"reset your password in log-in section."), 400
                else:
                    return dict(message=f"ERROR in register_user(): Something has failed during registration process: {res.args}"), 400
            else:
                verify_user("edugain:" + data["email"])
                set_api_v1_token("edugain:" + data["email"], shiUser["api_token"])
                delete_user('shibboleth:' + data["email"])
                created = "true"
  
    out = {}
    out['user'] = {
        'login_type': 'edugain',
        'id': 'edugain:' + data["email"],
        'email': data["email"],
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    token = jwt.encode(out, config.get('secret_key'), algorithm="HS256")
    out2 = {}
    out2['user'] = {
        'login_type': 'edugain',
        'id': 'edugain:' + data["email"],
        'email': data["email"],
    }
    out2['exp'] = datetime.utcnow()+timedelta(hours=72)
    refreshToken = jwt.encode(out2, config.get('secret_key'), algorithm="HS256")
    set_last_login(datetime.utcnow(), 'edugain:' + data["email"])
    return redirect(APP_BASE_URL + "/nerd2/auth?token=" + token + "&refreshToken=" + refreshToken + "&created=" + created, code=302)