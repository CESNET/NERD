from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, session, g, make_response, current_app, url_for, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from bcrypt import hashpw, checkpw, gensalt
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_dance.consumer import OAuth2ConsumerBlueprint
import jwt


# needed overridden render_template method because it passes some needed attributes to Jinja templates
from nerd_main import render_template, BASE_URL, config, mailer
from userdb import create_user, get_user_data_for_login, get_user_by_email, verify_user, get_verification_email_sent, \
    set_verification_email_sent, set_last_login, get_user_name, set_new_password, check_if_user_exists, get_user_by_id

ERROR_MSG_MISSING_MAIL_CONFIG = "ERROR: No destination email address configured. This is a server configuration " \
                                "error. Please, report this to NERD administrator if possible."

# variable name and name of blueprint is recommended to be same as filename
user_management = Blueprint("user_management", __name__, static_folder="static", template_folder="templates")


# ***** Util functions *****
def generate_token(user_email):
    """ Generates random token for email verification or password reset. """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(user_email)

def generate_jwt_token(email):
    out = {}
    out['user'] = {
        'login_type': 'local',
        'id': 'local:' + email,
        'email': email,
    }
    out['exp'] = datetime.utcnow()+timedelta(hours=4)
    return jwt.encode(out, config.get('secret_key'), algorithm="HS256")

def confirm_jwt_token(token):
    try:
        data=jwt.decode(token, config.get("secret_key"), algorithms=["HS256"])
        
        if data["user"]["login_type"] == "devel":
            return data
        current_user=get_user_by_id(data["user"]["id"])
        if current_user is None:
            return {
            "message": "Invalid Authentication token!",
            "data": data["user"]["id"],
            "error": "Unauthorized"
        }, 401
        if not "registered" in current_user["groups"]:
            return {
            "message": "Email address not verified",
            "data": None,
        }, 403
    except Exception as e:
        return {
            "message": "Something went wrong",
            "data": str(e),
            "error": "AuthToken wrong"
        }, 401
    return current_user


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            max_age=expiration
        )
    except (BadSignature, SignatureExpired):
        return False
    return email


def get_current_datetime():
    return datetime.now() # TODO? shouldn't it be utcnow()? uklad�d� se do DB


def send_verification_email(user_email, name):
    # TODO: udelat nekde kontrolu, ze je nakonfigurovane mailovani
    token = generate_token(user_email)
    confirm_url = url_for('user_management.verify_email', token=token, _external=True)
    msg = Message(subject="[NERD] Verify your account email address",
                  recipients=[user_email],
                  reply_to=current_app.config.get('MAIL_DEFAULT_SENDER'),
                  body=f"Dear {name},\n\nplease verify your email address to complete your registration process by"
                       f" clicking on this link:\n\n{confirm_url}\n\nThank you,\nNERD administrator",
                  )
    mailer.send(msg)


def send_password_reset_email(user_email, name):
    if not config.get('login.request-email', None):
        return make_response(ERROR_MSG_MISSING_MAIL_CONFIG)
    token = generate_token(user_email)
    password_reset_url = url_for('user_management.password_reset', token=token, _external=True)
    msg = Message(subject="[NERD] Password reset request",
                  recipients=[user_email],
                  reply_to=current_app.config.get('MAIL_DEFAULT_SENDER'),
                  body=f"Dear {name},\n\nyou can reset your password by clicking on this link:"
                       f"\n\n{password_reset_url}\n\nThank you,\nNERD administrator",
                  )
    mailer.send(msg)


def get_hashed_password(password):
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')


def verify_email_token(token):
    """ Verifies email token and returns user's email, to which the token was crafted and also user info. """
    email = confirm_token(token)
    if not email:
        flash('The link is invalid or has expired.', 'error')
        return None
    user = get_user_by_email(email)
    if user is None:
        flash('Such user account does not exist. Please check your link and if the problem persists, '
              'contact NERD administrator.', 'error')
    return user

