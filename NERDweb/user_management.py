from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, session, g, make_response, current_app, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from bcrypt import hashpw, checkpw, gensalt
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# needed overridden render_template method because it passes some needed attributes to Jinja templates
from nerd_main import render_template, BASE_URL, config, mailer
from userdb import create_user, get_user_data_for_login, get_user_by_email, verify_user, get_verification_email_sent, \
    set_verification_email_sent, set_last_login, get_user_name, set_new_password


# variable name and name of blueprint is recommended to be same as filename
user_management = Blueprint("user_management", __name__, static_folder="static", template_folder="templates")

ERROR_MSG_MISSING_MAIL_CONFIG = "ERROR: No destination email address configured. This is a server configuration " \
                                "error. Please, report this to NERD administrator if possible."


# ***** Util functions *****
def generate_token(user_email):
    """ Generates random token for email verification or password reset. """
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(user_email)


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
    return datetime.now() # TODO? shouldn't it be utcnow()? ukladádá se do DB


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


# ***** Forms *****
class UserRegistrationForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo('password')])
    name = StringField("Full name", validators=[Length(max=80)])
    organization = StringField("Organization", validators=[Length(max=80)])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class PasswordResetRequest(FlaskForm):
    email = StringField("Enter your email address:", validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")


class PasswordReset(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm new password", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Submit")


# ***** Routes *****
@user_management.route("/register", methods=['POST', 'GET'])
def register_user():
    reg_form = UserRegistrationForm()
    if reg_form.validate_on_submit():
        # store user in database
        hashed_password = get_hashed_password(reg_form.password.data)
        res = create_user(reg_form.email.data, hashed_password, "local", reg_form.name.data, reg_form.organization.data)
        if isinstance(res, Exception):
            if res.args[0].startswith("duplicate key") and "Key (id)" in res.args[0]: #TODO? neexistuje lepší způsob kontroly typu cyhby? Prý na to speciální typ Exc asi není
                flash(f"User with email address {reg_form.email.data} already exists! You can either log in or try to "
                      f"reset your password in log-in section.", "error")
            else:
                print(f"ERROR in register_user(): Something has failed during registration process: {res.args}")
                # TODO implement some notification mechanism for such errors
                flash(f"Something has failed during registration process, please contact administrator.", "error")
        else:
            flash(f"Account created for {reg_form.email.data}!", "success")
            # immediately log in user
            session['user'] = {
                'login_type': 'local',
                'id': reg_form.email.data,
            }
            send_verification_email(reg_form.email.data, reg_form.name.data)
            set_verification_email_sent(get_current_datetime(), reg_form.email.data)
            set_last_login(get_current_datetime(), reg_form.email.data)
        return redirect(BASE_URL+'/ips/')
    return render_template('user_registration.html', title="Registration", form=reg_form)


@user_management.route("/login/local", methods=['POST', 'GET'])
def login_local():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_data = get_user_data_for_login("local:" + login_form.email.data)
        if (user_data is None or
            not checkpw(login_form.password.data.encode('utf-8'), user_data['password'].encode('utf-8'))):
            flash(f"Wrong email or password!", "error")
        else:
            flash(f"User {user_data['name']} successfully logged in!")
            session['user'] = {
                'login_type': 'local',
                'id': login_form.email.data,
            }
            return redirect(BASE_URL + '/')
    return render_template('login.html', title="Local login", form=login_form)


@user_management.route("/password_reset_request", methods=['POST', 'GET'])
def password_reset_request():
    pw_reset_form = PasswordResetRequest()
    if pw_reset_form.validate_on_submit():
        user_name = get_user_name(pw_reset_form.email.data)
        if user_name is None:
            flash("User with such email address does not exist", "error") # TODO? is it OK to disclose information about account (non)existence?
        else:
            send_password_reset_email(pw_reset_form.email.data, user_name.split(' '))
            flash(f"Email with password reset link was sent!")
            return redirect(BASE_URL + '/')
    return render_template('password_reset_request.html', title="Password reset request", form=pw_reset_form)


@user_management.route("/password_reset_request/<token>", methods=['POST', 'GET']) #TODO? only one method should be allowed, there's no reason to allow the one we don't use (in all endpoints)
def password_reset(token):
    # Check token validity and load user info
    # TODO? shouldn't it be user ID instead?
    user = verify_email_token(token)
    if user is None or user['email'] is None:
        return redirect(BASE_URL + '/')

    assert user['id'].startswith("local:") # password reset is only possible for local accounts
    userid = user['id'][6:] # remove leading "local:"

    pw_reset_form = PasswordReset()
    if pw_reset_form.validate_on_submit():
        result = set_new_password(get_hashed_password(pw_reset_form.password.data), user['email'])
        if result is not None:
            # exception occurred
            flash("Password reset failed. Please, try again and if the problem persists, contact NERD administrator.",
                  "error")
        else:
            flash(f"Password has been successfully changed!", "success")
        return redirect(BASE_URL + '/')

    return render_template('password_reset.html', title="Password reset", form=pw_reset_form, userid=userid)
# TODO? i tady by mohl byt "password_strength_check"


@user_management.route("/verify/<token>")
def verify_email(token):
    # Check token validity and load user info
    user = verify_email_token(token)
    if user is None or user['email'] is None:
        return redirect(BASE_URL + '/') # error message was issued via flash(), just show main page

    if user['verified']:
        flash('Account already confirmed. Please login.', 'success')
    else:
        result = verify_user(user['id'])
        if result is not None:
            # exception occurred
            flash("Verification failed. Please, try again and if the problem persists, contact NERD administrator.",
                  "error")
        else:
            flash(f"Email address {user['email']} successfully verified!", "success")
    return redirect(BASE_URL + '/')


@user_management.route("/resend_verification")
def resend_verification_mail():
    user_email = g.user['fullid'].split(':')[1]
    email_sent_at = get_verification_email_sent(user_email)
    if email_sent_at and email_sent_at > (get_current_datetime() - timedelta(hours=1)):
        flash("Verification email was already sent in last hour. Check your inbox!", "error")
    else:
        user_name = get_user_name(user_email).split(' ')
        send_verification_email(user_email, user_name)
        set_verification_email_sent(get_current_datetime(), user_email)
        flash("New verification email was sent, check your inbox!", "success")
    return redirect(BASE_URL + '/')

# TODO: create some simpler html template/layout for these login/verify/reset pages (?)
