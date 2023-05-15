# NERDweb module for handling user database
from __future__ import print_function
import string
import random
import os.path
import psycopg2
import sys

__all__ = ['get_user_info', 'get_all_groups', 'authenticate_with_token', 'generate_unique_token']

def init(config, cfg_dir):
    """
    Initialize user database wrapper.
    """
    global users, acl, cfg, db
    cfg = config
    
    acl_cfg_file = os.path.join(cfg_dir, config.get('acl_config'))

    # Create database connection
    db = psycopg2.connect(database=config.get('userdb.dbname', 'nerd_users'),
                          user=config.get('userdb.dbuser', 'nerd'),
                          password=config.get('userdb.dbpassword', None))
    db.autocommit = True # don't use transactions, every action have immediate effect
    
    # Load "acl" file
    # Mapping of "resource_id" to two sets of groups: "groups_allow", "groups_deny".
    # To access a resource, a user must be in at least one group of "groups_allow"
    # and must not be in any of "groups_deny".
    # Format (one resource per line):
    # <resource_id> <comma_separated_list_of_groups_allow>[;<comma_separated_list_of_groups_deny>]
    # (* means anyone)
    acl = {}
    with open(acl_cfg_file, 'r') as f:
        for line in f:
            if line.strip() == "" or line.startswith("#"):
                continue
            id, rest = line.split(None, 1)
            allow, deny = rest.split(';') if ';' in rest else (rest, '')
            allow = set(filter(None, map(str.strip, allow.split(','))))
            deny = set(filter(None, map(str.strip, deny.split(','))))
            acl[id] = (allow, deny)


def get_all_groups():
    """Return all groups defined in the "acl" file."""
    groups = set()
    for allow,deny in acl.values():
        groups.update(allow)
        groups.update(deny)
    groups.discard('*')
    return sorted(list(groups))

# ***** Access control functions *****

def get_user_groups(full_id):
    cur = db.cursor()
    cur.execute("SELECT groups FROM users WHERE id = %s", (full_id,))
    row = cur.fetchone()
    if not row:
        return set() # Unknown user - no group
    return set(row[0])


def get_ac_func(user_groups):
    """Return a function for testing access permissions of a specific user."""
    user_groups2 = user_groups.copy()
    user_groups2.add('*') # every user is in group '*', so acl rule containing '*' always matches
    def ac(resource):
        """"
        Access control test - check if current user has access to given resource.
        """
        if resource in acl and acl[resource][0] & user_groups2 and not acl[resource][1] & user_groups2:
            return True
        else:
            return False
    return ac

def get_user_info(session):
    """
    Returun info about current user (or None if noone is logged in) and 
    the access control function.
     
    To be called by all page handlers as:
      user, ac = get_user_info(session)
    
    'user' contains:
      login_type, id, fullid, groups, name, email, org, api_token, rl-bs, rl-tps
      `----------v---------'  `-----------v------------------------------------'
            from session            from database (find by 'fullid')
    """
    # Get ID of user logged in
    if 'user' in session:
        user = session['user'].copy() # should contain 'id', 'login_type' and optionally 'name'
        user['fullid'] = user['login_type'] + ':' + user['id']
    else:
        # No user logged in
        return None, get_ac_func(set())
    
    # Get user info from DB
    # TODO: get only what is normally needed (id, groups, name (to show in web header), rl-*)
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user['fullid'],))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    if not row:
        # User not found in DB = user is authenticated (e.g. via shibboleth) but has no account yet
        user['groups'] = set()
        return user, get_ac_func(user['groups'])
    
    # Put all fields from DB into 'user' dict
    col_names[0] = 'fullid' # rename column 'id' to 'fullid', other columns can be mapped directly as they are in DB
    user.update(zip(col_names, row))
    
    # Convert user.groups from array/list to set
    user['groups'] = set(user['groups'])
    
    # Convert user.name from utf8 (TODO: this can be probably removed when we start using python3)
    if isinstance(user['name'], bytes):
        user['name'] = user['name'].decode('utf-8') if user['name'] else None
    
    # If the user is in "admin" group, he can select groups that take effect.
    # The set of selected groups is stored as "selected_groups" in the session
    # (which was copied into "user").
    if 'admin' in user['groups'] and 'selected_groups' in user:
        ac = get_ac_func(set(user['selected_groups']))
    else:
        ac = get_ac_func(user['groups'])
    return user, ac


def authenticate_with_token(token):
    """Like get_user_info, but authentication uses API token"""
    user = {}
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE api_token = %s", (token,))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    if not row:
        return None, lambda x: False # user not found

    col_names[0] = 'fullid' # rename column 'id' to 'fullid', other columns can be mapped directly as they are in DB
    user.update(zip(col_names, row))
    user['groups'] = set(user['groups'])
    ac = get_ac_func(user['groups'])
    return user, ac

def generate_unique_token(user):
    while True:
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        cur = db.cursor()
        try:
            cur.execute("SELECT id FROM users WHERE api_token = %s", (token,))
        except psycopg2.Error as e:
            print(e.pgerror, file=sys.stderr)
            return False
        row = cur.fetchone()
        if not row:
            try:
                cur.execute("UPDATE users SET api_token = %s WHERE id = %s", (token, user['fullid'],))
            except psycopg2.Error as e:
                print(e.pgerror, file=sys.stderr)
                return False

            return True

###############################################
#            NEW FUNCTIONS API v2             #
###############################################
# ***** User management functions *****
def create_user(email, password, provider, name=None, organization=None, groups=[]):
    try:
        cur = db.cursor()
        cur.execute("""INSERT INTO users (id, groups, name, email, org, password) 
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (provider + ":" + email, groups, name, email, organization, password))
        db.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as e:
        return e

def get_user_by_email(email):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    if not row:
        return None
    col_names = [col.name for col in cur.description]
    return dict(zip(col_names, row))

def get_user_by_id(id):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (id,))
    row = cur.fetchone()
    if not row:
        return None
    col_names = [col.name for col in cur.description]
    return dict(zip(col_names, row))

def get_user_data_for_login(user_id):
    cur = db.cursor()
    cur.execute("SELECT id, password, name FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    if not row:
        return None
    return {'id': row[0], 'password': row[1], 'name': row[2]}

def check_if_user_exists(user_id):
    cur = db.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    if not row:
        return False
    return True

def verify_user(user_id):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET groups=%s, verified=TRUE WHERE id = %s""", (["registered"], user_id,))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"verify_user() failed: {e.pgerror}")
        return e

def verify_user_by_mail(mail):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET groups=%s, verified=TRUE WHERE email = %s""", (["registered"], mail,))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"verify_user() failed: {e.pgerror}")
        return e

def just_verify_user_by_id(ide):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET verified=TRUE WHERE id = %s""", (ide,))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"verify_user() failed: {e.pgerror}")
        return e

def set_verification_email_sent(date_time, email):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET verification_email_sent=%s WHERE id = %s""", (date_time, id))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"set_verification_email_sent() failed: {e.pgerror}")
        return e


def set_last_login(date_time, ide):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET last_login=%s WHERE id = %s""", (date_time, ide))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"set_last_login() failed: {e.pgerror}")
        return e


def get_verification_email_sent(user_email):
    cur = db.cursor()
    cur.execute("SELECT verification_email_sent FROM users WHERE email = %s", (user_email,))
    row = cur.fetchone()
    if not row:
        return None
    return row[0]


def get_user_name(user_email):
    cur = db.cursor()
    cur.execute("SELECT name FROM users WHERE email = %s", (user_email,))
    row = cur.fetchone()
    if not row:
        return None
    return row[0]

def set_new_password(new_password, id):
    try:
        cur = db.cursor()
        cur.execute("""UPDATE users SET password=%s WHERE id = %s""", (new_password, id))
        db.commit()
        cur.close()
    except psycopg2.Error as e:
        print(f"set_new_password() failed: {e.pgerror}")
        return e


def set_api_v1_token(ide, token):
    cur = db.cursor()
    cur.execute("UPDATE users SET api_token = %s WHERE id = %s", (token, ide,))
    return True

def get_users_admin():
    cur = db.cursor()
    cur.execute("SELECT email, groups, id, org, api_token, verified, verification_email_sent, last_login FROM users ORDER BY email")
    row = cur.fetchall()
    if not row:
        return None
    return row

def set_new_roles(ide, roles):
    cur = db.cursor()
    cur.execute("UPDATE users SET groups = %s WHERE id = %s", (roles, ide,))
    return True

def delete_user(ide):
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (ide,))
    return True