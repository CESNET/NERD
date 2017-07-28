# NERDweb module for handling user database
import string
import random
import os.path
import psycopg2
import sys
from flask import flash

__all__ = ['get_user_info']

def init(config, cfg_dir):
    """
    Initialize user database wrapper.
    """
    global users, acl, cfg, db
    cfg = config
    
    acl_cfg_file = os.path.join(cfg_dir, config.get('acl_config'))

    # Create database connection
    db = psycopg2.connect(database=config.get('userdb.dbname', 'nerd'),
                          user=config.get('userdb.dbuser', 'nerd'),
                          password=config.get('userdb.dbpassword', None))
    db.autocommit = True # don't use transactions, every action have immediate effect
    
    # Load "acl" file
    # Mapping of "resource_id" to two sets of groups: "groups_allow", "groups_deny".
    # To access a resource, a user must be in at least one group of "groups_allow"
    # and must not be in any of "groups_deny".
    # Format (one resource per line):
    # <resource_id> <comma_separated_list_of_groups_allow>[;<comma_separated_list_of_groups_deny>]
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


# ***** Access control functions *****

def get_user_groups(full_id):
    cur = db.cursor()
    cur.execute("SELECT groups FROM users WHERE id = %s", (full_id,))
    row = cur.fetchone()
    if not row:
        return set(['notregistered']) # Unknown user
    return set(row[0])


def get_ac_func(user_groups):
    """Return a function for testing access permissions of a specific user."""
    def ac(resource):
        """"
        Access control test - check if current user has access to given resource.
        """
        if resource in acl and acl[resource][0] & user_groups and not acl[resource][1] & user_groups:
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
      login_type, id, fullid, groups, name, email, org, api_id, api_secret
      `----------v---------'  `-----------v------------------------------'
            from session            from database (find by 'fullid')
    """
    # Get ID of user logged in
    if 'user' in session:
        user = session['user'].copy() # should contain 'id', 'login_type' and optionally 'name'
        user['fullid'] = user['login_type'] + ':' + user['id']
    elif cfg.testing:
        user = {
            'login_type': '',
            'id': 'test_user',
            'fullid': 'test_user',
        }
    else:
        # No user logged in
        return None, lambda x: False
    
    # Get user info from DB
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user['fullid'],))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    if not row:
        # User not found in DB = user is authenticated (e.g. via shibboleth) but has no account yet
        user['groups'] = set(['notregistered'])
        return user, get_ac_func(user['groups'])
    
    # Put all fields from DB into 'user' dict
    col_names[0] = 'fullid' # rename column 'id' to 'fullid', other columns can be mapped directly as they are in DB
    user.update(zip(col_names, row))
    
    # Convert user.groups from array/list to set
    user['groups'] = set(user['groups'])
    
    # Convert user.name from utf8 (TODO: this can be probably removed when we start using python3)
    if isinstance(user['name'], bytes):
        user['name'] = user['name'].decode('utf-8') if user['name'] else None
    
    ac = get_ac_func(user['groups'])
    return user, ac

def authenticate_with_token(token):
    user = {}
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE api_token = %s", (token,))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    if not row:
        return None, lambda x: False

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
