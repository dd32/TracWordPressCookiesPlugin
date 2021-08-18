#
# Trac authentication using WordPress cookies.
#
# Also synchronizes the user's email address from the same wp_users table.
#
# Implements the auth cookie validation code from wp-includes/pluggable.php.
# Requires several configuration settings to be added to a "wordpress" section
# in trac.ini, for example:
#
#   [wordpress]
#   auth_cookie = wordpress
#   auth_key = q5y+wQ6)Nc@86B#00KJ:rTz6z59/=W*AJlxpr}.B%)gNYr#pD/;)X7]3B6W1R!dL
#   auth_salt = (3kfwOE-i)Oaq8q7@HTwdZ1Hi{F{=*s+O>ZCbsyMT+,^s<7XZq;T{|g{twM^6XlR
#   db = mysql://wordpress:cbi2jMEVDYWynaJ@localhost/wordpress
#   wp_users = wp_users
#   wp_usermeta = (Will be guessed based on wp_users if not specified)
#
# TODO: raise exception on missing configuration

from trac.core import *
from trac.db.mysql_backend import MySQLConnection
from trac.web.api import IAuthenticator
from trac.web.session import DetachedSession

import hashlib
import hmac
import re
import time
from urllib import unquote_plus
from urlparse import urlparse

class WordPressCookieAuthenticator(Component):
    implements(IAuthenticator)

    def authenticate(self, req):
        cookie_name = self.env.config.get('wordpress', 'auth_cookie')
        if not cookie_name in req.incookie:
            return None

        cookie = unquote_plus(req.incookie[cookie_name].value)
        elements = cookie.split('|')
        if len(elements) != 4:
            return None

        username, expiration, token, mac = elements
        if int(expiration) < time.time():
            return None

        # Sanitize username with strict whitelist from sanitize_user()
        username = re.sub('[^a-zA-Z0-9 _.@-]', '', username)

        user = self.get_wp_user(username)
        if not user:
            return None

        pass_frag = user.user_pass[8:12]
        key = self.wp_hash(username + '|' + pass_frag + '|' + expiration + '|' + token, 'auth')
        valid_mac = hmac.new(key, username + '|' + expiration + '|' + token, hashlib.sha256).hexdigest()
        if valid_mac != mac:
            return None

        # Verify against the user sessions.
        session_ok = user.validate_session(token)
        if not session_ok:
            return None

        return username

    def wp_hash(self, data, scheme = 'auth'):
        salt = self.wp_salt(scheme)
        return hmac.new(salt, data, hashlib.md5).hexdigest()

    def wp_salt(self, scheme = 'auth'):
        key = self.env.config.get('wordpress', scheme + '_key')
        salt = self.env.config.get('wordpress', scheme + '_salt')
        return key + salt

    def get_wp_user(self,username):
        db = self.env.config.get('wordpress', 'db')
        table = self.env.config.get('wordpress', 'wp_users')
        metatable = self.env.config.get('wordpress', 'wp_usermeta');
        if not metatable:
            metatable = table.replace( '_users', '_usermeta', 1 )

        r = urlparse(db)
        conn = MySQLConnection(r.path, self.log, user=r.username, password=r.password, host=r.hostname)

        cursor = conn.cursor()
        cursor.execute("SELECT user_login, user_pass, user_email, meta_value FROM " + conn.quote(table) + " u LEFT JOIN " + conn.quote(metatable) + " um ON u.ID = um.user_id AND um.meta_key = 'session_tokens' WHERE user_login = %s", [username])
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            user = WP_User( user )
            # Synchronize the user's email address while we have the chance.
            user.sync_email( self.env )

        return user;

class WP_User(object):
    def __init__(self,user):
        self.username, self.user_pass, self.user_email, sessions_raw = user

        try:
            self.sessions = self.unserialize( sessions_raw )[0]
        except:
            # Ignore the error, just don't process the sessions.
            self.sessions = {}

    def sync_email(self,env):
        trac_session = DetachedSession(env, self.username)
        trac_session.set('email', self.user_email)
        trac_session.save()

    def validate_session(self, token):
        '''
            Validate a session is valid.
        '''
        hash = hashlib.sha256(token).hexdigest()
        if not hash in self.sessions:
            return None

        # Check the session hasn't expired.
        if int(self.sessions[ hash ]['expiration']) < time.time():
            return None

        return True

    def unserialize(self, s):
        ''' Unserialize a single value from the head of a serialized string.

        Only supports arrays, strings, and integers.

        Alternatively, use the pip unserialize package and replace this method:
            pip install phpserialize
            from phpserialize import unserialize

        Returns value, tail
        '''
        if s.startswith('i:'):
            value, s = s[2:].split(';', 1)
            return int(value), s
        elif s.startswith('s:'):
            s = s[2:]
            length, s = s.split(':', 1)
            length = int(length)
            if length > len(s) - 3:
                raise ValueError('String length %d is too long for serialized data, length %d.' % (l, len(s)))
            elif s[0] != '"':
                raise ValueError('Missing opening quote after string, found %r.' % (s[0],))
            elif s[length+1:length+3] != '";':
                raise ValueError('Missing closing quote and semi-colon after string, found %r.' % (s[length+1:length+3],))
            return s[1:length+1], s[length+3:]
        elif s.startswith('a:'):
            s = s[2:]
            length, s = s.split(':', 1)
            length = int(length)
            if s[0] != '{':
                raise ValueError('Missing opening curly brace before array contents, found %r.' % (s[i+2],))
            s = s[1:]
            array = dict()
            for i in xrange(0, length):
                key, s = self.unserialize(s)
                value, s = self.unserialize(s)
                array[key] = value
            if s[0:1] != '}':
                raise ValueError('Missing closing curly brace and semicolon after array contents, found %r.' % (s[0:2],))
            return array, s[1:]
        else:
            raise ValueError('Cannot unserialize %r.' % (s,))
