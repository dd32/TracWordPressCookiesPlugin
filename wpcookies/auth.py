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
#   wp_user_sessions = wp_user_sessions
#
# NOTE: For wp_user_sessions, See https://github.com/WordPress/wporg-mu-plugins/pull/345
# TODO: raise exception on missing configuration
# TODO: cache _get_user_pass (but not across requests)

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

        user_pass, user_email, session_expiration = self.get_user_pass(username,token)
        if not user_pass:
            return None

        # Validate that the user session is still valid
        if int(session_expiration) < time.time():
            return None

        pass_frag = user_pass[8:12]
        key = self.wp_hash(username + '|' + pass_frag + '|' + expiration + '|' + token, 'auth')
        valid_mac = hmac.new(key, username + '|' + expiration + '|' + token, hashlib.sha256).hexdigest()
        if valid_mac != mac:
            return None

        return username

    def wp_hash(self, data, scheme = 'auth'):
        salt = self.wp_salt(scheme)
        return hmac.new(salt, data, hashlib.md5).hexdigest()

    def wp_salt(self, scheme = 'auth'):
        key = self.env.config.get('wordpress', scheme + '_key')
        salt = self.env.config.get('wordpress', scheme + '_salt')
        return key + salt

    def get_user_pass(self, username, token):
        # Sanitize username with strict whitelist from sanitize_user()
        username = re.sub('[^a-zA-Z0-9 _.@-]', '', username)

        # Generate the token verifier
        verifier = hashlib.sha256(token).hexdigest()

        return self._get_user_pass(username,verifier)

    def _get_user_pass(self, username, verifier):
        db = self.env.config.get('wordpress', 'db')
        table = self.env.config.get('wordpress', 'wp_users')
        session_table = self.env.config.get('wordpress', 'wp_user_sessions')

        r = urlparse(db)
        conn = MySQLConnection(r.path, self.log, user=r.username, password=r.password, host=r.hostname)

        cursor = conn.cursor()
        cursor.execute("SELECT user_pass, user_email, s.expiration FROM " + conn.quote(table) + " u JOIN " + conn.quote(session_table) + " s ON s.user_id = u.ID WHERE u.user_login = %s AND s.verifier = %s LIMIT 1", [username, verifier])
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            user_pass, user_email = user[:2]
            # Synchronize the user's email address while we have the chance.
            session = DetachedSession(self.env, username)
            session.set('email', user_email)
            session.save()
        return user
