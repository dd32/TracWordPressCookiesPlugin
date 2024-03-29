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
#   auth_key = auth_keyauth_keyauth_keyauth_keyauth_keyauth_keyauth_keyauth_key
#   auth_salt = auth_saltauth_saltauth_saltauth_saltauth_saltauth_saltauth_salt
#   db = mysql://wordpress:password@localhost/wordpress
#   wp_users = wp_users
#
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
        if len(elements) != 3:
            return None

        username, expiration, mac = elements
        if int(expiration) < time.time():
            return None

        user_pass = self.get_user_pass(username)
        if not user_pass:
            return None

        pass_frag = user_pass[8:12]
        key = self.wp_hash(username + pass_frag + '|' + expiration, 'auth')
        valid_mac = hmac.new(key, username + '|' + expiration, hashlib.md5).hexdigest()
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

    def get_user_pass(self, username):
        # Sanitize username with strict whitelist from sanitize_user()
        username = re.sub('[^a-zA-Z0-9 _.@-]', '', username)

        return self._get_user_pass(username)

    def _get_user_pass(self, username):
        db = self.env.config.get('wordpress', 'db')
        table = self.env.config.get('wordpress', 'wp_users')

        r = urlparse(db)
        conn = MySQLConnection(r.path, self.log, user=r.username, password=r.password, host=r.hostname)

        cursor = conn.cursor()
        cursor.execute("SELECT user_pass, user_email FROM " + conn.quote(table) + " WHERE user_login = %s", [username])
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user:
            user_pass, user_email = user
            # Synchronize the user's email address while we have the chance.
            session = DetachedSession(self.env, username)
            session.set('email', user_email)
            session.save()
            return user_pass
        return user
