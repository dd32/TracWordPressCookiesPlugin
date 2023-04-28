from setuptools import find_packages, setup

setup(
    name = 'WordPressCookies',
    version = '0.2-transitional-cookies',
    author = 'Jon Cave',
    description = 'Authentication plugin to read WordPress auth cookies. Supports WordPress Sessions with the wp_user_sessions table, and session-less cookies.',
    license = 'GPLv2+',

    packages = find_packages(exclude=['*.tests*']),
    entry_points = {
        'trac.plugins': [
            'wpcookies = wpcookies.auth',
        ],
    },
)
