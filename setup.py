from setuptools import find_packages, setup

setup(
    name = 'WordPressCookies',
    version = '0.3',
    author = 'the WordPress team',
    description = 'Authentication plugin to read WordPress auth cookies. Only supports WordPress Sessions with the wp_user_sessions table.',
    license = 'GPLv2+',

    packages = find_packages(exclude=['*.tests*']),
    entry_points = {
        'trac.plugins': [
            'wpcookies = wpcookies.auth',
        ],
    },
)
