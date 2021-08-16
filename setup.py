from setuptools import find_packages, setup

setup(
    name = 'WordPressCookies',
    version = '0.1',
    author = 'Jon Cave',
    description = 'Authentication plugin to read WordPress auth cookies',
    license = 'GPLv2+',

    packages = find_packages(exclude=['*.tests*']),
    entry_points = {
        'trac.plugins': [
            'wpcookies = wpcookies.auth',
        ],
    },
)
