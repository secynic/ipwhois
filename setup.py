# Filename: setup.py

from setuptools import setup
import io

NAME = 'ipwhois'
VERSION = '1.2.0'
AUTHOR = 'Philip Hane'
AUTHOR_EMAIL = 'secynic@gmail.com'
DESCRIPTION = 'Retrieve and parse whois data for IPv4 and IPv6 addresses.'
KEYWORDS = ' '.join([
    'Python',
    'WHOIS',
    'RWhois',
    'Referral Whois',
    'ASN',
    'IP Address',
    'IP',
    'IPv4',
    'IPv6',
    'IETF',
    'REST',
    'Arin',
    'Ripe',
    'Apnic',
    'Lacnic',
    'Afrinic',
    'NIC',
    'National Information Center',
    'RDAP',
    'RIR',
    'Regional Internet Registry'
    'NIR',
    'National Internet Registry',
    'ASN origin',
    'Origin'
])

README = io.open(file='README.rst', mode='r', encoding='utf-8').read()
CHANGES = io.open(file='CHANGES.rst', mode='r', encoding='utf-8').read()
LONG_DESCRIPTION = '\n\n'.join([README, CHANGES])
LICENSE = 'BSD'

URL = 'https://github.com/secynic/ipwhois'
DOWNLOAD_URL = 'https://github.com/secynic/ipwhois/tarball/master'
CLASSIFIERS = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'Intended Audience :: Information Technology',
    'Intended Audience :: Science/Research',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Topic :: Internet',
    'Topic :: Software Development',
]

PACKAGES = ['ipwhois']

PACKAGE_DATA = {'ipwhois': ['data/*.xml', 'data/*.csv']}

INSTALL_REQUIRES = ['dnspython<=3.0.0', 'ipaddr==2.2.0;python_version<"3.3"']

setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    keywords=KEYWORDS,
    long_description=LONG_DESCRIPTION,
    license=LICENSE,
    url=URL,
    download_url=DOWNLOAD_URL,
    classifiers=CLASSIFIERS,
    packages=PACKAGES,
    package_data=PACKAGE_DATA,
    install_requires=INSTALL_REQUIRES,
    scripts=['ipwhois/scripts/ipwhois_cli.py',
             'ipwhois/scripts/ipwhois_utils_cli.py']
)
