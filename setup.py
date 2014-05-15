# Filename: setup.py

from distutils.core import setup
import sys

NAME = 'ipwhois'
VERSION = "0.8.2"
AUTHOR = "Philip Hane"
AUTHOR_EMAIL = "secynic AT gmail DOT com"
DESCRIPTION = "IP Whois Resolution and Parsing"
KEYWORDS = [
    "Python",
    "WHOIS",
    "ASN",
    "IP Address",
    "IP",
    "IPv4",
    "IPv6",
    "IETF",
    "REST",
    "Arin",
    "Ripe",
    "Apnic",
    "Lacnic",
    "Afrinic",
    "NIC"
]

LONG_DESCRIPTION = '\n\n'.join([open('README.rst').read(),
                                open('CHANGES.rst').read()])

LICENSE = open('LICENSE.txt').read()

URL = "https://github.com/secynic/ipwhois"
DOWNLOAD_URL = "https://github.com/secynic/ipwhois/tarball/master"
CLASSIFIERS = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: BSD License",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 2.6",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.3",
    "Programming Language :: Python :: 3.4",
    "Topic :: Internet",
    "Topic :: Software Development",
]

PACKAGES = ['ipwhois']

PACKAGE_DATA = {'ipwhois': ['data/*.xml']}

INSTALL_REQUIRES = []
if sys.version_info >= (3,):
    INSTALL_REQUIRES.append("dnspython3")
else:
    INSTALL_REQUIRES.append("dnspython")

if sys.version_info < (3, 3,):
    INSTALL_REQUIRES.append("ipaddr")

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
    install_requires=INSTALL_REQUIRES
)
