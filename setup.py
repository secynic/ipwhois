# Filename: setup.py

from distutils.core import setup
import ipwhois

NAME = 'ipwhois'
VERSION = ipwhois.__version__
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
]

README = open('README.txt').read()

LICENSE = open('LICENSE.txt').read()

URL = "https://github.com/secynic/ipwhois"
DOWNLOAD_URL = "https://pypi.python.org/packages/source/p/ipwhois"
CLASSIFIERS = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: BSD License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.3",
    "Topic :: Internet",
    "Topic :: Software Development",
]

PACKAGES = ['ipwhois']

PACKAGE_DATA = {'ipwhois': ['*.xml']}

INSTALL_REQUIRES = [
    "dnspython3"
]

setup(
    name=NAME,
    version=VERSION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    keywords=KEYWORDS,
    long_description=README,
    license=LICENSE,
    url=URL,
    download_url=DOWNLOAD_URL,
    classifiers=CLASSIFIERS,
    packages=PACKAGES,
    package_data = PACKAGE_DATA,
    install_requires=INSTALL_REQUIRES
)