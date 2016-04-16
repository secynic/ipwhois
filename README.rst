=======
ipwhois
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

RDAP is the recommended query method as of v0.11.0. Please see the
`upgrade info <https://github.com/secynic/ipwhois/blob/master/RDAP.rst
#upgrading-from-0-10-to-0-11>`_.

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Features
========

* Parses a majority of whois fields in to a standard dictionary
* IPv4 and IPv6 support
* Referral whois support
* Supports RDAP queries (recommended method, more detailed information)
* Proxy support for RDAP queries
* Recursive network parsing for IPs with parent/children networks listed
* Python 2.6+ and 3.3+ supported
* Useful set of utilities
* BSD license
* 100% core code coverage (See '# pragma: no cover' for exclusions)
* Human readable field translations
* Full CLI for IPWhois with optional human readable and ANSI console output.

Links
=====

Documentation
-------------

https://secynic.github.io/ipwhois

Examples
--------

https://github.com/secynic/ipwhois/tree/master/ipwhois/examples

Github
------

https://github.com/secynic/ipwhois

Pypi
----

https://pypi.python.org/pypi/ipwhois

Changes
-------

https://secynic.github.io/ipwhois/CHANGES.html

Dependencies
============

Python 2.6, 2.7::

    dnspython
    ipaddr

Python 3.3+::

    dnspython3

Installing
==========

Latest version from PyPi::

	pip install --upgrade ipwhois

Latest version from GitHub::

	pip install -e git+https://github.com/secynic/ipwhois@master#egg=ipwhois

Firewall Ports
==============

ipwhois needs some outbound firewall ports opened from your host/server.

:ASN (DNS): 53/tcp
:ASN (Whois): 43/tcp
:ASN (HTTP):
    80/tcp

    443/tcp (Pending)
:RDAP (HTTP):
    80/tcp

    443/tcp (Pending)
:Legacy Whois: 43/tcp
:Get Host: 43/tcp

API
===

RDAP (HTTP)
-----------

IPWhois.lookup_rdap() is the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

RDAP documentation:
https://secynic.github.io/ipwhois/RDAP.html

Legacy Whois
------------

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Legacy Whois documentation:
https://secynic.github.io/ipwhois/WHOIS.html

Utilities
---------

Utilities documentation:
https://secynic.github.io/ipwhois/UTILS.html

IP Reputation Support
=====================

This feature is under consideration. Take a look at TekDefense's Automater:

`TekDefense-Automater <https://github.com/1aN0rmus/TekDefense-Automater>`_

Domain Support
==============

There are no plans for domain whois support in this project.

Look at Sven Slootweg's
`python-whois <https://github.com/joepie91/python-whois>`_ for a library with
domain support.

Special Thanks
==============

Thank you JetBrains for the PyCharm open source support!
