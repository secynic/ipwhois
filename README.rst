=======
ipwhois
=======

.. image:: https://travis-ci.org/secynic/ipwhois.svg?branch=master
    :target: https://travis-ci.org/secynic/ipwhois
.. image:: https://coveralls.io/repos/github/secynic/ipwhois/badge.svg?branch=
    master
    :target: https://coveralls.io/github/secynic/ipwhois?branch=master
.. image:: https://img.shields.io/badge/license-BSD%202--Clause-blue.svg
    :target: https://github.com/secynic/ipwhois/tree/master/LICENSE.txt
.. image:: https://img.shields.io/badge/python-2.6%2C%202.7%2C%203.3%2C%203.4
    %2C%203.5-blue.svg

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

.. attention::

    RDAP (IPWhois.lookup_rdap()) is the recommended query method as of v0.11.0.
    Please see the
    `upgrade info <https://github.com/secynic/ipwhois/blob/master/RDAP.rst
    #upgrading-from-0-10-to-0-11>`_.

.. attention::

    NIR (National Internet Registry) lookups are now enabled by default.
    This is currently only performed for JPNIC and KRNIC addresses.
    To disable, set inc_nir=False in your IPWhois.lookup_*() query.

.. warning::

    The 'nets' -> 'emails' key in IPWhois.lookup_whois() has been changed from
    a '\\n' separated string to a list.

Features
========

* Parses a majority of whois fields in to a standard dictionary
* IPv4 and IPv6 support
* Referral whois support
* Supports RDAP queries (recommended method, see:
  https://tools.ietf.org/html/rfc7483)
* Proxy support for RDAP queries
* Recursive network parsing for IPs with parent/children networks listed
* Python 2.6+ and 3.3+ supported
* Useful set of utilities
* BSD license
* 100% core code coverage (See '# pragma: no cover' for exclusions)
* Human readable field translations
* Full CLI for IPWhois with optional ANSI colored console output.

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

Dev version from GitHub::

    pip install -e git+https://github.com/secynic/ipwhois@dev#egg=ipwhois

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

IPWhois (main class)
--------------------

ipwhois.IPWhois is the base class for wrapping RDAP and Legacy Whois lookups.
Instantiate this object, then call one of the lookup functions:

`RDAP (HTTP) - IPWhois.lookup_rdap() <#rdap-http>`_
OR
`Legacy Whois - IPWhois.lookup_whois() <#legacy-whois>`_

Input
^^^^^

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| address            | String | An IPv4 or IPv6 address as a string, integer, |
|                    |        | IPv4Address, or IPv6Address.                  |
+--------------------+--------+-----------------------------------------------+
| timeout            | Int    | The default timeout for socket connections    |
|                    |        | in seconds.                                   |
+--------------------+--------+-----------------------------------------------+
| proxy_opener       | Object | The urllib.request.OpenerDirector request for |
|                    |        | proxy support or None.                        |
+--------------------+--------+-----------------------------------------------+
| allow_permutations | Bool   | Allow net.Net() to use additional methods if  |
|                    |        | DNS lookups to Cymru fail.                    |
+--------------------+--------+-----------------------------------------------+

RDAP (HTTP)
-----------

IPWhois.lookup_rdap() is the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

RDAP documentation:

https://secynic.github.io/ipwhois/RDAP.html

https://github.com/secynic/ipwhois/blob/master/RDAP.rst

Legacy Whois
------------

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Legacy Whois documentation:

https://secynic.github.io/ipwhois/WHOIS.html

https://github.com/secynic/ipwhois/blob/master/WHOIS.rst

Utilities
---------

Utilities documentation:

https://secynic.github.io/ipwhois/UTILS.html

https://github.com/secynic/ipwhois/blob/master/UTILS.rst

Scripts
-------

CLI documentation:

https://secynic.github.io/ipwhois/CLI.html

https://github.com/secynic/ipwhois/blob/master/CLI.rst

Contributing
============

https://secynic.github.io/ipwhois/CONTRIBUTING.html

https://github.com/secynic/ipwhois/blob/master/CONTRIBUTING.rst

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
