=======
ipwhois
=======

.. image:: https://travis-ci.org/secynic/ipwhois.svg?branch=master
    :target: https://travis-ci.org/secynic/ipwhois
.. image:: https://coveralls.io/repos/github/secynic/ipwhois/badge.svg?branch=
    master
    :target: https://coveralls.io/github/secynic/ipwhois?branch=master
.. image:: https://codeclimate.com/github/secynic/ipwhois/badges/issue_count.svg
   :target: https://codeclimate.com/github/secynic/ipwhois
.. image:: https://img.shields.io/badge/license-BSD%202--Clause-blue.svg
    :target: https://github.com/secynic/ipwhois/tree/master/LICENSE.txt
.. image:: https://img.shields.io/badge/python-2.6%2C%202.7%2C%203.3+-blue.svg
    :target: https://docs.python.org
.. image:: https://img.shields.io/badge/docs-latest-green.svg?style=flat
    :target: https://ipwhois.readthedocs.io/en/latest
.. image:: https://img.shields.io/badge/docs-dev-yellow.svg?style=flat
    :target: https://ipwhois.readthedocs.io/en/dev

Summary
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

.. note::

    If you are experiencing latency issues, it is likely related to rate
    limiting. Rate limiting is based on your source IP, which may be a problem
    with multiple users behind the same proxy. Additionally, LACNIC implements
    aggressive rate limiting. Experimental bulk query support is new as of
    v1.0.0.

Features
========

* Parses a majority of whois fields in to a standard dictionary
* IPv4 and IPv6 support
* Supports RDAP queries (recommended method, see:
  https://tools.ietf.org/html/rfc7483)
* Proxy support for RDAP queries
* Supports legacy whois protocol queries
* Referral whois support for legacy whois protocol
* Recursive network parsing for IPs with parent/children networks listed
* National Internet Registry support for JPNIC and KRNIC
* Supports IP to ASN and ASN origin queries
* Python 2.6+ and 3.3+ supported
* Useful set of utilities
* Experimental bulk query support
* BSD license
* 100% core code coverage (See '# pragma: no cover' for exclusions)
* Human readable field translations
* Full CLI for IPWhois with optional ANSI colored console output.

Links
=====

Documentation
-------------

GitHub latest
^^^^^^^^^^^^^

https://ipwhois.readthedocs.io/en/latest

GitHub dev
^^^^^^^^^^

https://ipwhois.readthedocs.io/en/dev

Examples
--------

https://github.com/secynic/ipwhois/tree/master/ipwhois/examples

Github
------

https://github.com/secynic/ipwhois

Pypi
----

https://pypi.org/project/ipwhois

Changes
-------

https://ipwhois.readthedocs.io/en/latest/CHANGES.html

Upgrade Notes
-------------

https://ipwhois.readthedocs.io/en/latest/UPGRADING.html

Dependencies
============

Python 2.6::

    dnspython
    ipaddr
    argparse (required only for CLI)

Python 2.7::

    dnspython
    ipaddr

Python 3.3+::

    dnspython

Installing
==========

Latest release from PyPi::

    pip install --upgrade ipwhois

GitHub - Stable::

    pip install -e git+https://github.com/secynic/ipwhois@master#egg=ipwhois

GitHub - Dev::

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
:NIR (HTTP):
    80/tcp

    443/tcp (KRNIC)
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
| address            | str    | An IPv4 or IPv6 address as a string, integer, |
|                    |        | IPv4Address, or IPv6Address.                  |
+--------------------+--------+-----------------------------------------------+
| timeout            | int    | The default timeout for socket connections    |
|                    |        | in seconds. Defaults to 5.                    |
+--------------------+--------+-----------------------------------------------+
| proxy_opener       | object | The urllib.request.OpenerDirector request for |
|                    |        | proxy support or None.                        |
+--------------------+--------+-----------------------------------------------+
| allow_permutations | bool   | Allow net.Net() to use additional methods if  |
|                    |        | DNS lookups to Cymru fail. *WARNING*          |
|                    |        | deprecated in favor of new argument           |
|                    |        | asn_methods. Defaults to True.                |
+--------------------+--------+-----------------------------------------------+

RDAP (HTTP)
-----------

IPWhois.lookup_rdap() is the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

RDAP documentation:

https://ipwhois.readthedocs.io/en/latest/RDAP.html

Legacy Whois
------------

Legacy Whois documentation:

https://ipwhois.readthedocs.io/en/latest/WHOIS.html

National Internet Registries
----------------------------

This library now supports NIR lookups for JPNIC and KRNIC. Previously, Whois
and RDAP data for Japan and South Korea was restricted. NIR lookups scrape
these national registries directly for the data restricted from regional
internet registries. NIR queries are enabled by default via the inc_nir
argument in the IPWhois.lookup_*() functions.

https://ipwhois.readthedocs.io/en/latest/NIR.html

Autonomous System Numbers
-------------------------

This library now supports ASN origin lookups via Whois and HTTP.

IP ASN functionality was moved to its own parser API (IPASN).

There is no CLI for these yet.

https://ipwhois.readthedocs.io/en/latest/ASN.html

Utilities
---------

Utilities documentation:

https://ipwhois.readthedocs.io/en/latest/UTILS.html

Scripts
-------

CLI documentation:

https://ipwhois.readthedocs.io/en/latest/CLI.html

Experimental Functions
----------------------

.. caution::

    Functions in experimental.py contain new functionality that has not yet
    been widely tested. Bulk lookup support contained here can result in
    significant system/network resource utilization. Additionally, abuse of
    this functionality may get you banned by the various services queried by
    this library. Use at your own discretion.

Experimental functions documentation:

https://ipwhois.readthedocs.io/en/latest/EXPERIMENTAL.html

Contributing
============

https://ipwhois.readthedocs.io/en/latest/CONTRIBUTING.html

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

Thank you JetBrains for the `PyCharm <https://www.jetbrains.com/pycharm/>`_
open source support!

Thank you Chris Wells (`@cdubz <https://github.com/cdubz>`_) for your
extensive testing on the experimental functions!

Last but not least, thank you to all the issue submitters and contributors.
