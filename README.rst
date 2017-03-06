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
.. image:: https://img.shields.io/badge/python-2.6%2C%202.7%2C%203.3+-blue.svg
    :target: https://docs.python.org
.. image:: https://img.shields.io/badge/docs-release%20v0.15.1-green.svg?style=flat
    :target: https://ipwhois.readthedocs.io/en/v0.15.1
.. image:: https://readthedocs.org/projects/pip/badge/?version=latest
    :target: https://ipwhois.readthedocs.io/en/latest
.. image:: https://img.shields.io/badge/docs-dev-yellow.svg?style=flat
    :target: https://ipwhois.readthedocs.io/en/dev

Summary
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

.. attention::

    The IPWhois argument allow_permutations and the lookup argument asn_alts
    have been deprecated in favor of new argument asn_methods.

.. attention::

    NIR (National Internet Registry) lookups are enabled by default as of
    v0.14.0. This is currently only performed for JPNIC and KRNIC addresses.
    To disable, set inc_nir=False in your IPWhois.lookup_*() query.

.. attention::

    The 'nets' -> 'emails' key in IPWhois.lookup_whois() was changed from
    a '\\n' separated string to a list in v0.14.0.

.. important::

    RDAP (IPWhois.lookup_rdap()) is the recommended query method as of v0.11.0.
    If you are upgrading from earlier than 0.11.0, please see the
    `upgrade info <https://ipwhois.readthedocs.io/en/v0.15.1/RDAP.html
    #upgrading-from-0-10-to-0-11>`_.

.. note::

    If you are experiencing latency issues, it is likely related to rate
    limiting. Profiling the tests, I see most time spent attributed to network
    latency. Rate limiting is based on your source IP, which may be a problem
    with multiple users behind the same proxy. Additionally, LACNIC implements
    aggressive rate limiting. Bulk query optimization is on the roadmap
    (https://github.com/secynic/ipwhois/issues/134)

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
* BSD license
* 100% core code coverage (See '# pragma: no cover' for exclusions)
* Human readable field translations
* Full CLI for IPWhois with optional ANSI colored console output.

Links
=====

Documentation
-------------

Release v0.15.1
^^^^^^^^^^^^^^^

https://ipwhois.readthedocs.io/en/v0.15.1

GitHub master
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

https://pypi.python.org/pypi/ipwhois

Changes
-------

https://ipwhois.readthedocs.io/en/latest/CHANGES.html

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
|                    |        | DNS lookups to Cymru fail. *WARNING*          |
|                    |        | deprecated in favor of new argument           |
|                    |        | asn_methods.                                  |
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

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

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
