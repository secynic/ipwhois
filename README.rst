=======
ipwhois
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

RDAP is the recommended query method as of v0.11.0. Please see the
`upgrade info <#upgrading-from-0-10-to-0-11>`_.

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

Usage Examples
==============

RDAP (HTTP)
-----------

Basic usage
^^^^^^^^^^^

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_rdap(depth=1)
    >>>> pprint(results)

    {
    'asn': '15169',
    'asn_cidr': '74.125.225.0/24',
    'asn_country_code': 'US',
    'asn_date': '2007-03-13',
    'asn_registry': 'arin',
    'entities': [u'GOGL'],
    'network': {
        'cidr': '74.125.0.0/16',
        'country': None,
        'end_address': '74.125.255.255',
        'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2012-02-24T09:44:34-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2007-03-13T12:09:54-04:00'
            }
        ],
        'handle': u'NET-74-125-0-0-1',
        'ip_version': u'v4',
        'links': [
            u'https://rdap.arin.net/registry/ip/074.125.000.000',
            u'https://whois.arin.net/rest/net/NET-74-125-0-0-1'
        ],
        'name': u'GOOGLE',
        'notices': [{
            'description': u'By using the ARIN RDAP/Whois service, you are
                agreeing to the RDAP/Whois Terms of Use',
            'links': [u'https://www.arin.net/whois_tou.html'],
            'title': u'Terms of Service'
        }],
        'parent_handle': u'NET-74-0-0-0-0',
        'raw': None,
        'remarks': None,
        'start_address': '74.125.0.0',
        'status': None,
        'type': None
    },
    'objects': {
        u'ABUSE5250-ARIN': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': [{
                    'type': None,
                    'value': u'network-abuse@google.com'
                }],
                'kind': u'group',
                'name': u'Abuse',
                'phone': [{
                    'type': [u'work', u'voice'],
                    'value': u'+1-650-253-0000'
                }],
                'role': None,
                'title': None
            },
            'entities': None,
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-11-06T15:36:35-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2015-11-06T15:36:35-05:00'
            }],
            'events_actor': None,
            'handle': u'ABUSE5250-ARIN',
            'links': [
                u'https://rdap.arin.net/registry/entity/ABUSE5250-ARIN',
                u'https://whois.arin.net/rest/poc/ABUSE5250-ARIN'
            ],
            'notices': [{
                'description': u'By using the ARIN RDAP/Whois service, you are
                    agreeing to the RDAP/Whois Terms of Use',
                'links': [u'https://www.arin.net/whois_tou.html'],
                'title': u'Terms of Service'}],
            'raw': None,
            'remarks': [{
                'description': u'Please note that the recommended way to file
                    abuse complaints are located in the following links.\r\n\r
                    \nToreport abuse and illegal activity:
                    https://www.google.com/intl/en_US/goodtoknow/online-safety
                    /reporting-abuse/ \r\n\r\nFor legal requests:
                    http://support.google.com/legal \r\n\r\n
                    Regards,\r\nThe Google Team',
                'links': None,
                'title': u'Registration Comments'
            }],
            'roles': None,
            'status': [u'validated']
        },
        u'GOGL': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': None,
                'kind': u'org',
                'name': u'Google Inc.',
                'phone': None,
                'role': None,
                'title': None
            },
            'entities': [u'ABUSE5250-ARIN', u'ZG39-ARIN'],
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-11-06T15:45:54-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2000-03-30T00:00:00-05:00'
            }],
            'events_actor': None,
            'handle': u'GOGL',
            'links': [
                u'https://rdap.arin.net/registry/entity/GOGL',
                u'https://whois.arin.net/rest/org/GOGL'
            ],
            'notices': None,
            'raw': None,
            'remarks': None,
            'roles': [u'registrant'],
            'status': None
        },
        u'ZG39-ARIN': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': [{
                    'type': None,
                    'value': u'arin-contact@google.com'
                }],
                'kind': u'group',
                'name': u'Google Inc',
                'phone': [{
                    'type': [u'work', u'voice'],
                    'value': u'+1-650-253-0000'
                }],
                'role': None,
                'title': None
            },
            'entities': None,
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-09-01T14:03:11-04:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2000-11-30T13:54:08-05:00'
            }],
            'events_actor': None,
            'handle': u'ZG39-ARIN',
            'links': [
                u'https://rdap.arin.net/registry/entity/ZG39-ARIN',
                u'https://whois.arin.net/rest/poc/ZG39-ARIN'
            ],
            'notices': [{
                'description': u'By using the ARIN RDAP/Whois service, you are
                    agreeing to the RDAP/Whois Terms of Use',
                'links': [u'https://www.arin.net/whois_tou.html'],
                'title': u'Terms of Service'
            }],
            'raw': None,
            'remarks': None,
            'roles': None,
            'status': [u'validated']
        }
    },
    'query': '74.125.225.229',
    'raw': None
    }

Use a proxy
^^^^^^^^^^^

::

	>>>> from urllib import request
	>>>> from ipwhois import IPWhois
	>>>> handler = request.ProxyHandler({'http': 'http://192.168.0.1:80/'})
	>>>> opener = request.build_opener(handler)
	>>>> obj = IPWhois('74.125.225.229', proxy_opener = opener)

Tweaking queries for your network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

	>>>> from ipwhois import IPWhois
	>>>> obj = IPWhois('74.125.225.229', timeout=10)
	>>>> results = obj.lookup_rdap(retry_count=5, rate_limit_timeout=60)

Legacy Whois
------------

Basic usage
^^^^^^^^^^^

::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint

	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup_whois()
	>>>> pprint(results)

	{
	'asn': '15169',
	'asn_cidr': '74.125.225.0/24',
	'asn_country_code': 'US',
	'asn_date': '2007-03-13',
	'asn_registry': 'arin',
	'nets': [{'address': '1600 Amphitheatre Parkway',
              'cidr': '74.125.0.0/16',
              'city': 'Mountain View',
              'country': 'US',
              'created': '2007-03-13',
              'description': 'Google Inc.',
              'emails': 'arin-contact@google.com\nnetwork-abuse@google.com',
              'handle': 'NET-74-125-0-0-1',
              'name': 'GOOGLE',
              'postal_code': '94043',
              'range': '74.125.0.0 - 74.125.255.255',
              'state': 'CA',
              'updated': '2012-02-24'}],
	'query': '74.125.225.229',
	'raw': None,
	'raw_referral': None,
	'referral': None
	}

Multiple networks listed and referral whois
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('38.113.198.252')
    >>>> results = obj.lookup_whois(get_referral=True)
    >>>> pprint(results)

    {
    'asn': '174',
    'asn_cidr': '38.0.0.0/8',
    'asn_country_code': 'US',
    'asn_date': '',
    'asn_registry': 'arin',
    'nets': [{'address': '2450 N Street NW',
           'cidr': '38.0.0.0/8',
           'city': 'Washington',
           'country': 'US',
           'created': '1991-04-16',
           'description': 'PSINet, Inc.',
           'emails': 'noc@cogentco.com\n'
                     'abuse@cogentco.com\n'
                     'ipalloc@cogentco.com',
           'handle': 'NET-38-0-0-0-1',
           'name': 'COGENT-A',
           'postal_code': '20037',
           'range': '38.0.0.0 - 38.255.255.255',
           'state': 'DC',
           'updated': '2011-05-20'},
          {'address': '2450 N Street NW',
           'cidr': '38.112.0.0/13',
           'city': 'Washington',
           'country': 'US',
           'created': '2003-08-20',
           'description': 'PSINet, Inc.',
           'emails': 'noc@cogentco.com\n'
                     'abuse@cogentco.com\n'
                     'ipalloc@cogentco.com',
           'handle': 'NET-38-112-0-0-1',
           'name': 'COGENT-NB-0002',
           'postal_code': '20037',
           'range': None,
           'state': 'DC',
           'updated': '2004-03-11'}],
    'query': '38.113.198.252',
    'raw': None,
    'raw_referral': None,
    'referral': {'address': '1015 31st St NW',
                 'city': 'Washington',
                 'country': 'US',
                 'description': 'Cogent communications - IPENG',
                 'name': 'NET4-2671C60017',
                 'postal_code': '20007',
                 'state': 'DC',
                 'updated': '2007-09-18 22:02:09'}
    }

Utilities
---------

Retrieve host information for an IP address
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint

	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.get_host()
	>>>> pprint(results)

	('dfw06s26-in-f5.1e100.net', [], ['74.125.225.229'])

Retrieve the official country name for an ISO 3166-1 country code
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

	>>>> from ipwhois import IPWhois
	>>>> from ipwhois.utils import get_countries

	>>>> countries = get_countries()
	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup_whois(False)
	>>>> print(countries[results['nets'][0]['country']])

	United States

Parse out IP addresses and ports from text or a file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

	>>>> from ipwhois.utils import unique_addresses
	>>>> from pprint import pprint

	>>>> input_data = (
            'You can have IPs like 74.125.225.229, or 2001:4860:4860::8888'
            'Put a port at the end 74.125.225.229:80 or for IPv6: '
            '[2001:4860:4860::8888]:443 or even networks like '
            '74.125.0.0/16 and 2001:4860::/32.'
	)

	>>>> results = unique_addresses(data=input_data, file_path=None)
	>>>> pprint(results)

	{'2001:4860:4860::8888': {'count': 2, 'ports': {'443': 1}},
	 '2001:4860::/32': {'count': 1, 'ports': {}},
	 '74.125.0.0/16': {'count': 1, 'ports': {}},
	 '74.125.225.229': {'count': 2, 'ports': {'80': 1}}}

RDAP (HTTP)
===========

IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

Upgrading from 0.10 to 0.11
---------------------------

Considerable changes were made between v0.10.3 and v0.11.0. The new RDAP return
format was introduced and split off from the legacy whois return format. Using
RDAP lookup is the recommended method to maximize indexable values.

RDAP return data is different in nearly every way from the legacy whois data.

For information on raw RDAP responses, please see the RFC:
https://tools.ietf.org/html/rfc7483

Here are the new standard keys for RDAP results::

	:query: The IP address (String)
	:network: Dictionary of values returned by _RDAPNetwork. The raw
		result is included for each entity if the inc_raw parameter is
		True.
	:entities: List of entity keys referenced by the top level IP
		address query.
	:objects: Dictionary of objects with the handles as keys, and the
		dictionary returned by _RDAPEntity, etc as the values. The raw
		result is included for each object if the inc_raw parameter is
		True.

See the `example <#basic-usage>`_ for more detailed field information.

Legacy Whois Parsing
====================

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Parsing is currently limited to CIDR, country, name, handle, range,
description, state, city, address, postal_code, abuse_emails, tech_emails,
misc_emails, created and updated fields. This is assuming that those fields
are present (for both whois and rwhois).

Some IPs have parent networks listed. The parser attempts to recognize this,
and break the networks into individual dictionaries. If a single network has
multiple CIDRs, they will be separated by ', '.

Sometimes, you will see whois information with multiple consecutive same name
fields, e.g., Description: some text\\nDescription: more text. The parser will
recognize this and the returned result will have the values separated by '\\n'.

Country Codes
=============

The legacy country code listing (iso_3166-1_list_en.xml) is no longer
available as a free export from iso.org. Support has been added for
iso_3166-1.csv, which is now the default.

Use Legacy XML File::

	>>>> from ipwhois.utils import get_countries
	>>>> countries = get_countries(is_legacy_xml=True)

IP Reputation Support?
======================

This feature is under consideration. Take a look at TekDefense's Automater:

`TekDefense-Automater <https://github.com/1aN0rmus/TekDefense-Automater>`_

Domain Support?
===============

There are no plans for domain whois support in this project.

Look at Sven Slootweg's
`python-whois <https://github.com/joepie91/python-whois>`_ for a library with
domain support.

Special Thanks
==============

Thank you JetBrains for the PyCharm open source support!
