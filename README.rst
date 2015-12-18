=======
ipwhois
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

RDAP is the recommended query method as of v0.11.0. Please see the
`upgrade info <#upgrading-from-0-10-to-0-11>`_.

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
    'entities': ['GOGL'],
    'network': {
        'country': None,
         'end_address': '74.125.255.255',
         'events': [{'action': 'last changed',
                     'actor': None,
                     'timestamp': '2012-02-24T09:44:34-05:00'},
                    {'action': 'registration',
                     'actor': None,
                     'timestamp': '2007-03-13T12:09:54-04:00'}],
         'handle': 'NET-74-125-0-0-1',
         'ip_version': 'v4',
         'links': ['https://rdap.arin.net/registry/ip/074.125.000.000',
                   'http://whois.arin.net/rest/net/NET-74-125-0-0-1'],
         'name': 'GOOGLE',
         'notices': [{'description': 'By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use',
                      'title': 'Terms of Service'}],
         'parent_handle': 'NET-74-0-0-0-0',
         'raw': None,
         'remarks': None,
         'start_address': '74.125.0.0',
         'status': None,
         'type': None
    },
    'objects': {
        'GOGL': {'contact': {'address': [{
            'type': None,
            'value': '1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUNITED STATES'}],
            'email': None,
            'kind': 'org',
            'name': 'Google Inc.',
            'phone': None,
            'role': None,
            'title': None},
            'entities': ['ZG39-ARIN'],
            'events': [{'action': 'last changed',
                      'actor': None,
                      'timestamp': '2013-08-07T19:59:17-04:00'},
                     {'action': 'registration',
                      'actor': None,
                      'timestamp': '2000-03-30T00:00:00-05:00'}],
            'events_actor': None,
            'handle': 'GOGL',
            'links': ['https://rdap.arin.net/registry/entity/GOGL',
                    'http://whois.arin.net/rest/org/GOGL'],
            'notices': None,
            'raw': None,
            'remarks': None,
            'roles': ['registrant'],
            'status': None},
        'ZG39-ARIN': {'contact': {'address': [{
            'type': None,
            'value': '1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUNITED STATES'}],
            'email': [{'type': None,
                      'value': 'arin-contact@google.com'}],
            'kind': 'group',
            'name': 'Google Inc',
            'phone': [{'type': ['work',
                               'voice'],
                      'value': '+1-650-253-0000'}],
            'role': None,
            'title': None},
            'entities': None,
            'events': [{'action': 'last changed',
                       'actor': None,
                       'timestamp': '2015-09-01T14:03:11-04:00'},
                      {'action': 'registration',
                       'actor': None,
                       'timestamp': '2000-11-30T13:54:08-05:00'}],
            'events_actor': None,
            'handle': 'ZG39-ARIN',
            'links': ['https://rdap.arin.net/registry/entity/ZG39-ARIN',
                     'http://whois.arin.net/rest/poc/ZG39-ARIN'],
            'notices': [{'description': 'By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use',
                        'title': 'Terms of Service'}],
            'raw': None,
            'remarks': None,
            'roles': None,
            'status': ['validated']}},
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

Legacy Whois
------------

Basic usage
^^^^^^^^^^^

::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint

	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup()
	>>>> pprint(results)

	{
	'asn': '15169',
	'asn_cidr': '74.125.225.0/24',
	'asn_country_code': 'US',
	'asn_date': '2007-03-13',
	'asn_registry': 'arin',
	'nets': [{'abuse_emails': 'arin-contact@google.com',
	          'address': '1600 Amphitheatre Parkway',
	          'cidr': '74.125.0.0/16',
	          'city': 'Mountain View',
	          'country': 'US',
	          'created': '2007-03-13T00:00:00',
	          'description': 'Google Inc.',
	          'handle': 'NET-74-125-0-0-1',
	          'misc_emails': None,
	          'name': 'GOOGLE',
	          'postal_code': '94043',
	          'range': '74.125.0.0 - 74.125.255.255',
	          'state': 'CA',
	          'tech_emails': 'arin-contact@google.com',
	          'updated': '2012-02-24T00:00:00'}],
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
    >>>> results = obj.lookup(get_referral=True)
    >>>> pprint(results)

    {
    'asn': '174',
    'asn_cidr': '38.0.0.0/8',
    'asn_country_code': 'US',
    'asn_date': '',
    'asn_registry': 'arin',
    'nets': [{'abuse_emails': 'abuse@cogentco.com',
              'address': '1015 31st St NW',
              'cidr': '38.0.0.0/8',
              'city': 'Washington',
              'country': 'US',
              'created': '1991-04-16T00:00:00',
              'description': 'PSINet, Inc.',
              'handle': 'NET-38-0-0-0-1',
              'misc_emails': None,
              'name': 'COGENT-A',
              'postal_code': '20007',
              'range': '38.0.0.0 - 38.255.255.255',
              'state': 'DC',
              'tech_emails': 'ipalloc@cogentco.com',
              'updated': '2011-05-20T00:00:00'},
             {'abuse_emails': 'abuse@cogentco.com',
              'address': '1015 31st St NW',
              'cidr': '38.112.0.0/13',
              'city': 'Washington',
              'country': 'US',
              'created': '2003-08-20T00:00:00',
              'description': 'PSINet, Inc.',
              'handle': 'NET-38-112-0-0-1',
              'misc_emails': None,
              'name': 'COGENT-NB-0002',
              'postal_code': '20007',
              'range': None,
              'state': 'DC',
              'tech_emails': 'ipalloc@cogentco.com',
              'updated': '2004-03-11T00:00:00'}],
    'query': '38.113.198.252',
    'raw': None,
    'raw_referral': None,
    'referral': {'address': '1015 31st St NW',
                 'cidr': '38.113.198.0/23',
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
	>>>> results = obj.lookup(False)
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
