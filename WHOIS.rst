====================
Legacy Whois Lookups
====================

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Parsing is currently limited to the keys in the output
`below <#results-dictionary>`_..
This is assuming that those fields are present (for both whois and rwhois).

Some IPs have parent networks listed. The parser attempts to recognize this,
and break the networks into individual dictionaries. If a single network has
multiple CIDRs, they will be separated by ', '.

Sometimes, you will see whois information with multiple consecutive same name
fields, e.g., Description: some text\\nDescription: more text. The parser will
recognize this and the returned result will have the values separated by '\\n'.

Input
=====

TODO

Output
======

Results Dictionary
------------------

The output dictionary from IPWhois.lookup_whois().

TODO

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
`Results Dictionary <#results-dictionary>`_.

TODO

Usage Examples
==============

Basic usage
-----------

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
-------------------------------------------

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
