=======
ipwhois
=======

ipwhois is a Python package focused on retrieving and parsing whois data
for IPv4 and IPv6 addresses.

Features
========

* Parses a majority of whois fields in to a standard dictionary
* IPv4 and IPv6 support
* Supports REST queries (useful if whois is blocked from your network)
* Proxy support for REST queries
* Recursive network parsing for IPs with parent/children networks listed
* Python 2.6+ and 3.3+ supported
* Useful set of utilities
* BSD license

Usage Examples
==============

Typical usage::

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
	
REST (HTTP)::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint
	
	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup_rws()
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
	          'created': '2007-03-13T12:09:54-04:00',
	          'description': 'Google Inc.',
	          'handle': 'NET-74-125-0-0-1',
	          'misc_emails': None,
	          'name': 'GOOGLE',
	          'postal_code': '94043',
	          'range': '74.125.0.0 - 74.125.255.255',
	          'state': 'CA',
	          'tech_emails': 'arin-contact@google.com',
	          'updated': '2012-02-24T09:44:34-05:00'}],
	'query': '74.125.225.229',
	'raw': None
	}

Proxy::

	>>>> from urllib import request
	>>>> from ipwhois import IPWhois
	>>>> handler = request.ProxyHandler({'http': 'http://192.168.0.1:80/'})
	>>>> opener = request.build_opener(handler)
	>>>> obj = IPWhois('74.125.225.229', proxy_opener = opener)

Hostname::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint
	
	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.get_host()
	>>>> pprint(results)
	
	('dfw06s26-in-f5.1e100.net', [], ['74.125.225.229'])
		
Countries::

	>>>> from ipwhois import IPWhois
	>>>> from ipwhois.utils import get_countries
	
	>>>> countries = get_countries()
	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup(False)
	>>>> print(countries[results['nets'][0]['country']])

	United States

Unique IP Addresses::

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

Parsing
=======

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

REST (HTTP)
===========

IPWhois.lookup_rws() should be faster than IPWhois.lookup(), but may not be as 
reliable. AFRINIC does not have a Whois-RWS service yet. We have to rely on the
Ripe RWS service, which does not contain all of the data we need. The LACNIC
RWS service is supported, but is in beta v2. This may result in availability
or performance issues.

Country Codes
=============

The legacy country code listing (iso_3166-1_list_en.xml) is no longer
available as a free export from iso.org. Support has been added for
iso_3166-1.csv, which is now the default.

IP Reputation?
==============

This feature is under consideration. Take a look at TekDefense's Automater for
now: `TekDefense-Automater <https://github.com/1aN0rmus/TekDefense-Automater>`_

Domains?
========

There are no plans for domain whois support in this project. It is under
consideration as a new library in the future.

For now, consider using Sven Slootweg's
`python-whois <https://github.com/joepie91/python-whois>`_ for a library with
domain support.

Special Thanks
==============

Thank you JetBrains for the PyCharm open source support. It has contributed
significantly, especially in the pkg/env management and code inspection
domains.
