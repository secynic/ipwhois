=======
ipwhois
=======

ipwhois is a simple package for retrieving and parsing whois data for IPv4 and IPv6 addresses. 

The various NICs are pretty inconsistent with formatting Whois results and the information contained within. I am still working through how to parse some of these fields in to standard dictionary keys.

This version requires Python 3.3+ (for the ipaddress library) and dnspython3.

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
	          'misc_emails': None,
	          'name': 'GOOGLE',
	          'postal_code': '94043',
	          'state': 'CA',
	          'tech_emails': 'arin-contact@google.com',
	          'updated': '2012-02-24T00:00:00'}],
	'query': '74.125.225.229',
	'raw': None
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
	          'misc_emails': None,
	          'name': 'GOOGLE',
	          'postal_code': '94043',
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

Installing
==========

Latest version from PyPi::

	pip install ipwhois

Latest version from GitHub::

	pip install -e git+https://github.com/secynic/ipwhois@master#egg=ipwhois
	
Parsing
=======

Parsing is currently limited to CIDR, country, name, description, state, city, address, postal_code, abuse_emails, tech_emails, misc_emails, created and updated fields. This is assuming that those fields are present.

Some IPs have parent networks listed. The parser attempts to recognize this, and break the networks into individual dictionaries. If a single network has multiple CIDRs, they will be separated by ', '.

Sometimes, you will see whois information with multiple consecutive same name fields, e.g., Description: some text\\nDescription: more text. The parser will recognize this and the returned result will have the values separated by '\\n'.

REST (HTTP)
===========

IPWhois.lookup_rws() should be faster than IPWhois.lookup(), but may not be as reliable. APNIC, LACNIC, and AFRINIC do not have a Whois-RWS service yet. We have to rely on the Ripe RWS service, which does not contain all of the data we need.