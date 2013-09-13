=======
ipwhois
=======

ipwhois is a simple package for retrieving and parsing whois data for IPv4 and IPv6 addresses. This code was quickly thrown together to demonstrate functionality, and is by no means optimized or fully featured. 

This version requires Python 3.3+ (for the ipaddress library) and dnspython3. Other Python version support is planned.

Usage Examples
==============

Typical usage::

    >>>> import ipwhois
    >>>> from pprint import pprint
    
    >>>> obj = ipwhois.IPWhois("74.125.225.229")
    >>>> results = obj.lookup(False)
    >>>> pprint(results)
    
	{
	'asn': '15169',
	'asn_cidr': '74.125.225.0/24',
	'asn_country_code': 'US',
	'asn_date': '2007-03-13',
	'asn_registry': 'arin',
	'nets': [{'cidr': '74.125.0.0/16',
	          'city': 'Mountain View',
	          'country': 'US',
	          'description': 'Google Inc.',
	          'name': 'GOOGLE',
	          'state': 'CA'}],
	'query': '74.125.225.229',
	'raw': None
	}
	
REST (HTTP)::

	>>>> import ipwhois
	>>>> from pprint import pprint
	
	>>>> obj = ipwhois.IPWhois("74.125.225.229")
	>>>> results = obj.lookup_rws(False)
	>>>> pprint(results)
	
	{
	'asn': '15169',
	'asn_cidr': '74.125.225.0/24',
	'asn_country_code': 'US',
	'asn_date': '2007-03-13',
	'asn_registry': 'arin',
	'nets': [{'cidr': '74.0.0.0/8',
	          'city': 'Chantilly',
	          'country': 'US',
	          'description': 'American Registry for Internet Numbers',
	          'name': 'NET74',
	          'state': 'VA'},
	         {'cidr': '74.125.0.0/16',
	          'city': 'Mountain View',
	          'country': 'US',
	          'description': 'Google Inc.',
	          'name': 'GOOGLE',
	          'state': 'CA'}],
	'query': '74.125.225.229',
	'raw': None
	}

Proxy (Optional before ipwhois.IPWhois.lookup_rws())::

	>>>> import ipwhois
	>>>> ipwhois.set_proxy("192.168.0.1", "80", "some_username", "some_password")
	
Countries::

	>>>> import ipwhois
	
	>>>> countries = ipwhois.get_countries()
	>>>> obj = ipwhois.IPWhois("74.125.225.229")
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

Parsing is currently limited to CIDR, country, description, name, and state fields. This is assuming that those fields are present.

Some IPs have parent networks listed. The parser attempts to recognize this, and break the networks into individual dictionaries. If a single network has multiple CIDRs, they will be separated by ', '.

Sometimes, you will see whois information with multiple consecutive same name fields, e.g., Description: some text\\nDescription: more text. The parser will recognize this and the returned result will have these separated by '\\n'.

REST (HTTP)
===========

IPWhois.lookup_rws() should be faster than IPWhois.lookup(), but may not be as reliable. APNIC, LACNIC, and AFRINIC do not have a Whois-RWS service yet. We have to rely on the Ripe RWS service, which does not contain all of the data we need.