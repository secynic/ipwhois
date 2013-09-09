=======
ipwhois
=======

ipwhois is a simple package for retrieving and parsing whois data for IPv4 and IPv6 addresses. This code was quickly thrown together to demonstrate functionality, and is by no means optimized or fully featured. 

This version requires Python 3.3 (for the ipaddress library) and dnspython3. Other Python version support is planned.

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

Parsing
=======

Parsing is currently limited to CIDR, country, description, name, and state fields. This is assuming that those fields are present.

Some IPs have parent networks listed. The parser attempts to recognize this, and break the networks into individual dictionaries.

Sometimes, you will see whois information with multiple consecutive same name fields, e.g., Description: some text\\nDescription: more text. The parser will recognize this and the returned result will have these separated by '\\n'.

Future Plans
============

IPWhois.httplookup() - Allow parsing of Whois data via RWS feeds from the various NICs. This feature is useful when outbound port 43 is not available. Only ARIN and RIPE have Whois-RWS services at the time of this writing. Although RIPE does have a feature that integrates the other NICs, they are limited on the types of information that is allowed to be displayed. Additionally, as part of this feature, proxy support will also be added.