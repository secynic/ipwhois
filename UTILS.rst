=========
Utilities
=========

There are many useful utilities included with the ipwhois library. This
will be fully documented here in a future release.

Country Codes
=============

The legacy country code listing (iso_3166-1_list_en.xml) is no longer
available as a free export from iso.org. Support has been added for
iso_3166-1.csv, which is now the default.

Use Legacy XML File::

	>>>> from ipwhois.utils import get_countries
	>>>> countries = get_countries(is_legacy_xml=True)


Usage Examples
==============

Retrieve host information for an IP address
-------------------------------------------

::

	>>>> from ipwhois import IPWhois
	>>>> from pprint import pprint

	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.get_host()
	>>>> pprint(results)

	('dfw06s26-in-f5.1e100.net', [], ['74.125.225.229'])

Retrieve the official country name for an ISO 3166-1 country code
-----------------------------------------------------------------

::

	>>>> from ipwhois import IPWhois
	>>>> from ipwhois.utils import get_countries

	>>>> countries = get_countries()
	>>>> obj = IPWhois('74.125.225.229')
	>>>> results = obj.lookup_whois(False)
	>>>> print(countries[results['nets'][0]['country']])

	United States

Parse out IP addresses and ports from text or a file
----------------------------------------------------

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

