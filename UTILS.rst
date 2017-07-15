=========
Utilities
=========

Many useful utilities are provided for IP addresses outside of whois
functionality. The following utilities are used throughout the ipwhois library
for validation and parsing.

Country Codes
=============

The legacy country code listing (iso_3166-1_list_en.xml) is no longer
available as a free export from iso.org. Support has been added for
iso_3166-1.csv, which is now the default.

Use Legacy XML File::

    >>>> from ipwhois.utils import get_countries
    >>>> countries = get_countries(is_legacy_xml=True)

Human Readable Fields
=====================

Human readable translations are available for all result fields (RDAP and
Legacy Whois). Translations are currently limited to the short name (_short),
the name (_name), and the description (_description).

See the ipwhois CLI (ipwhois_utils_cli.py) for an example.

Import the human readable translation dictionaries

::

    >>>> from ipwhois.hr import (HR_ASN, HR_ASN_ORIGIN, HR_RDAP_COMMON,
                                 HR_RDAP, HR_WHOIS, HR_WHOIS_NIR)

Usage Examples
==============

IPv4 Strip Zeros
----------------
Strip leading zeros in each octet of an IPv4 address string.

::

    >>>> from ipwhois.utils import ipv4_lstrip_zeros
    >>>> print(ipv4_lstrip_zeros('074.125.025.229'))

    74.125.25.229

CIDR Calculation
----------------
Get a list of CIDR range(s) from a start and end IP address.

::

    >>>> from ipwhois.utils import calculate_cidr
    >>>> print(calculate_cidr('192.168.0.9', '192.168.5.4'))

    ['192.168.0.9/32', '192.168.0.10/31', '192.168.0.12/30', '192.168.0.16/28',
    '192.168.0.32/27', '192.168.0.64/26', '192.168.0.128/25', '192.168.1.0/24',
    '192.168.2.0/23', '192.168.4.0/24', '192.168.5.0/30', '192.168.5.4/32']

Check if IP is reserved/defined
-------------------------------
Check if an IPv4 or IPv6 address is in a reserved/defined pool.

::

    >>>> from ipwhois.utils import (ipv4_is_defined, ipv6_is_defined)
    >>>> print(ipv4_is_defined('192.168.0.1'))

    (True, 'Private-Use Networks', 'RFC 1918')

    >>>> print(ipv6_is_defined('fe80::'))

    (True, 'Link-Local', 'RFC 4291, Section 2.5.6')

Country Code Mapping
--------------------
Retrieve a dictionary mapping ISO 3166-1 country codes to country names.

::

    >>>> from ipwhois import IPWhois
    >>>> from ipwhois.utils import get_countries

    >>>> countries = get_countries()
    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_whois(False)
    >>>> print(countries[results['nets'][0]['country']])

    United States

Iterable to unique elements (order preserved)
---------------------------------------------
List unique elements, preserving the order. This was taken from the itertools
recipes.

::

    >>>> from ipwhois.utils import unique_everseen
    >>>> print(list(unique_everseen(['b', 'a', 'b', 'a', 'c', 'a', 'b', 'c')))

    ['b', 'a', 'c']

Parse IPs/ports from text/file
------------------------------
Search an input string and/or file, extracting and counting IPv4/IPv6
addresses/networks. Summarizes ports with sub-counts.

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

Generate random IP addresses
----------------------------
Generate random, unique IPv4/IPv6 addresses that are not defined (can be
looked up using ipwhois).

::

    >>>> from ipwhois.utils import ipv4_generate_random
    >>>> for address in ipv4_generate_random(10):
    >>>>     print(address)

    71.58.89.10
    17.206.180.200
    156.94.166.94
    36.92.169.70
    52.214.0.208
    174.254.156.179
    33.184.228.52
    17.58.3.61
    101.151.158.16
    61.162.38.154

    >>>> from ipwhois.utils import ipv6_generate_random
    >>>> for address in ipv6_generate_random(10):
    >>>>     print(address)

    218e:a9ad:aae4:431c:ff16:eb94:f063:47f7
    24ba:3185:a26f:fd30:5756:16d5:b4ab:771b
    38ad:f797:360a:d98e:4f3b:b1c8:5811:8425
    2c0e:9add:6b48:96c4:d22:2674:8067:2de9
    3b72:414b:c387:4650:c4a6:eed3:21a8:ba9b
    3d24:4053:dd81:d269:2cdc:91c9:b0f8:830e
    32a4:8ef8:807:1bf0:e866:c8d7:d69e:2a52
    2a2b:eb87:d368:89ee:6861:555:32c6:d552
    2ee6:5445:f1ff:b1c6:d68f:3ee1:1e31:fe34
    2c6b:393f:ae7:a0f7:1c2:2e19:bab1:af9c

