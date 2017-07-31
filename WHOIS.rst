====================
Legacy Whois Lookups
====================

IPWhois.lookup() is deprecated as of v0.12.0 and will be removed. Legacy whois
lookups were moved to IPWhois.lookup_whois().

Parsing is currently limited to the keys in the output
:ref:`whois-results-dictionary`.
This is assuming that those fields are present (for both whois and rwhois).

Some IPs have parent networks listed. The parser attempts to recognize this,
and break the networks into individual dictionaries. If a single network has
multiple CIDRs, they will be separated by ', '.

Sometimes, you will see whois information with multiple consecutive same name
fields, e.g., Description: some text\\nDescription: more text. The parser will
recognize this and the returned result will have the values separated by '\\n'.

.. _whois-input:

Input
=====

Arguments supported by IPWhois.lookup_whois().

+------------------------+--------+-------------------------------------------+
| **Key**                |**Type**| **Description**                           |
+------------------------+--------+-------------------------------------------+
| inc_raw                | bool   | Whether to include the raw whois results  |
|                        |        | in the returned dictionary. Defaults to   |
|                        |        | False.                                    |
+------------------------+--------+-------------------------------------------+
| retry_count            | int    | The number of times to retry in case      |
|                        |        | socket errors, timeouts, connection       |
|                        |        | resets, etc. are encountered.             |
|                        |        | Defaults to 3.                            |
+------------------------+--------+-------------------------------------------+
| get_referral           | bool   | Whether to retrieve referral whois        |
|                        |        | information, if available. Defaults to    |
|                        |        | False.                                    |
+------------------------+--------+-------------------------------------------+
| extra_blacklist        | list   | Blacklisted whois servers in addition to  |
|                        |        | the global BLACKLIST. Defaults to None.   |
+------------------------+--------+-------------------------------------------+
| ignore_referral_errors | bool   | Whether to ignore and continue when an    |
|                        |        | exception is encountered on referral whois|
|                        |        | lookups. Defaults to False.               |
+------------------------+--------+-------------------------------------------+
| field_list             | list   | If provided, a list of fields to parse:   |
|                        |        | ['name', 'handle', 'description',         |
|                        |        | 'country', 'state', 'city', 'address',    |
|                        |        | 'postal_code', 'emails', 'created',       |
|                        |        | 'updated']. If None, defaults to all.     |
+------------------------+--------+-------------------------------------------+
| asn_alts               | list   | Additional lookup types to attempt if the |
|                        |        | ASN dns lookup fails. Allow permutations  |
|                        |        | must be enabled. If None, defaults to all |
|                        |        | ['whois', 'http']. *WARNING* deprecated   |
|                        |        | in favor of new argument asn_methods.     |
+------------------------+--------+-------------------------------------------+
| extra_org_map          | dict   | Dictionary mapping org handles to RIRs.   |
|                        |        | This is for limited cases where ARIN      |
|                        |        | REST (ASN fallback HTTP lookup) does not  |
|                        |        | show an RIR as the org handle e.g., DNIC  |
|                        |        | (which is now built in ORG_MAP)           |
|                        |        | e.g., {'DNIC': 'arin'}                    |
|                        |        | Valid RIR values are (note the            |
|                        |        | case-sensitive - this is meant to match   |
|                        |        | the REST result):  'ARIN', 'RIPE',        |
|                        |        | 'apnic', 'lacnic', 'afrinic'              |
|                        |        | Defaults to None.                         |
+------------------------+--------+-------------------------------------------+
| inc_nir                | bool   | Whether to retrieve NIR (National Internet|
|                        |        | Registry) information, if registry is     |
|                        |        | JPNIC (Japan) or KRNIC (Korea). If True,  |
|                        |        | extra network requests will be required.  |
|                        |        | If False, the information returned for JP |
|                        |        | or KR IPs is severely restricted.         |
|                        |        | Defaults to True.                         |
+------------------------+--------+-------------------------------------------+
| nir_field_list         | list   | If provided and inc_nir, a list of fields |
|                        |        | to parse: ['name', 'handle', 'country',   |
|                        |        | 'address', 'postal_code', 'nameservers',  |
|                        |        | 'created', 'updated', 'contacts']         |
|                        |        | If None, defaults to all.                 |
+------------------------+--------+-------------------------------------------+
| asn_methods            | list   | ASN lookup types to attempt, in order. If |
|                        |        | None, defaults to all ['dns', 'whois',    |
|                        |        | 'http'].                                  |
+------------------------+--------+-------------------------------------------+
| get_asn_description    | bool   | Whether to run an additional query when   |
|                        |        | pulling ASN information via dns, in order |
|                        |        | to get the ASN description. Defaults to   |
|                        |        | True.                                     |
+------------------------+--------+-------------------------------------------+

.. _whois-output:

Output
======

.. _whois-results-dictionary:

Results Dictionary
------------------

The output dictionary from IPWhois.lookup_whois().

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| query            | str    | The IP address input                            |
+------------------+--------+-------------------------------------------------+
| asn              | str    | Globally unique identifier used for routing     |
|                  |        | information exchange with Autonomous Systems.   |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | str    | Network routing block assigned to an ASN.       |
+------------------+--------+-------------------------------------------------+
| asn_country_code | str    | ASN assigned country code in ISO 3166-1 format. |
+------------------+--------+-------------------------------------------------+
| asn_date         | str    | ASN allocation date in ISO 8601 format.         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | str    | ASN assigned regional internet registry.        |
+------------------+--------+-------------------------------------------------+
| asn_description  | str    | The ASN description                             |
+------------------+--------+-------------------------------------------------+
| nets             | list   | List of network dictionaries.                   |
|                  |        | See :ref:`whois-network-dictionary`.            |
+------------------+--------+-------------------------------------------------+
| raw              | str    | Raw whois results if inc_raw is True.           |
+------------------+--------+-------------------------------------------------+
| referral         | dict   | Referral whois information if get_referral      |
|                  |        | is True and the server isn't blacklisted. See   |
|                  |        | :ref:`whois-referral-dictionary`.               |
+------------------+--------+-------------------------------------------------+
| raw_referral     | str    | Raw referral whois results if the inc_raw       |
|                  |        | parameter is True.                              |
+------------------+--------+-------------------------------------------------+
| nir              | dict   | The National Internet Registry results if       |
|                  |        | inc_nir is True. See `NIR result <https://      |
|                  |        | ipwhois.readthedocs.io/en/latest/NIR.html       |
|                  |        | #results-dictionary>`_                          |
+------------------+--------+-------------------------------------------------+

.. _whois-network-dictionary:

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`whois-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | str    | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| range       | str    | Network range an IP address belongs to.              |
+-------------+--------+------------------------------------------------------+
| name        | str    | The identifier assigned to the network registration  |
|             |        | for an IP address.                                   |
+-------------+--------+------------------------------------------------------+
| handle      | str    | Unique identifier for a registered network.          |
+-------------+--------+------------------------------------------------------+
| description | str    | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| country     | str    | Country code registered with the RIR in              |
|             |        | ISO 3166-1 format.                                   |
+-------------+--------+------------------------------------------------------+
| state       | str    | State for a registered network (if applicable).      |
+-------------+--------+------------------------------------------------------+
| city        | str    | City for a registered network (if applicable).       |
+-------------+--------+------------------------------------------------------+
| address     | str    | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | str    | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| emails      | list   | The email addresses listed for a registered network. |
+-------------+--------+------------------------------------------------------+
| created     | str    | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | str    | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+

.. _whois-referral-dictionary:

Referral Dictionary
^^^^^^^^^^^^^^^^^^^

The dictionary mapped to the referral key in the
:ref:`whois-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | str    | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| range       | str    | Network range an IP address belongs to.              |
+-------------+--------+------------------------------------------------------+
| name        | str    | The identifier assigned to the network registration  |
|             |        | for an IP address.                                   |
+-------------+--------+------------------------------------------------------+
| description | str    | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| country     | str    | Country code registered in ISO 3166-1 format.        |
+-------------+--------+------------------------------------------------------+
| state       | str    | State for a registered network (if applicable).      |
+-------------+--------+------------------------------------------------------+
| city        | str    | City for a registered network (if applicable).       |
+-------------+--------+------------------------------------------------------+
| address     | str    | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | str    | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| emails      | list   | The email addresses listed for a registered network. |
+-------------+--------+------------------------------------------------------+
| created     | str    | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | str    | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+

.. _whois-usage-examples:

Usage Examples
==============

Basic usage
-----------

.. OUTPUT_BASIC START

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_whois()
    >>>> pprint(results)

    {
    "asn": "15169",
    "asn_cidr": "74.125.225.0/24",
    "asn_country_code": "US",
    "asn_date": "2007-03-13",
    "asn_description": "GOOGLE - Google Inc., US",
    "asn_registry": "arin",
    "nets": [
        {
            "address": "1600 Amphitheatre Parkway",
            "cidr": "74.125.0.0/16",
            "city": "Mountain View",
            "country": "US",
            "created": "2007-03-13",
            "description": "Google Inc.",
            "emails": [
                "network-abuse@google.com",
                "arin-contact@google.com"
            ],
            "handle": "NET-74-125-0-0-1",
            "name": "GOOGLE",
            "postal_code": "94043",
            "range": "74.125.0.0 - 74.125.255.255",
            "state": "CA",
            "updated": "2012-02-24"
        }
    ],
    "nir": None,
    "query": "74.125.225.229",
    "raw": None,
    "raw_referral": None,
    "referral": None
    }

.. OUTPUT_BASIC END

Multiple networks listed and referral whois
-------------------------------------------

.. OUTPUT_MULTI_REF START

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('38.113.198.252')
    >>>> results = obj.lookup_whois(get_referral=True)
    >>>> pprint(results)

    {
    "asn": "174",
    "asn_cidr": "38.0.0.0/8",
    "asn_country_code": "US",
    "asn_date": "",
    "asn_description": "COGENT-174 - Cogent Communications, US",
    "asn_registry": "arin",
    "nets": [
        {
            "address": "2450 N Street NW",
            "cidr": "38.0.0.0/8",
            "city": "Washington",
            "country": "US",
            "created": "1991-04-16",
            "description": "PSINet, Inc.",
            "emails": [
                "ipalloc@cogentco.com",
                "abuse@cogentco.com",
                "noc@cogentco.com"
            ],
            "handle": "NET-38-0-0-0-1",
            "name": "COGENT-A",
            "postal_code": "20037",
            "range": "38.0.0.0 - 38.255.255.255",
            "state": "DC",
            "updated": "2011-05-20"
        },
        {
            "address": "2450 N Street NW",
            "cidr": "38.112.0.0/13",
            "city": "Washington",
            "country": "US",
            "created": "2003-08-20",
            "description": "PSINet, Inc.",
            "emails": [
                "ipalloc@cogentco.com",
                "abuse@cogentco.com",
                "noc@cogentco.com"
            ],
            "handle": "NET-38-112-0-0-1",
            "name": "COGENT-NB-0002",
            "postal_code": "20037",
            "range": None,
            "state": "DC",
            "updated": "2004-03-11"
        }
    ],
    "nir": None,
    "query": "38.113.198.252",
    "raw": None,
    "raw_referral": None,
    "referral": {
        "address": "2450 N Street NW",
        "city": "Washington",
        "country": "US",
        "description": "Cogent communications - IPENG",
        "name": "NET4-2671C60017",
        "postal_code": "20037",
        "state": "DC",
        "updated": "2007-09-18 22:02:09"
    }
    }

.. OUTPUT_MULTI_REF END
