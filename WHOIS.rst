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
| inc_raw                | Bool   | Boolean for whether to include the raw    |
|                        |        | whois results in the returned dictionary. |
+------------------------+--------+-------------------------------------------+
| retry_count            | Int    | The number of times to retry in case      |
|                        |        | socket errors, timeouts, connection       |
|                        |        | resets, etc. are encountered.             |
+------------------------+--------+-------------------------------------------+
| get_referral           | Bool   | Boolean for whether to retrieve           |
|                        |        | referral whois information, if available. |
+------------------------+--------+-------------------------------------------+
| extra_blacklist        | List   | A list of blacklisted whois servers in    |
|                        |        | addition to the global BLACKLIST.         |
+------------------------+--------+-------------------------------------------+
| ignore_referral_errors | Bool   | Boolean for whether to ignore and         |
|                        |        | continue when an exception is encountered |
|                        |        | on referral whois lookups.                |
+------------------------+--------+-------------------------------------------+
| field_list             | List   | If provided, a list of fields to parse:   |
|                        |        | ['name', 'handle', 'description',         |
|                        |        | 'country', 'state', 'city', 'address',    |
|                        |        | 'postal_code', 'emails', 'created',       |
|                        |        | 'updated']                                |
+------------------------+--------+-------------------------------------------+
| asn_alts               | List   | List of additional lookup types to        |
|                        |        | attempt if the ASN dns lookup fails.      |
|                        |        | Allow permutations must be enabled.       |
|                        |        | Defaults to all ['whois', 'http'].        |
|                        |        | *WARNING* deprecated in favor of new      |
|                        |        | argument asn_methods.                     |
+------------------------+--------+-------------------------------------------+
| asn_methods            | List   | List of ASN lookup types to attempt, in   |
|                        |        | order. Defaults to all                    |
|                        |        | ['dns', 'whois', 'http'].                 |
+------------------------+--------+-------------------------------------------+
| extra_org_map          | Dict   | Dictionary mapping org handles to RIRs.   |
|                        |        | This is for limited cases where ARIN      |
|                        |        | REST (ASN fallback HTTP lookup) does not  |
|                        |        | show an RIR as the org handle e.g., DNIC  |
|                        |        | (which is now built in ORG_MAP)           |
|                        |        | e.g., {'DNIC': 'arin'}                    |
|                        |        | Valid RIR values are (note the            |
|                        |        | case-sensitive - this is meant to match   |
|                        |        | the REST result):  'ARIN', 'RIPE',        |
|                        |        | 'apnic', 'lacnic', 'afrinic'              |
+------------------------+--------+-------------------------------------------+
| get_asn_description    | Bool   | Boolean for whether to run an additional  |
|                        |        | query when pulling ASN information via    |
|                        |        | dns, in order to get the ASN description. |
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
| query            | String | The IP address input                            |
+------------------+--------+-------------------------------------------------+
| asn              | String | Globally unique identifier used for routing     |
|                  |        | information exchange with Autonomous Systems.   |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | String | Network routing block assigned to an ASN.       |
+------------------+--------+-------------------------------------------------+
| asn_country_code | String | ASN assigned country code in ISO 3166-1 format. |
+------------------+--------+-------------------------------------------------+
| asn_date         | String | ASN allocation date in ISO 8601 format.         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | String | ASN assigned regional internet registry.        |
+------------------+--------+-------------------------------------------------+
| asn_description  | String | The ASN description                             |
+------------------+--------+-------------------------------------------------+
| nets             | List   | List of network dictionaries.                   |
|                  |        | See :ref:`whois-network-dictionary`.            |
+------------------+--------+-------------------------------------------------+
| raw              | String | Raw whois results if inc_raw is True.           |
+------------------+--------+-------------------------------------------------+
| referral         | Dict   | Referral whois information if get_referral      |
|                  |        | is True and the server isn't blacklisted. See   |
|                  |        | :ref:`whois-referral-dictionary`.               |
+------------------+--------+-------------------------------------------------+
| raw_referral     | String | Raw referral whois results if the inc_raw       |
|                  |        | parameter is True.                              |
+------------------+--------+-------------------------------------------------+

.. _whois-network-dictionary:

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`whois-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | String | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| range       | String | Network range an IP address belongs to.              |
+-------------+--------+------------------------------------------------------+
| name        | String | The identifier assigned to the network registration  |
|             |        | for an IP address.                                   |
+-------------+--------+------------------------------------------------------+
| handle      | String | Unique identifier for a registered network.          |
+-------------+--------+------------------------------------------------------+
| description | String | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| country     | String | Country code registered with the RIR in              |
|             |        | ISO 3166-1 format.                                   |
+-------------+--------+------------------------------------------------------+
| state       | String | State for a registered network (if applicable).      |
+-------------+--------+------------------------------------------------------+
| city        | String | City for a registered network (if applicable).       |
+-------------+--------+------------------------------------------------------+
| address     | String | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | String | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| emails      | List   | The email addresses listed for a registered network. |
+-------------+--------+------------------------------------------------------+
| created     | String | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | String | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+

.. _whois-referral-dictionary:

Referral Dictionary
^^^^^^^^^^^^^^^^^^^

The dictionary mapped to the referral key in the
:ref:`whois-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | String | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| range       | String | Network range an IP address belongs to.              |
+-------------+--------+------------------------------------------------------+
| name        | String | The identifier assigned to the network registration  |
|             |        | for an IP address.                                   |
+-------------+--------+------------------------------------------------------+
| description | String | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| country     | String | Country code registered in ISO 3166-1 format.        |
+-------------+--------+------------------------------------------------------+
| state       | String | State for a registered network (if applicable).      |
+-------------+--------+------------------------------------------------------+
| city        | String | City for a registered network (if applicable).       |
+-------------+--------+------------------------------------------------------+
| address     | String | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | String | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| emails      | List   | The email addresses listed for a registered network. |
+-------------+--------+------------------------------------------------------+
| created     | String | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | String | Network registration updated date in ISO 8601 format.|
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
