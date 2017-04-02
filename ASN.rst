==============
IP ASN Lookups
==============

This is new functionality as of v0.15.0. This functionality was migrated from
net.Net and is still used by IPWhois.lookup*().

.. _ip-asn-input:

IP ASN Input
============

Arguments supported by IPASN.lookup().

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
| asn_alts               | List   | Array of additional lookup types to       |
|                        |        | attempt if the ASN dns lookup fails.      |
|                        |        | Allow permutations must be enabled.       |
|                        |        | Defaults to all ['whois', 'http'].        |
|                        |        | *WARNING* deprecated in favor of new      |
|                        |        | argument asn_methods.                     |
+------------------------+--------+-------------------------------------------+
| asn_methods            | List   | Array of ASN lookup types to attempt, in  |
|                        |        | order. Defaults to all                    |
|                        |        | ['dns', 'whois', 'http'].                 |
+------------------------+--------+-------------------------------------------+
| extra_org_map          | List   | Dictionary mapping org handles to RIRs.   |
|                        |        | This is for limited cases where ARIN REST |
|                        |        | (ASN fallback HTTP lookup) does not show  |
|                        |        | an RIR as the org handle e.g., DNIC       |
|                        |        | (which is now the built in ORG_MAP) e.g., |
|                        |        | {'DNIC': 'arin'}. Valid RIR values are    |
|                        |        | (note the case-sensitive - this is meant  |
|                        |        | to match the REST result): 'ARIN',        |
|                        |        | 'RIPE', 'apnic', 'lacnic', 'afrinic'      |
+------------------------+--------+-------------------------------------------+

.. _ip-asn-output:

IP ASN Output
=============

.. _ip-asn-results-dictionary:

IP ASN Results Dictionary
-------------------------

The output dictionary from IPASN.lookup().

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| asn              | String | The Autonomous System Number                    |
+------------------+--------+-------------------------------------------------+
| asn_date         | String | The ASN Allocation date                         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | String | The assigned ASN registry                       |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | String | The assigned ASN CIDR                           |
+------------------+--------+-------------------------------------------------+
| asn_country_code | String | The assigned ASN country code                   |
+------------------+--------+-------------------------------------------------+
| raw              | String | Raw ASN results if inc_raw is True.             |
+------------------+--------+-------------------------------------------------+

.. _ip-asn-usage-examples:

IP ASN Usage Examples
=====================

Basic usage
-----------

.. OUTPUT_IP_ASN_BASIC START

::

    >>>> from ipwhois.net import Net
    >>>> from ipwhois.asn import IPASN
    >>>> from pprint import pprint

    >>>> net = Net('2001:43f8:7b0::')
    >>>> obj = IPASN(net)
    >>>> results = obj.lookup()

    {
    "asn": "37578",
    "asn_cidr": "2001:43f8:7b0::/48",
    "asn_country_code": "KE",
    "asn_date": "2013-03-22",
    "asn_registry": "afrinic"
    }

.. OUTPUT_IP_ASN_BASIC END

==================
ASN Origin Lookups
==================

This is new functionality as of v0.15.0.

Both Whois and HTTP protocols are supported.

RADB is the only query destination at the moment.

Parsing is currently limited to the keys in the output
:ref:`asn-origin-results-dictionary`.
This is assuming that those fields are present.

.. _asn-origin-input:

ASN Origin Input
================

Arguments supported by ASNOrigin.lookup().

+------------------------+--------+-------------------------------------------+
| **Key**                |**Type**| **Description**                           |
+------------------------+--------+-------------------------------------------+
| asn                    | String | The autonomous system number (ASN) to     |
|                        |        | lookup. May be in format '1234'/'AS1234'  |
+------------------------+--------+-------------------------------------------+
| inc_raw                | Bool   | Boolean for whether to include the raw    |
|                        |        | whois results in the returned dictionary. |
+------------------------+--------+-------------------------------------------+
| retry_count            | Int    | The number of times to retry in case      |
|                        |        | socket errors, timeouts, connection       |
|                        |        | resets, etc. are encountered.             |
+------------------------+--------+-------------------------------------------+
| field_list             | List   | If provided, a list of fields to parse:   |
|                        |        | ['description', 'maintainer', 'updated',  |
|                        |        | 'source']                                 |
+------------------------+--------+-------------------------------------------+
| asn_alts               | List   | Array of additional lookup types to       |
|                        |        | attempt if the ASN whois lookup fails.    |
|                        |        | Defaults to all ['http'].                 |
+------------------------+--------+-------------------------------------------+

.. _asn-origin-output:

ASN Origin Output
=================

.. _asn-origin-results-dictionary:

ASN Origin Results Dictionary
-----------------------------

The output dictionary from ASNOrigin.lookup().

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| query            | String | The ASN input                                   |
+------------------+--------+-------------------------------------------------+
| nets             | List   | List of network dictionaries.                   |
|                  |        | See :ref:`asn-origin-network-dictionary`.       |
+------------------+--------+-------------------------------------------------+
| raw              | String | Raw ASN origin whois results if inc_raw is True.|
+------------------+--------+-------------------------------------------------+

.. _asn-origin-network-dictionary:

ASN Origin Network Dictionary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`asn-origin-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | String | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| description | String | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| maintainer  | String | The entity that maintains this network.              |
+-------------+--------+------------------------------------------------------+
| updated     | String | Network registration updated information.            |
+-------------+--------+------------------------------------------------------+
| source      | String | The source of this network information.              |
+-------------+--------+------------------------------------------------------+

.. _asn-origin-usage-examples:

ASN Origin Usage Examples
=========================

Basic usage
-----------

.. OUTPUT_ASN_ORIGIN_BASIC START

::

    >>>> from ipwhois.net import Net
    >>>> from ipwhois.asn import ASNOrigin
    >>>> from pprint import pprint

    >>>> net = Net('2001:43f8:7b0::')
    >>>> obj = ASNOrigin(net)
    >>>> results = obj.lookup(asn='AS37578')

    {
    "nets": [
        {
            "cidr": "196.6.220.0/24",
            "description": "KIXP Nairobi Management Network",
            "maintainer": "TESPOK-MNT",
            "source": "AFRINIC",
            "updated": "***@isoc.org 20160720"
        }
    ],
    "query": "AS37578",
    "raw": null
    }

.. OUTPUT_ASN_ORIGIN_BASIC END
