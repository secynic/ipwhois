==============
IP ASN Lookups
==============

This is new functionality as of v0.15.0. This functionality was migrated from
net.Net and is still used by IPWhois.lookup*().

.. note::

    Cymru ASN data should not be considered a primary source for data points
    like country code.

    Message from the Cymru site::

        The country code, registry, and allocation date are all based on data
        obtained directly from the regional registries including: ARIN, RIPE,
        AFRINIC, APNIC, LACNIC. The information returned relating to these
        categories will only be as accurate as the data present in the RIR
        databases.

        IMPORTANT NOTE: Country codes are likely to vary significantly from
        actual IP locations, and we must strongly advise that the IP to ASN
        mapping tool not be used as an IP geolocation (GeoIP) service.

    https://team-cymru.com/community-services/ip-asn-mapping/

.. _ip-asn-input:

IP ASN Input
============

Arguments supported by IPASN.lookup().

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
| asn_methods            | list   | ASN lookup types to attempt, in order. If |
|                        |        | None, defaults to all ['dns', 'whois',    |
|                        |        | 'http'].                                  |
+------------------------+--------+-------------------------------------------+
| get_asn_description    | bool   | Whether to run an additional query when   |
|                        |        | pulling ASN information via dns, in order |
|                        |        | to get the ASN description. Defaults to   |
|                        |        | True.                                     |
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
| asn              | str    | The Autonomous System Number                    |
+------------------+--------+-------------------------------------------------+
| asn_date         | str    | The ASN Allocation date                         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | str    | The assigned ASN registry                       |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | str    | The assigned ASN CIDR                           |
+------------------+--------+-------------------------------------------------+
| asn_country_code | str    | The assigned ASN country code                   |
+------------------+--------+-------------------------------------------------+
| asn_description  | str    | The ASN description                             |
+------------------+--------+-------------------------------------------------+
| raw              | str    | Raw ASN results if inc_raw is True.             |
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
    >>>> pprint(results)

    {
    "asn": "37578",
    "asn_cidr": "2001:43f8:7b0::/48",
    "asn_country_code": "KE",
    "asn_date": "2013-03-22",
    "asn_description": "Tespok, KE",
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
| asn                    | str    | The autonomous system number (ASN) to     |
|                        |        | lookup. May be in format '1234'/'AS1234'  |
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
| response               | str    | Optional response object, this bypasses   |
|                        |        | the Whois lookup. Defaults to None.       |
+------------------------+--------+-------------------------------------------+
| field_list             | list   | If provided, fields to parse:             |
|                        |        | ['description', 'maintainer', 'updated',  |
|                        |        | 'source']. If None, defaults to all.      |
+------------------------+--------+-------------------------------------------+
| asn_methods            | list   | ASN lookup types to attempt, in order. If |
|                        |        | None, defaults to all ['whois', 'http'].  |
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
| query            | str    | The ASN input                                   |
+------------------+--------+-------------------------------------------------+
| nets             | list   | List of network dictionaries.                   |
|                  |        | See :ref:`asn-origin-network-dictionary`.       |
+------------------+--------+-------------------------------------------------+
| raw              | str    | Raw ASN origin whois results if inc_raw is True.|
+------------------+--------+-------------------------------------------------+

.. _asn-origin-network-dictionary:

ASN Origin Network Dictionary
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`asn-origin-results-dictionary`.

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| cidr        | str    | Network routing block an IP address belongs to.      |
+-------------+--------+------------------------------------------------------+
| description | str    | Description for a registered network.                |
+-------------+--------+------------------------------------------------------+
| maintainer  | str    | The entity that maintains this network.              |
+-------------+--------+------------------------------------------------------+
| updated     | str    | Network registration updated information.            |
+-------------+--------+------------------------------------------------------+
| source      | str    | The source of this network information.              |
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
    >>>> pprint(results)

    {
    "nets": [
        {
            "cidr": "196.6.220.0/24",
            "description": "KIXP Nairobi Management Network",
            "maintainer": "TESPOK-MNT",
            "source": "AFRINIC",
            "updated": "***@isoc.org 20160720"
        },
        {
            "cidr": "2001:43f8:7b0::/48",
            "description": "KIXP Nairobi Management Network",
            "maintainer": "TESPOK-MNT",
            "source": "AFRINIC",
            "updated": "***@isoc.org 20160721"
        }
    ],
    "query": "AS37578",
    "raw": None
    }

.. OUTPUT_ASN_ORIGIN_BASIC END
