===========
ASN Lookups
===========

This is new functionality as of v0.15.0. Currently only support origin lookups
for a provided ASN. Both Whois and HTTP protocols are supported.

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
