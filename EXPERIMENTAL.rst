======================
Experimental Functions
======================

.. caution::

    Functions in experimental.py contain new functionality that has not yet
    been widely tested. Bulk lookup support contained here can result in
    significant system/network resource utilization. Additionally, abuse of
    this functionality may get you banned by the various services queried by
    this library. Use at your own discretion.

Bulk ASN Lookups
================

The function for retrieving ASN information for multiple IP addresses from
Cymru via port 43/tcp (WHOIS).

`ipwhois.experimental.get_bulk_asn_whois()
<https://ipwhois.readthedocs.io/en/latest/ipwhois.html#ipwhois.experimental.
get_bulk_asn_whois>`_

.. _get_bulk_asn_whois-input:

Input
-----

Arguments supported:

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| addresses          | list   | List of IP address strings to lookup.         |
+--------------------+--------+-----------------------------------------------+
| retry_count        | int    | The number of times to retry in case socket   |
|                    |        | errors, timeouts, connection resets, etc. are |
|                    |        | encountered. Defaults to 3.                   |
+--------------------+--------+-----------------------------------------------+
| timeout            | int    | The default timeout for socket connections in |
|                    |        | seconds. Defaults to 120.                     |
+--------------------+--------+-----------------------------------------------+

.. _get_bulk_asn_whois-output:

Output
------

Outputs a string of the raw ASN bulk data, new line separated. The first line
is obsolete.

.. _get_bulk_asn_whois-examples:

Usage Examples
--------------

Basic usage
^^^^^^^^^^^

.. GET_BULK_ASN_WHOIS_OUTPUT_BASIC START

::

    >>>> from ipwhois.experimental import get_bulk_asn_whois
    >>>> from pprint import pprint

    >>>> ip_list = ['74.125.225.229', '2001:4860:4860::8888', '62.239.237.1', '2a00:2381:ffff::1', '210.107.73.73', '2001:240:10c:1::ca20:9d1d', '200.57.141.161', '2801:10:c000::', '196.11.240.215', '2001:43f8:7b0::', '133.1.2.5', '115.1.2.3']
    >>>> results = get_bulk_asn_whois(addresses=ip_list)
    >>>> pprint(results.split('\n'))

    [
    "Bulk mode; whois.cymru.com [2017-07-30 23:02:21 +0000]",
    "15169   | 74.125.225.229   | 74.125.225.0/24     | US | arin     | 2007-03-13 | GOOGLE - Google Inc., US",
    "15169   | 2001:4860:4860::8888                     | 2001:4860::/32      | US | arin     | 2005-03-14 | GOOGLE - Google Inc., US",
    "2856    | 62.239.237.1     | 62.239.0.0/16       | GB | ripencc  | 2001-01-02 | BT-UK-AS BTnet UK Regional network, GB",
    "2856    | 2a00:2381:ffff::1                        | 2a00:2380::/25      | GB | ripencc  | 2007-08-29 | BT-UK-AS BTnet UK Regional network, GB",
    "3786    | 210.107.73.73    | 210.107.0.0/17      | KR | apnic    |            | LGDACOM LG DACOM Corporation, KR",
    "2497    | 2001:240:10c:1::ca20:9d1d                | 2001:240::/32       | JP | apnic    | 2000-03-08 | IIJ Internet Initiative Japan Inc., JP",
    "19373   | 200.57.141.161   | 200.57.128.0/20     | MX | lacnic   | 2000-12-04 | Triara.com, S.A. de C.V., MX",
    "NA      | 2801:10:c000::                           | NA                  | CO | lacnic   | 2013-10-29 | NA",
    "12091   | 196.11.240.215   | 196.11.240.0/24     | ZA | afrinic  |            | MTNNS-1, ZA",
    "37578   | 2001:43f8:7b0::                          | 2001:43f8:7b0::/48  | KE | afrinic  | 2013-03-22 | Tespok, KE",
    "4730    | 133.1.2.5        | 133.1.0.0/16        | JP | apnic    |            | ODINS Osaka University, JP",
    "4134    | 115.1.2.3        | 115.0.0.0/14        | KR | apnic    | 2008-07-01 | CHINANET-BACKBONE No.31,Jin-rong Street, CN",
    ""
    }

.. GET_BULK_ASN_WHOIS_OUTPUT_BASIC END

Bulk RDAP Lookups
=================

The function for bulk retrieving and parsing whois information for a list of
IP addresses via HTTP (RDAP). This bulk lookup method uses bulk ASN Whois
lookups first to retrieve the ASN for each IP. It then optimizes RDAP queries
to achieve the fastest overall time, accounting for rate-limiting RIRs.

`ipwhois.experimental.bulk_lookup_rdap()
<https://ipwhois.readthedocs.io/en/latest/ipwhois.html#ipwhois.experimental.
bulk_lookup_rdap>`_

.. _bulk_lookup_rdap-input:

Input
-----

Arguments supported:

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| addresses          | list   | List of IP address strings to lookup.         |
+--------------------+--------+-----------------------------------------------+
| inc_raw            | bool   | Whether to include the raw whois results in   |
|                    |        | the returned dictionary. Defaults to False.   |
+--------------------+--------+-----------------------------------------------+
| retry_count        | int    | The number of times to retry in case socket   |
|                    |        | errors, timeouts, connection resets, etc. are |
|                    |        | encountered. Defaults to 3.                   |
+--------------------+--------+-----------------------------------------------+
| depth              | int    | How many levels deep to run queries when      |
|                    |        | additional referenced objects are found.      |
|                    |        | Defaults to 0.                                |
+--------------------+--------+-----------------------------------------------+
| excluded_entities  | list   | Entity handles to not perform lookups.        |
|                    |        | Defaults to None.                             |
+--------------------+--------+-----------------------------------------------+
| rate_limit_timeout | int    | The number of seconds to wait before retrying |
|                    |        | when a rate limit notice isreturned via       |
|                    |        | rdap+json. Defaults to 60.                    |
+--------------------+--------+-----------------------------------------------+
| socket_timeout     | int    | The default timeout for socket connections in |
|                    |        | seconds. Defaults to 10.                      |
+--------------------+--------+-----------------------------------------------+
| asn_timeout        | int    | The default timeout for bulk ASN lookups in   |
|                    |        | seconds. Defaults to 240.                     |
+--------------------+--------+-----------------------------------------------+
| proxy_openers      | list   | List of urllib.request.OpenerDirector proxy   |
|                    |        | openers for single/rotating proxy support.    |
|                    |        | Defaults to None.                             |
+--------------------+--------+-----------------------------------------------+

.. _bulk_lookup_rdap-output:

Output
------

The output namedtuple from ipwhois.experimental.bulk_lookup_rdap().

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| results          | dict   | IP address keys with the values as dictionaries |
|                  |        | returned by `IPWhois.lookup_rdap()              |
|                  |        | <https://ipwhois.readthedocs.io/en/latest/      |
|                  |        | RDAP.html#results-dictionary>`_                 |
+------------------+--------+-------------------------------------------------+
| stats            | dict   | Stats for the lookup containing the keys        |
|                  |        | identified in :ref:`bulk_lookup_rdap-stats`     |
+------------------+--------+-------------------------------------------------+

.. _bulk_lookup_rdap-stats:

Stats Dictionary
^^^^^^^^^^^^^^^^

The stats dictionary returned by ipwhois.experimental.bulk_lookup_rdap()

::

    {
        'ip_input_total' (int) - The total number of addresses
            originally provided for lookup via the addresses argument.
        'ip_unique_total' (int) - The total number of unique addresses
            found in the addresses argument.
        'ip_lookup_total' (int) - The total number of addresses that
            lookups were attempted for, excluding any that failed ASN
            registry checks.
        'lacnic' (dict) -
        {
            'failed' (list) - The addresses that failed to lookup.
                Excludes any that failed initially, but succeeded after
                futher retries.
            'rate_limited' (list) - The addresses that encountered
                rate-limiting. Unless an address is also in 'failed',
                it eventually succeeded.
            'total' (int) - The total number of addresses belonging to
                this RIR that lookups were attempted for.
        }
        'ripencc' (dict) - Same as 'lacnic' above.
        'apnic' (dict) - Same as 'lacnic' above.
        'afrinic' (dict) - Same as 'lacnic' above.
        'arin' (dict) - Same as 'lacnic' above.
        'unallocated_addresses' (list) - The addresses that are
            unallocated/failed ASN lookups. These can be addresses that
            are not listed for one of the 5 RIRs (other). No attempt
            was made to perform an RDAP lookup for these.
    }

.. _bulk_lookup_rdap-examples:

Usage Examples
--------------

Basic usage
^^^^^^^^^^^

.. BULK_LOOKUP_RDAP_OUTPUT_BASIC START

::

    >>>> from ipwhois.experimental import bulk_lookup_rdap
    >>>> from pprint import pprint

    >>>> ip_list = ['74.125.225.229', '2001:4860:4860::8888', '62.239.237.1', '2a00:2381:ffff::1', '210.107.73.73', '2001:240:10c:1::ca20:9d1d', '200.57.141.161', '2801:10:c000::', '196.11.240.215', '2001:43f8:7b0::', '133.1.2.5', '115.1.2.3']
    >>>> results, stats = bulk_lookup_rdap(addresses=ip_list)
    >>>> pprint(stats)

    {
    "afrinic": {
        "failed": [],
        "rate_limited": [],
        "total": 2
    },
    "apnic": {
        "failed": [
            "115.1.2.3"
        ],
        "rate_limited": [],
        "total": 4
    },
    "arin": {
        "failed": [],
        "rate_limited": [],
        "total": 2
    },
    "ip_input_total": 12,
    "ip_lookup_total": 12,
    "ip_unique_total": 12,
    "lacnic": {
        "failed": [],
        "rate_limited": [],
        "total": 2
    },
    "ripencc": {
        "failed": [],
        "rate_limited": [],
        "total": 2
    },
    "unallocated_addresses": []
    }

.. BULK_LOOKUP_RDAP_OUTPUT_BASIC END
