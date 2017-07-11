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

.. _get_bulk_asn_whois-input:

Input
-----

Arguments supported by ipwhois.experimental.get_bulk_asn_whois().

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| addresses          | List   | List of IP address strings to lookup.         |
+--------------------+--------+-----------------------------------------------+
| retry_count        | Int    | The number of times to retry in case socket   |
|                    |        | errors, timeouts, connection resets, etc. are |
|                    |        | encountered. Defaults to 3.                   |
+--------------------+--------+-----------------------------------------------+
| timeout            | Int    | The default timeout for socket connections in |
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

.. GET_BULK_ASN_WHOIS_OUTPUT_BASIC END

Bulk RDAP Lookups
=================

.. _bulk_lookup_rdap-input:

Input
-----

Arguments supported by ipwhois.experimental.bulk_lookup_rdap().

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| addresses          | List   | List of IP address strings to lookup.         |
+--------------------+--------+-----------------------------------------------+
| inc_raw            | Bool   | Whether to include the raw whois results in   |
|                    |        | the returned dictionary. Defaults to False.   |
+--------------------+--------+-----------------------------------------------+
| retry_count        | Int    | The number of times to retry in case socket   |
|                    |        | errors, timeouts, connection resets, etc. are |
|                    |        | encountered. Defaults to 3.                   |
+--------------------+--------+-----------------------------------------------+
| depth              | Int    | How many levels deep to run queries when      |
|                    |        | additional referenced objects are found.      |
|                    |        | Defaults to 0.                                |
+--------------------+--------+-----------------------------------------------+
| excluded_entities  | List   | Entity handles to not perform lookups.        |
|                    |        | Defaults to None.                             |
+--------------------+--------+-----------------------------------------------+
| rate_limit_timeout | Int    | The number of seconds to wait before retrying |
|                    |        | when a rate limit notice isreturned via       |
|                    |        | rdap+json. Defaults to 60.                    |
+--------------------+--------+-----------------------------------------------+
| socket_timeout     | Int    | The default timeout for socket connections in |
|                    |        | seconds. Defaults to 10.                      |
+--------------------+--------+-----------------------------------------------+
| asn_timeout        | Int    | The default timeout for bulk ASN lookups in   |
|                    |        | seconds. Defaults to 240.                     |
+--------------------+--------+-----------------------------------------------+
| proxy_openers      | List   | List of urllib.request.OpenerDirector proxy   |
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
| results          | Dict   | IP address keys with the values as dictionaries |
|                  |        | returned by IPWhois.lookup_rdap().              |
+------------------+--------+-------------------------------------------------+
| stats            | Dict   | Stats for the lookup containing the keys        |
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

.. BULK_LOOKUP_RDAP_OUTPUT_BASIC END
