================================
NIR (National Internet Registry)
================================

IPWhois.nir provides functionality for national registries which restrict
information on regional registries. Currently, JPNIC (Japan) and KRNIC
(South Korea) are supported.

Input (IPWhois Wrapper)
=======================

NIR is included by default (inc_nir=True) in the wrapper functions:
IPWhois.lookup(), IPWhois.lookup_rdap(). For use with the wrappers, see the
following input documentation links:

RDAP documentation:

https://secynic.github.io/ipwhois/RDAP.html#input

https://github.com/secynic/ipwhois/blob/master/RDAP.rst#input

Legacy Whois documentation:

https://secynic.github.io/ipwhois/WHOIS.html#input

https://github.com/secynic/ipwhois/blob/master/WHOIS.rst#input

Input (Direct)
==============

If you prefer to use NIRWhois(net).lookup() directly, here are the input
arguments for that function call:

+-------------+--------+------------------------------------------------------+
| **Key**     |**Type**| **Description**                                      |
+-------------+--------+------------------------------------------------------+
| nir         | String | The NIR to query ('jpnic' or 'krnic').               |
+-------------+--------+------------------------------------------------------+
| inc_raw     | Bool   | Boolean for whether to include the raw NIR whois     |
|             |        | results in the returned dictionary.                  |
+-------------+--------+------------------------------------------------------+
| retry_count | Int    | The number of times to retry in case socket errors,  |
|             |        | timeouts, connection resets, etc. are encountered.   |
+-------------+--------+------------------------------------------------------+
| response    | String | Optional response object, this bypasses the NIR      |
|             |        | lookup.                                              |
+-------------+--------+------------------------------------------------------+
| field_list  | List   | If provided, a list of fields to parse:              |
|             |        | ['name', 'handle', 'country', 'address',             |
|             |        | 'postal_code', 'nameservers', 'created',             |
|             |        | 'updated', 'contacts']                               |
+-------------+--------+------------------------------------------------------+
| is_offline  | Bool   | Boolean for whether to perform lookups offline.      |
|             |        | If True, response and asn_data must be provided.     |
|             |        | Primarily used for testing.                          |
+-------------+--------+------------------------------------------------------+

Output
======

If calling via an IPWhois wrapper, the NIR results are added to the RDAP/WHOIS
result dictionary under the key 'nir'.

Results Dictionary
------------------

The NIR output dictionary (key: nir) from IPWhois.lookup() or
IPWhois.lookup_whois() results.

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| query            | String | The IP address input                            |
+------------------+--------+-------------------------------------------------+
| nets             | List   | List of network dictionaries.                   |
|                  |        | See `Network Dictionary <#network-dictionary>`_.|
+------------------+--------+-------------------------------------------------+
| raw              | String | Raw NIR whois results if inc_raw is True.       |
+------------------+--------+-------------------------------------------------+

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
`Results Dictionary <#results-dictionary>`_.

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
| country     | String | Country code registered with the NIR in ISO 3166-1   |
|             |        | format.                                              |
+-------------+--------+------------------------------------------------------+
| address     | String | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | String | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| nameservers | String | The nameservers listed for a registered network,     |
|             |        | separated by '\n\'                                   |
+-------------+--------+------------------------------------------------------+
| created     | String | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | String | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+
| contacts    | Dict   | Dictionary with keys: admin, tech. Values map to     |
|             |        | contact dictionaries if found. See                   |
|             |        | `Contact Dictionary <#contact-dictionary>`_.         |
+-------------+--------+------------------------------------------------------+

Contact Dictionary
^^^^^^^^^^^^^^^^^^

The contact information dictionary registered to a NIR network object. This is
'contacts' -> 'admin'/'tech' key in
`Network Dictionary <#network-dictionary>`_.

+--------------+--------+-----------------------------------------------------+
| **Key**      |**Type**| **Description**                                     |
+--------------+--------+-----------------------------------------------------+
| name         | String | The contact's name.                                 |
+--------------+--------+-----------------------------------------------------+
| organization | String | The contact's organization.                         |
+--------------+--------+-----------------------------------------------------+
| division     | String | The contact's division of the organization.         |
+--------------+--------+-----------------------------------------------------+
| email        | String | Contact email address.                              |
+--------------+--------+-----------------------------------------------------+
| reply_email  | String | Contact reply email address.                        |
+--------------+--------+-----------------------------------------------------+
| updated      | String | Updated date in ISO 8601 format.                    |
+--------------+--------+-----------------------------------------------------+
| phone        | String | Contact phone number.                               |
+--------------+--------+-----------------------------------------------------+
| fax          | String | Contact fax number.                                 |
+--------------+--------+-----------------------------------------------------+
| title        | String | The contact's position or job title.                |
+--------------+--------+-----------------------------------------------------+

Usage Examples
==============

Basic usage
-----------

inc_nir defaults to true in IPWhois.lookup_*(), but I will set it here to
show the usage and results.

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_whois(inc_nir=True)

    TODO: Output

    >>>> results = obj.lookup_rdap(depth=1, inc_nir=True)

    TODO: Output

