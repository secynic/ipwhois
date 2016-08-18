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

.. OUTPUT_BASIC START

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('133.1.2.5')
    >>>> results = obj.lookup_whois(inc_nir=True)

    {
    "asn": "4730",
    "asn_cidr": "133.1.0.0/16",
    "asn_country_code": "JP",
    "asn_date": "",
    "asn_registry": "apnic",
    "nets": [
        {
            "address": "Urbannet-Kanda Bldg 4F, 3-6-2 Uchi-Kanda, Chiyoda-ku, Tokyo 101-0047,Japan",
            "cidr": "133.0.0.0/8",
            "city": null,
            "country": "JP",
            "created": null,
            "description": "Japan Network Information Center",
            "emails": "hm-changed@apnic.net, hostmaster@nic.ad.jp, ip-apnic@nic.ad.jp",
            "handle": "JNIC1-AP",
            "name": "JPNIC-NET-JP-ERX",
            "postal_code": null,
            "range": "133.0.0.0 - 133.255.255.255",
            "state": null,
            "updated": "20120828"
        }
    ],
    "nir": {
        "nets": [
            {
                "address": null,
                "cidr": "133.1.0.0/16",
                "contacts": {
                    "admin": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Yoshihide, Minami",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "reg@jpdirect.jp",
                        "title": "Specialist",
                        "updated": "2015-08-13T09:08:34"
                    },
                    "tech": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Yoshihide, Minami",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "reg@jpdirect.jp",
                        "title": "Specialist",
                        "updated": "2015-08-13T09:08:34"
                    }
                },
                "country": "JP",
                "created": null,
                "handle": "OSAKAU-NET",
                "name": "Osaka University",
                "nameservers": "a.osaka-u.ac.jp, b.osaka-u.ac.jp, dns-x.sinet.ad.jp",
                "postal_code": null,
                "range": "133.1.0.1 - 133.1.255.255",
                "updated": "2015-01-14T02:50:03"
            }
        ],
        "query": "133.1.2.5",
        "raw": null
    },
    "query": "133.1.2.5",
    "raw": null,
    "raw_referral": null,
    "referral": null
    }

    >>>> results = obj.lookup_rdap(depth=1, inc_nir=True)

    {
    "asn": "4730",
    "asn_cidr": "133.1.0.0/16",
    "asn_country_code": "JP",
    "asn_date": "",
    "asn_registry": "apnic",
    "entities": [
        "JNIC1-AP"
    ],
    "network": {
        "cidr": "133.0.0.0/8",
        "country": "JP",
        "end_address": "133.255.255.255",
        "events": [
            {
                "action": "last changed",
                "actor": null,
                "timestamp": "2009-10-30T00:51:09Z"
            }
        ],
        "handle": "133.0.0.0 - 133.255.255.255",
        "ip_version": "v4",
        "links": [
            "http://rdap.apnic.net/ip/133.0.0.0/8"
        ],
        "name": "JPNIC-NET-JP-ERX",
        "notices": [
            {
                "description": "This is the APNIC WHOIS Database query service. The objects are in RDAP format.",
                "links": [
                    "http://www.apnic.net/db/dbcopyright.html"
                ],
                "title": "Terms and Conditions"
            }
        ],
        "parent_handle": null,
        "raw": null,
        "remarks": [],
        "start_address": "133.0.0.0",
        "status": null,
        "type": "ALLOCATED PORTABLE"
    },
    "nir": {
        "nets": [
            {
                "address": null,
                "cidr": "133.1.0.0/16",
                "contacts": {
                    "admin": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Yoshihide, Minami",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "reg@jpdirect.jp",
                        "title": "Specialist",
                        "updated": "2015-08-13T09:08:34"
                    },
                    "tech": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Yoshihide, Minami",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "reg@jpdirect.jp",
                        "title": "Specialist",
                        "updated": "2015-08-13T09:08:34"
                    }
                },
                "country": "JP",
                "created": null,
                "handle": "OSAKAU-NET",
                "name": "Osaka University",
                "nameservers": "a.osaka-u.ac.jp, b.osaka-u.ac.jp, dns-x.sinet.ad.jp",
                "postal_code": null,
                "range": "133.1.0.1 - 133.1.255.255",
                "updated": "2015-01-14T02:50:03"
            }
        ],
        "query": "133.1.2.5",
        "raw": null
    },
    "objects": {
        "JNIC1-AP": {
            "contact": {
                "address": [
                    {
                        "type": null,
                        "value": "Urbannet-Kanda Bldg 4F\, 3-6-2 Uchi-Kanda\, Chiyoda-ku, Tokyo 101-0047,Japan"
                    }
                ],
                "email": [
                    {
                        "type": null,
                        "value": "hostmaster@nic.ad.jp"
                    }
                ],
                "kind": "group",
                "name": "Japan Network Information Center",
                "phone": [
                    {
                        "type": "voice",
                        "value": "+81-3-5297-2311"
                    },
                    {
                        "type": "fax",
                        "value": "+81-3-5297-2312"
                    }
                ],
                "role": null,
                "title": null
            },
            "entities": null,
            "events": null,
            "events_actor": null,
            "handle": "JNIC1-AP",
            "links": [
                "http://rdap.apnic.net/entity/JNIC1-AP"
            ],
            "notices": null,
            "raw": null,
            "remarks": null,
            "roles": [
                "technical",
                "administrative"
            ],
            "status": null
        }
    },
    "query": "133.1.2.5",
    "raw": null
    }

.. OUTPUT_BASIC END
