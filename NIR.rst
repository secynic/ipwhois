================================
NIR (National Internet Registry)
================================

IPWhois.nir provides functionality for national registries which restrict
information on regional registries. Currently, JPNIC (Japan) and KRNIC
(South Korea) are supported.

.. _nir-input-ipwhois-wrapper:

Input (IPWhois Wrapper)
=======================

NIR is included by default (inc_nir=True) in the wrapper functions:
IPWhois.lookup(), IPWhois.lookup_rdap(). For use with the wrappers, see the
following input documentation links:

RDAP documentation:

https://ipwhois.readthedocs.io/en/latest/RDAP.html#input

Legacy Whois documentation:

https://ipwhois.readthedocs.io/en/latest/WHOIS.html#input

.. _nir-input-direct:

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

.. _nir-output:

Output
======

If calling via an IPWhois wrapper, the NIR results are added to the RDAP/WHOIS
result dictionary under the key 'nir'.

.. _nir-results-dictionary:

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
|                  |        | See :ref:`nir-network-dictionary`.              |
+------------------+--------+-------------------------------------------------+
| raw              | String | Raw NIR whois results if inc_raw is True.       |
+------------------+--------+-------------------------------------------------+

.. _nir-network-dictionary:

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`nir-results-dictionary`.

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
| nameservers | List   | The nameservers listed for a registered network.     |
+-------------+--------+------------------------------------------------------+
| created     | String | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | String | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+
| contacts    | Dict   | Dictionary with keys: admin, tech. Values map to     |
|             |        | contact dictionaries if found. See                   |
|             |        | :ref:`nir-contact-dictionary`.                       |
+-------------+--------+------------------------------------------------------+

.. _nir-contact-dictionary:

Contact Dictionary
^^^^^^^^^^^^^^^^^^

The contact information dictionary registered to a NIR network object. This is
'contacts' -> 'admin'/'tech' key in
:ref:`nir-network-dictionary`.

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

.. _nir-usage-examples:

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
    >>>> pprint(results)

    {
    "asn": "4730",
    "asn_cidr": "133.1.0.0/16",
    "asn_country_code": "JP",
    "asn_date": "",
    "asn_description": "ODINS Osaka University, JP",
    "asn_registry": "apnic",
    "nets": [
        {
            "address": "Urbannet-Kanda Bldg 4F\n3-6-2 Uchi-Kanda\nChiyoda-ku, Tokyo 101-0047,Japan",
            "cidr": "133.0.0.0/8",
            "city": None,
            "country": "JP",
            "created": None,
            "description": "Japan Network Information Center",
            "emails": [
                "hm-changed@apnic.net",
                "hostmaster@nic.ad.jp",
                "ip-apnic@nic.ad.jp"
            ],
            "handle": "JNIC1-AP",
            "name": "JPNIC-NET-JP-ERX",
            "postal_code": None,
            "range": "133.0.0.0 - 133.255.255.255",
            "state": None,
            "updated": "20120828"
        }
    ],
    "nir": {
        "nets": [
            {
                "address": None,
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
                "created": None,
                "handle": "OSAKAU-NET",
                "name": "Osaka University",
                "nameservers": [
                    "a.osaka-u.ac.jp",
                    "b.osaka-u.ac.jp",
                    "dns-x.sinet.ad.jp"
                ],
                "postal_code": None,
                "range": "133.1.0.1 - 133.1.255.255",
                "updated": "2015-01-14T02:50:03"
            }
        ],
        "query": "133.1.2.5",
        "raw": None
    },
    "query": "133.1.2.5",
    "raw": None,
    "raw_referral": None,
    "referral": None
    }

    >>>> results = obj.lookup_rdap(depth=1, inc_nir=True)
    >>>> pprint(results)

    {
    "asn": "4730",
    "asn_cidr": "133.1.0.0/16",
    "asn_country_code": "JP",
    "asn_date": "",
    "asn_description": "ODINS Osaka University, JP",
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
                "actor": None,
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
                "description": "Objects returned came from source\nAPNIC",
                "links": None,
                "title": "Source"
            },
            {
                "description": "This is the APNIC WHOIS Database query service. The objects are in RDAP format.",
                "links": [
                    "http://www.apnic.net/db/dbcopyright.html"
                ],
                "title": "Terms and Conditions"
            }
        ],
        "parent_handle": None,
        "raw": None,
        "remarks": [
            {
                "description": "Japan Network Information Center",
                "links": None,
                "title": "description"
            },
            {
                "description": "133/8 block is an ERX range which transfered from\nARIN to APNIC on 2009-10-30\nThe original allocation date was 1997-03-01\nPlease search whois.nic.ad.jp for more information\nabout this range\n% whois -h whois.nic.ad.jp ***.***.***.***/e",
                "links": None,
                "title": "remarks"
            }
        ],
        "start_address": "133.0.0.0",
        "status": None,
        "type": "ALLOCATED PORTABLE"
    },
    "nir": {
        "nets": [
            {
                "address": None,
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
                "created": None,
                "handle": "OSAKAU-NET",
                "name": "Osaka University",
                "nameservers": [
                    "a.osaka-u.ac.jp",
                    "b.osaka-u.ac.jp",
                    "dns-x.sinet.ad.jp"
                ],
                "postal_code": None,
                "range": "133.1.0.1 - 133.1.255.255",
                "updated": "2015-01-14T02:50:03"
            }
        ],
        "query": "133.1.2.5",
        "raw": None
    },
    "objects": {
        "JNIC1-AP": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "Urbannet-Kanda Bldg 4F\n3-6-2 Uchi-Kanda\nChiyoda-ku, Tokyo 101-0047,Japan"
                    }
                ],
                "email": [
                    {
                        "type": None,
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
                "role": None,
                "title": None
            },
            "entities": None,
            "events": None,
            "events_actor": None,
            "handle": "JNIC1-AP",
            "links": [
                "http://rdap.apnic.net/entity/JNIC1-AP"
            ],
            "notices": None,
            "raw": None,
            "remarks": None,
            "roles": [
                "technical",
                "administrative"
            ],
            "status": None
        }
    },
    "query": "133.1.2.5",
    "raw": None
    }

.. OUTPUT_BASIC END
