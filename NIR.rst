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
| nir         | str    | The NIR to query ('jpnic' or 'krnic').               |
+-------------+--------+------------------------------------------------------+
| inc_raw     | bool   | Whether to include the raw whois results in          |
|             |        | the returned dictionary. Defaults to False.          |
+-------------+--------+------------------------------------------------------+
| retry_count | int    | The number of times to retry in case socket errors,  |
|             |        | timeouts, connection resets, etc. are encountered.   |
|             |        | Defaults to 3.                                       |
+-------------+--------+------------------------------------------------------+
| response    | str    | Optional response object, this bypasses the NIR      |
|             |        | lookup.                                              |
+-------------+--------+------------------------------------------------------+
| field_list  | list   | If provided, a list of fields to parse:              |
|             |        | ['name', 'handle', 'country', 'address',             |
|             |        | 'postal_code', 'nameservers', 'created',             |
|             |        | 'updated', 'contacts']. If None, defaults to all.    |
+-------------+--------+------------------------------------------------------+
| is_offline  | bool   | Whether to perform lookups offline.                  |
|             |        | If True, response and asn_data must be provided.     |
|             |        | Primarily used for testing. Defaults to False.       |
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
| query            | str    | The IP address input                            |
+------------------+--------+-------------------------------------------------+
| nets             | list   | List of network dictionaries.                   |
|                  |        | See :ref:`nir-network-dictionary`.              |
+------------------+--------+-------------------------------------------------+
| raw              | str    | Raw NIR whois results if inc_raw is True.       |
+------------------+--------+-------------------------------------------------+

.. _nir-network-dictionary:

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the nets key in the
:ref:`nir-results-dictionary`.

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
| country     | str    | Country code registered with the NIR in ISO 3166-1   |
|             |        | format.                                              |
+-------------+--------+------------------------------------------------------+
| address     | str    | The mailing address for a registered network.        |
+-------------+--------+------------------------------------------------------+
| postal_code | str    | The postal code for a registered network.            |
+-------------+--------+------------------------------------------------------+
| nameservers | list   | The nameservers listed for a registered network.     |
+-------------+--------+------------------------------------------------------+
| created     | str    | Network registration date in ISO 8601 format.        |
+-------------+--------+------------------------------------------------------+
| updated     | str    | Network registration updated date in ISO 8601 format.|
+-------------+--------+------------------------------------------------------+
| contacts    | dict   | Dictionary with keys: admin, tech. Values map to     |
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
| name         | str    | The contact's name.                                 |
+--------------+--------+-----------------------------------------------------+
| organization | str    | The contact's organization.                         |
+--------------+--------+-----------------------------------------------------+
| division     | str    | The contact's division of the organization.         |
+--------------+--------+-----------------------------------------------------+
| email        | str    | Contact email address.                              |
+--------------+--------+-----------------------------------------------------+
| reply_email  | str    | Contact reply email address.                        |
+--------------+--------+-----------------------------------------------------+
| updated      | str    | Updated date in ISO 8601 format.                    |
+--------------+--------+-----------------------------------------------------+
| phone        | str    | Contact phone number.                               |
+--------------+--------+-----------------------------------------------------+
| fax          | str    | Contact fax number.                                 |
+--------------+--------+-----------------------------------------------------+
| title        | str    | The contact's position or job title.                |
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
    "asn_date": "1997-03-01",
    "asn_description": "ODINS Osaka University, JP",
    "asn_registry": "apnic",
    "nets": [
        {
            "address": "Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda\nChiyoda-ku, Tokyo 101-0047, japan",
            "cidr": "133.0.0.0/8",
            "city": None,
            "country": "JP",
            "created": None,
            "description": "Japan Network Information Center",
            "emails": [
                "hostmaster@nic.ad.jp"
            ],
            "handle": "AJ382-AP",
            "name": "JPNIC-NET-JP-ERX",
            "postal_code": None,
            "range": "133.0.0.0 - 133.255.255.255",
            "state": None,
            "updated": None
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
                        "name": "Minami, Yoshihide",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "odins-room@odins.osaka-u.ac.jp",
                        "title": "Specialist",
                        "updated": "2022-06-30T03:50:03"
                    },
                    "tech": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Minami, Yoshihide",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "odins-room@odins.osaka-u.ac.jp",
                        "title": "Specialist",
                        "updated": "2022-06-30T03:50:03"
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
                "updated": "2022-07-15T05:50:05"
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
    "asn_date": "1997-03-01",
    "asn_description": "ODINS Osaka University, JP",
    "asn_registry": "apnic",
    "entities": [
        "JNIC1-AP",
        "IRT-JPNIC-JP"
    ],
    "network": {
        "cidr": "133.0.0.0/8",
        "country": "JP",
        "end_address": "133.255.255.255",
        "events": [
            {
                "action": "registration",
                "actor": None,
                "timestamp": "2022-11-01T04:33:10Z"
            },
            {
                "action": "last changed",
                "actor": None,
                "timestamp": "2022-11-01T04:33:10Z"
            }
        ],
        "handle": "133.0.0.0 - 133.255.255.255",
        "ip_version": "v4",
        "links": [
            "https://rdap.apnic.net/ip/133.0.0.0/8",
            "https://netox.apnic.net/search/133.0.0.0%2F8?utm_source=rdap&utm_medium=result&utm_campaign=rdap_result"
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
            },
            {
                "description": "If you see inaccuracies in the results, please visit: ",
                "links": [
                    "https://www.apnic.net/manage-ip/using-whois/abuse-and-spamming/invalid-contact-form"
                ],
                "title": "Whois Inaccuracy Reporting"
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
        "status": [
            "active"
        ],
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
                        "name": "Minami, Yoshihide",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "odins-room@odins.osaka-u.ac.jp",
                        "title": "Specialist",
                        "updated": "2022-06-30T03:50:03"
                    },
                    "tech": {
                        "division": "Department of Information and Communications Technology Services",
                        "email": "odins-room@odins.osaka-u.ac.jp",
                        "fax": "06-6879-8988",
                        "name": "Minami, Yoshihide",
                        "organization": "Osaka University",
                        "phone": "06-6879-8815",
                        "reply_email": "odins-room@odins.osaka-u.ac.jp",
                        "title": "Specialist",
                        "updated": "2022-06-30T03:50:03"
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
                "updated": "2022-07-15T05:50:05"
            }
        ],
        "query": "133.1.2.5",
        "raw": None
    },
    "objects": {
        "IRT-JPNIC-JP": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda\nChiyoda-ku, Tokyo 101-0047, japan"
                    }
                ],
                "email": [
                    {
                        "type": None,
                        "value": "hostmaster@nic.ad.jp"
                    },
                    {
                        "type": None,
                        "value": "hostmaster@nic.ad.jp"
                    }
                ],
                "kind": "group",
                "name": "IRT-JPNIC-JP",
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
            "events": [
                {
                    "action": "registration",
                    "actor": None,
                    "timestamp": "2010-11-08T01:21:46Z"
                },
                {
                    "action": "last changed",
                    "actor": None,
                    "timestamp": "2024-09-28T21:13:03Z"
                }
            ],
            "events_actor": None,
            "handle": "IRT-JPNIC-JP",
            "links": [
                "https://rdap.apnic.net/entity/IRT-JPNIC-JP"
            ],
            "notices": None,
            "raw": None,
            "remarks": [
                {
                    "description": "hostmaster@nic.ad.jp is invalid",
                    "links": None,
                    "title": "remarks"
                }
            ],
            "roles": [
                "abuse"
            ],
            "status": None
        },
        "JNIC1-AP": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "Uchikanda OS Bldg 4F, 2-12-6 Uchi-Kanda\nChiyoda-ku, Tokyo 101-0047, Japan"
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
            "events": [
                {
                    "action": "registration",
                    "actor": None,
                    "timestamp": "2008-09-04T07:54:15Z"
                },
                {
                    "action": "last changed",
                    "actor": None,
                    "timestamp": "2022-01-05T03:04:02Z"
                }
            ],
            "events_actor": None,
            "handle": "JNIC1-AP",
            "links": [
                "https://rdap.apnic.net/entity/JNIC1-AP"
            ],
            "notices": None,
            "raw": None,
            "remarks": None,
            "roles": [
                "administrative",
                "technical"
            ],
            "status": None
        }
    },
    "query": "133.1.2.5",
    "raw": None
    }

.. OUTPUT_BASIC END
