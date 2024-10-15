===================
RDAP (HTTP) Lookups
===================

IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

.. _rdap-input:

Input
=====

Arguments supported by IPWhois.lookup_rdap().

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
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
| bootstrap          | bool   | If True, performs lookups via ARIN bootstrap  |
|                    |        | rather than lookups based on ASN data. ASN    |
|                    |        | lookups are not performed and no output for   |
|                    |        | any of the asn* fields is provided. Defaults  |
|                    |        | to False.                                     |
+--------------------+--------+-----------------------------------------------+
| rate_limit_timeout | int    | The number of seconds to wait before retrying |
|                    |        | when a rate limit notice is returned via      |
|                    |        | rdap+json. Defaults to 120.                   |
+--------------------+--------+-----------------------------------------------+
| extra_org_map      | dict   | Dictionary mapping org handles to RIRs.       |
|                    |        | This is for limited cases where ARIN REST     |
|                    |        | (ASN fallback HTTP lookup) does not show an   |
|                    |        | RIR as the org handle e.g., DNIC (which       |
|                    |        | is now built in ORG_MAP)                      |
|                    |        | e.g., {'DNIC': 'arin'}. Valid RIR             |
|                    |        | values are (note the case-sensitive - this is |
|                    |        | meant to match the REST result):              |
|                    |        | 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'  |
|                    |        | Defaults to None.                             |
+--------------------+--------+-----------------------------------------------+
| inc_nir            | bool   | Whether to retrieve NIR (National Internet    |
|                    |        | Registry) information, if registry is JPNIC   |
|                    |        | (Japan) or KRNIC (Korea). If True, extra      |
|                    |        | network requests will be required. If False,  |
|                    |        | the information returned for JP or KR IPs is  |
|                    |        | severely restricted. Defaults to True.        |
+--------------------+--------+-----------------------------------------------+
| nir_field_list     | list   | If provided and inc_nir, a list of            |
|                    |        | fields to parse: ['name', 'handle', 'country',|
|                    |        | 'address', 'postal_code', 'nameservers',      |
|                    |        | 'created', 'updated', 'contacts']             |
|                    |        | If None, defaults to all.                     |
+--------------------+--------+-----------------------------------------------+
| asn_methods        | list   | ASN lookup types to attempt, in order. If     |
|                    |        | None, defaults to all ['dns', 'whois', 'http']|
+--------------------+--------+-----------------------------------------------+
| get_asn_description| bool   | Whether to run an additional query when       |
|                    |        | pulling ASN information via dns, in order to  |
|                    |        | get the ASN description. Defaults to True.    |
+--------------------+--------+-----------------------------------------------+
| root_ent_check     | bool   | If True, will perform additional RDAP HTTP    |
|                    |        | queries for missing entity data at the root   |
|                    |        | level. Defaults to True.                      |
+--------------------+--------+-----------------------------------------------+

.. _rdap-output:

Output
======

.. _rdap-results-dictionary:

Results Dictionary
------------------

The output dictionary from IPWhois.lookup_rdap(). Contains many nested lists
and dictionaries, detailed below this section.

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| query            | str    | The IP address                                  |
+------------------+--------+-------------------------------------------------+
| asn              | str    | Globally unique identifier used for routing     |
|                  |        | information exchange with Autonomous Systems.   |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | str    | Network routing block assigned to an ASN.       |
+------------------+--------+-------------------------------------------------+
| asn_country_code | str    | ASN assigned country code in ISO 3166-1 format. |
+------------------+--------+-------------------------------------------------+
| asn_date         | str    | ASN allocation date in ISO 8601 format.         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | str    | ASN assigned regional internet registry.        |
+------------------+--------+-------------------------------------------------+
| asn_description  | str    | The ASN description                             |
+------------------+--------+-------------------------------------------------+
| network          | dict   | The assigned network for an IP address. May be  |
|                  |        | a parent or child network. See                  |
|                  |        | :ref:`rdap-network-dictionary`.                 |
+------------------+--------+-------------------------------------------------+
| entities         | list   | list of object names referenced by an RIR       |
|                  |        | network. Map these to the objects dict keys.    |
+------------------+--------+-------------------------------------------------+
| objects          | dict   | The objects (entities) referenced by an RIR     |
|                  |        | network or by other entities (depending on      |
|                  |        | depth parameter). Keys are the object names     |
|                  |        | with values as                                  |
|                  |        | :ref:`rdap-objects-dictionary`.                 |
+------------------+--------+-------------------------------------------------+
| raw              | dict   | The raw results dictionary (JSON) if            |
|                  |        | inc_raw is True.                                |
+------------------+--------+-------------------------------------------------+
| nir              | dict   | The National Internet Registry results if       |
|                  |        | inc_nir is True. See `NIR result <https://      |
|                  |        | ipwhois.readthedocs.io/en/latest/NIR.html       |
|                  |        | #results-dictionary>`_                          |
+------------------+--------+-------------------------------------------------+

.. _rdap-network-dictionary:

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the network key in the objects list within
:ref:`rdap-results-dictionary`.

+---------------+--------+----------------------------------------------------+
| **Key**       |**Type**| **Description**                                    |
+---------------+--------+----------------------------------------------------+
| cidr          | str    | Network routing block an IP address belongs to.    |
+---------------+--------+----------------------------------------------------+
| country       | str    | Country code registered with the RIR in            |
|               |        | ISO 3166-1 format.                                 |
+---------------+--------+----------------------------------------------------+
| end_address   | str    | The last IP address in a network block.            |
+---------------+--------+----------------------------------------------------+
| events        | list   | List of event dictionaries. See                    |
|               |        | :ref:`rdap-events-dictionary`.                     |
+---------------+--------+----------------------------------------------------+
| handle        | str    | Unique identifier for a registered object.         |
+---------------+--------+----------------------------------------------------+
| ip_version    | str    | IP protocol version (v4 or v6) of an IP address.   |
+---------------+--------+----------------------------------------------------+
| links         | list   | HTTP/HTTPS links provided for an RIR object.       |
+---------------+--------+----------------------------------------------------+
| name          | str    | The identifier assigned to the network             |
|               |        | registration for an IP address.                    |
+---------------+--------+----------------------------------------------------+
| notices       | list   | List of notice dictionaries. See                   |
|               |        | :ref:`rdap-notices-dictionary`.                    |
+---------------+--------+----------------------------------------------------+
| parent_handle | str    | Unique identifier for the parent network of a      |
|               |        | registered network.                                |
+---------------+--------+----------------------------------------------------+
| remarks       | list   | List of remark (notice) dictionaries. See          |
|               |        | :ref:`rdap-notices-dictionary`.                    |
+---------------+--------+----------------------------------------------------+
| start_address | str    | The first IP address in a network block.           |
+---------------+--------+----------------------------------------------------+
| status        | list   | List indicating the state of a registered object.  |
+---------------+--------+----------------------------------------------------+
| type          | str    | The RIR classification of a registered network.    |
+---------------+--------+----------------------------------------------------+

.. _rdap-objects-dictionary:

Objects Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the object (entity) key in the objects list within
:ref:`rdap-results-dictionary`.

+--------------+--------+-----------------------------------------------------+
| **Key**      |**Type**| **Description**                                     |
+--------------+--------+-----------------------------------------------------+
| contact      | dict   | Contact information registered with an RIR object.  |
|              |        | See                                                 |
|              |        | :ref:`rdap-objects-contact-dictionary`.             |
+--------------+--------+-----------------------------------------------------+
| entities     | list   | List of object names referenced by an RIR object.   |
|              |        | Map these to other objects dictionary keys.         |
+--------------+--------+-----------------------------------------------------+
| events       | list   | List of event dictionaries. See                     |
|              |        | :ref:`rdap-events-dictionary`.                      |
+--------------+--------+-----------------------------------------------------+
| events_actor | list   | List of event (no actor) dictionaries. See          |
|              |        | :ref:`rdap-events-dictionary`.                      |
+--------------+--------+-----------------------------------------------------+
| handle       | str    | Unique identifier for a registered object.          |
+--------------+--------+-----------------------------------------------------+
| links        | list   | List of HTTP/HTTPS links provided for an RIR object.|
+--------------+--------+-----------------------------------------------------+
| notices      | list   | List of notice dictionaries. See                    |
|              |        | :ref:`rdap-notices-dictionary`.                     |
+--------------+--------+-----------------------------------------------------+
| remarks      | list   | List of remark (notice) dictionaries. See           |
|              |        | :ref:`rdap-notices-dictionary`.                     |
+--------------+--------+-----------------------------------------------------+
| roles        | list   | List of roles assigned to a registered object.      |
+--------------+--------+-----------------------------------------------------+
| status       | list   | List indicating the state of a registered object.   |
+--------------+--------+-----------------------------------------------------+

.. _rdap-objects-contact-dictionary:

Objects Contact Dictionary
^^^^^^^^^^^^^^^^^^^^^^^^^^

The contact information dictionary registered to an RIR object. This is the
contact key contained in :ref:`rdap-objects-dictionary`.

+---------+--------+----------------------------------------------------------+
| **Key** |**Type**| **Description**                                          |
+---------+--------+----------------------------------------------------------+
| address | list   | List of contact postal address dictionaries. Contains key|
|         |        | type and value.                                          |
+---------+--------+----------------------------------------------------------+
| email   | list   | List of contact email address dictionaries. Contains key |
|         |        | type and value.                                          |
+---------+--------+----------------------------------------------------------+
| kind    | str    | The contact information kind (individual, group, org).   |
+---------+--------+----------------------------------------------------------+
| name    | str    | The contact name.                                        |
+---------+--------+----------------------------------------------------------+
| phone   | list   | List of contact phone number dictionaries. Contains key  |
|         |        | type and value.                                          |
+---------+--------+----------------------------------------------------------+
| role    | str    | The contact's role.                                      |
+---------+--------+----------------------------------------------------------+
| title   | str    | The contact's position or job title.                     |
+---------+--------+----------------------------------------------------------+

.. _rdap-events-dictionary:

Events Dictionary
^^^^^^^^^^^^^^^^^

Common to lists in :ref:`rdap-network-dictionary` and
:ref:`rdap-objects-dictionary`.
Contained in events and events_actor (no actor).

+-----------+--------+-------------------------------------------------+
| **Key**   |**Type**| **Description**                                 |
+-----------+--------+-------------------------------------------------+
| action    | str    | The reason for an event.                        |
+-----------+--------+-------------------------------------------------+
| timestamp | str    | The date an event occured in ISO 8601 format.   |
+-----------+--------+-------------------------------------------------+
| actor     | str    | The identifier for an event initiator (if any). |
+-----------+--------+-------------------------------------------------+

.. _rdap-notices-dictionary:

Notices Dictionary
^^^^^^^^^^^^^^^^^^

Common to lists in :ref:`rdap-network-dictionary` and
:ref:`rdap-objects-dictionary`. Contained in notices and remarks.

+-------------+--------+-------------------------------------------------+
| **Key**     |**Type**| **Description**                                 |
+-------------+--------+-------------------------------------------------+
| title       | str    | The title/header for a notice.                  |
+-------------+--------+-------------------------------------------------+
| description | str    | The description/body of a notice.               |
+-------------+--------+-------------------------------------------------+
| links       | list   | list of HTTP/HTTPS links provided for a notice. |
+-------------+--------+-------------------------------------------------+

.. _rdap-usage-examples:

Usage Examples
==============

Basic usage
-----------

.. OUTPUT_BASIC START

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_rdap(depth=1)
    >>>> pprint(results)

    {
    "asn": "15169",
    "asn_cidr": "74.125.225.0/24",
    "asn_country_code": "US",
    "asn_date": "2007-03-13",
    "asn_description": "GOOGLE, US",
    "asn_registry": "arin",
    "entities": [
        "GOGL"
    ],
    "network": {
        "cidr": "74.125.0.0/16",
        "country": None,
        "end_address": "74.125.255.255",
        "events": [
            {
                "action": "last changed",
                "actor": None,
                "timestamp": "2012-02-24T09:44:34-05:00"
            },
            {
                "action": "registration",
                "actor": None,
                "timestamp": "2007-03-13T12:09:54-04:00"
            }
        ],
        "handle": "NET-74-125-0-0-1",
        "ip_version": "v4",
        "links": [
            "https://rdap.arin.net/registry/ip/74.125.0.0",
            "https://whois.arin.net/rest/net/NET-74-125-0-0-1"
        ],
        "name": "GOOGLE",
        "notices": [
            {
                "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                "links": [
                    "https://www.arin.net/resources/registry/whois/tou/"
                ],
                "title": "Terms of Service"
            },
            {
                "description": "If you see inaccuracies in the results, please visit: ",
                "links": [
                    "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                ],
                "title": "Whois Inaccuracy Reporting"
            },
            {
                "description": "Copyright 1997-2024, American Registry for Internet Numbers, Ltd.",
                "links": None,
                "title": "Copyright Notice"
            }
        ],
        "parent_handle": "NET-74-0-0-0-0",
        "raw": None,
        "remarks": None,
        "start_address": "74.125.0.0",
        "status": [
            "active"
        ],
        "type": "DIRECT ALLOCATION"
    },
    "nir": None,
    "objects": {
        "ABUSE5250-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": None,
                        "value": "network-abuse@google.com"
                    }
                ],
                "kind": "group",
                "name": "Abuse",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-650-253-0000"
                    }
                ],
                "role": None,
                "title": None
            },
            "entities": None,
            "events": [
                {
                    "action": "last changed",
                    "actor": None,
                    "timestamp": "2024-08-01T17:54:23-04:00"
                },
                {
                    "action": "registration",
                    "actor": None,
                    "timestamp": "2015-11-06T15:36:35-05:00"
                }
            ],
            "events_actor": None,
            "handle": "ABUSE5250-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                "https://whois.arin.net/rest/poc/ABUSE5250-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2024, American Registry for Internet Numbers, Ltd.",
                    "links": None,
                    "title": "Copyright Notice"
                }
            ],
            "raw": None,
            "remarks": [
                {
                    "description": "Please note that the recommended way to file abuse complaints are located in the following links.\n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards,\nThe Google Team",
                    "links": None,
                    "title": "Registration Comments"
                }
            ],
            "roles": [
                "abuse"
            ],
            "status": [
                "validated"
            ]
        },
        "GOGL": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                    }
                ],
                "email": None,
                "kind": "org",
                "name": "Google LLC",
                "phone": None,
                "role": None,
                "title": None
            },
            "entities": [
                "ABUSE5250-ARIN",
                "ZG39-ARIN"
            ],
            "events": [
                {
                    "action": "last changed",
                    "actor": None,
                    "timestamp": "2019-10-31T15:45:45-04:00"
                },
                {
                    "action": "registration",
                    "actor": None,
                    "timestamp": "2000-03-30T00:00:00-05:00"
                }
            ],
            "events_actor": None,
            "handle": "GOGL",
            "links": [
                "https://rdap.arin.net/registry/entity/GOGL",
                "https://whois.arin.net/rest/org/GOGL"
            ],
            "notices": None,
            "raw": None,
            "remarks": [
                {
                    "description": "Please note that the recommended way to file abuse complaints are located in the following links. \n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards, \nThe Google Team",
                    "links": None,
                    "title": "Registration Comments"
                }
            ],
            "roles": [
                "registrant"
            ],
            "status": None
        },
        "ZG39-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": None,
                        "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": None,
                        "value": "arin-contact@google.com"
                    }
                ],
                "kind": "group",
                "name": "Google LLC",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-650-253-0000"
                    }
                ],
                "role": None,
                "title": None
            },
            "entities": None,
            "events": [
                {
                    "action": "last changed",
                    "actor": None,
                    "timestamp": "2023-11-10T07:01:59-05:00"
                },
                {
                    "action": "registration",
                    "actor": None,
                    "timestamp": "2000-11-30T13:54:08-05:00"
                }
            ],
            "events_actor": None,
            "handle": "ZG39-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                "https://whois.arin.net/rest/poc/ZG39-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2024, American Registry for Internet Numbers, Ltd.",
                    "links": None,
                    "title": "Copyright Notice"
                }
            ],
            "raw": None,
            "remarks": None,
            "roles": [
                "technical",
                "administrative"
            ],
            "status": [
                "validated"
            ]
        }
    },
    "query": "74.125.225.229",
    "raw": None
    }

.. OUTPUT_BASIC END

Use a proxy
-----------

::

    >>>> from urllib import request
    >>>> from ipwhois import IPWhois
    >>>> handler = request.ProxyHandler({
            'http': 'http://192.168.0.1:80/',
            'https': 'https://192.168.0.1:443/'
        })
    >>>> opener = request.build_opener(handler)
    >>>> obj = IPWhois('74.125.225.229', proxy_opener = opener)

Use a local file with RDAP data
-------------------------------

::

    >>>> from ipwhois.net import Net
    >>>> from ipwhois.rdap import RDAP
    >>>> data_dir = '/some/dir'
    >>>> with io.open(str(data_dir) + '/rdap.json', 'r') as data_file:
    >>>>    data = json.load(data_file)
    >>>>    for key, val in data.items():
    >>>>    net = Net(key)
    >>>>    obj = RDAP(net)
    >>>>    obj.lookup(response=val['response'],
                asn_data=val['asn_data'],
                depth=0
            )

Optimizing queries for your network
-----------------------------------

Multiple factors will slow your queries down. Several :ref:`rdap-input`
arguments assist in optimizing query performance:

bootstrap
^^^^^^^^^

**False**: ASN lookups are performed to determine the correct RIR to query
RDAP. This adds minor overhead for single queries.

**True**: Use ARIN bootstrap (redirection), significantly reducing overall time
for bulk queries, but at the sacrifice of not having asn* field data in the
results.

depth
^^^^^

This value equates to the number of entity levels deep to search for sub-entity
information. Found entities each result in a query to the RIR. The larger this
value, the longer a single IP query will take. More queries will cause RIR rate
limiting to trigger more often for bulk IP queries (only seen with LACNIC).

retry_count
^^^^^^^^^^^

This is the number of times to retry a query in the case of failure. If a
rate limit error (HTTPRateLimitError) is raised, the lookup will wait for
rate_limit_timeout seconds before retrying. A combination of adjusting
retry_count and rate_limit_timeout is needed to optimize bulk queries.

rate_limit_timeout
^^^^^^^^^^^^^^^^^^

When a HTTPRateLimitError is raised, and retry_count > 0, this is the amount of
seconds to sleep before retrying the query. Using the default value, or setting
this too high, will have a large impact on bulk IP queries. I recommend setting
this very low for bulk queries, or disable completely by setting retry_count=0.

Note that setting this result too low may cause a larger number of IP lookups
to fail.

root_ent_check
^^^^^^^^^^^^^^

When root level entities (depth=0) are missing vcard data, additional
entity specific HTTP lookups are performed. In the past, you would expect
depth=0 to mean a single lookup per IP. This was a bug and has been fixed as of
v1.2.0. Set this to False to revert back to the old method, although you will be
missing entity specific data.
