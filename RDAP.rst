===================
RDAP (HTTP) Lookups
===================

IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides a
far better data structure than legacy whois and REST lookups (previous
implementation). RDAP queries allow for parsing of contact information and
details for users, organizations, and groups. RDAP also provides more detailed
network information.

Input
=====

Arguments supported by IPWhois.lookup_rdap().

+--------------------+--------+-----------------------------------------------+
| **Key**            |**Type**| **Description**                               |
+--------------------+--------+-----------------------------------------------+
| inc_raw            | Bool   | Boolean for whether to include the raw whois  |
|                    |        | results in the returned dictionary.           |
+--------------------+--------+-----------------------------------------------+
| retry_count        | Int    | The number of times to retry in case socket   |
|                    |        | errors, timeouts, connection resets, etc. are |
|                    |        | encountered.                                  |
+--------------------+--------+-----------------------------------------------+
| depth              | Int    | How many levels deep to run queries when      |
|                    |        | additional referenced objects are found.      |
+--------------------+--------+-----------------------------------------------+
| excluded_entities  | List   | A list of entity handles to not perform       |
|                    |        | lookups.                                      |
+--------------------+--------+-----------------------------------------------+
| bootstrap          | Bool   | If True, performs lookups via ARIN bootstrap  |
|                    |        | rather than lookups based on ASN data. ASN    |
|                    |        | lookups are not performed and no output for   |
|                    |        | any of the asn* fields is provided.           |
+--------------------+--------+-----------------------------------------------+
| rate_limit_timeout | Int    | The number of seconds to wait before retrying |
|                    |        | when a rate limit notice isreturned via       |
|                    |        | rdap+json.                                    |
+--------------------+--------+-----------------------------------------------+
| asn_alts           | List   | Array of additional lookup types to attempt if|
|                    |        | the ASN dns lookup fails. Allow permutations  |
|                    |        | must be enabled. Defaults to all              |
|                    |        | ['whois', 'http'].                            |
+--------------------+--------+-----------------------------------------------+
| extra_org_map      | Dict   | Dictionary mapping org handles to RIRs.       |
|                    |        | This is for limited cases where ARIN REST     |
|                    |        | (ASN fallback HTTP lookup) does not show an   |
|                    |        | RIR as the org handle e.g., DNIC (which       |
|                    |        | is now built in ORG_MAP)                      |
|                    |        | e.g., {'DNIC': 'arin'}. Valid RIR             |
|                    |        | values are (note the case-sensitive - this is |
|                    |        | meant to match the REST result):              |
|                    |        | 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'  |
+--------------------+--------+-----------------------------------------------+

Output
======

Results Dictionary
------------------

The output dictionary from IPWhois.lookup_rdap(). Contains many nested lists
and dictionaries, detailed below this section.

+------------------+--------+-------------------------------------------------+
| **Key**          |**Type**| **Description**                                 |
+------------------+--------+-------------------------------------------------+
| query            | String | The IP address input                            |
+------------------+--------+-------------------------------------------------+
| asn              | String | Globally unique identifier used for routing     |
|                  |        | information exchange with Autonomous Systems.   |
+------------------+--------+-------------------------------------------------+
| asn_cidr         | String | Network routing block assigned to an ASN.       |
+------------------+--------+-------------------------------------------------+
| asn_country_code | String | ASN assigned country code in ISO 3166-1 format. |
+------------------+--------+-------------------------------------------------+
| asn_date         | String | ASN allocation date in ISO 8601 format.         |
+------------------+--------+-------------------------------------------------+
| asn_registry     | String | ASN assigned regional internet registry.        |
+------------------+--------+-------------------------------------------------+
| network          | Dict   | The assigned network for an IP address. May be  |
|                  |        | a parent or child network. See                  |
|                  |        | `Network Dictionary <#network-dictionary>`_.    |
+------------------+--------+-------------------------------------------------+
| entities         | List   | List of object names referenced by an RIR       |
|                  |        | network. Map these to the objects dict keys.    |
+------------------+--------+-------------------------------------------------+
| objects          | Dict   | The objects (entities) referenced by an RIR     |
|                  |        | network or by other entities (depending on      |
|                  |        | depth parameter). Keys are the object names     |
|                  |        | with values as                                  |
|                  |        | `Objects Dictionary <#objects-dictionary>`_.    |
+------------------+--------+-------------------------------------------------+
| raw              | Dict   | The raw results dictionary (JSON) if            |
|                  |        | inc_raw is True.                                |
+------------------+--------+-------------------------------------------------+

Network Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the network key in the objects list within
`Results Dictionary <#results-dictionary>`_.

+---------------+--------+----------------------------------------------------+
| **Key**       |**Type**| **Description**                                    |
+---------------+--------+----------------------------------------------------+
| cidr          | String | Network routing block an IP address belongs to.    |
+---------------+--------+----------------------------------------------------+
| country       | String | Country code registered with the RIR in            |
|               |        | ISO 3166-1 format.                                 |
+---------------+--------+----------------------------------------------------+
| end_address   | String | The last IP address in a network block.            |
+---------------+--------+----------------------------------------------------+
| events        | List   | List of event dictionaries. See                    |
|               |        | `Events Dictionary <#events-dictionary>`_.         |
+---------------+--------+----------------------------------------------------+
| handle        | String | Unique identifier for a registered object.         |
+---------------+--------+----------------------------------------------------+
| ip_version    | String | IP protocol version (v4 or v6) of an IP address.   |
+---------------+--------+----------------------------------------------------+
| links         | List   | HTTP/HTTPS links provided for an RIR object.       |
+---------------+--------+----------------------------------------------------+
| name          | String | The identifier assigned to the network             |
|               |        | registration for an IP address.                    |
+---------------+--------+----------------------------------------------------+
| notices       | List   | List of notice dictionaries. See                   |
|               |        | `Notices Dictionary <#notices-dictionary>`_.       |
+---------------+--------+----------------------------------------------------+
| parent_handle | String | Unique identifier for the parent network of a      |
|               |        | registered network.                                |
+---------------+--------+----------------------------------------------------+
| remarks       | List   | List of remark (notice) dictionaries. See          |
|               |        | `Notices Dictionary <#notices-dictionary>`_.       |
+---------------+--------+----------------------------------------------------+
| start_address | String | The first IP address in a network block.           |
+---------------+--------+----------------------------------------------------+
| status        | List   | List indicating the state of a registered object.  |
+---------------+--------+----------------------------------------------------+
| type          | String | The RIR classification of a registered network.    |
+---------------+--------+----------------------------------------------------+

Objects Dictionary
^^^^^^^^^^^^^^^^^^

The dictionary mapped to the object (entity) key in the objects list within
`Results Dictionary <#results-dictionary>`_.

+--------------+--------+-----------------------------------------------------+
| **Key**      |**Type**| **Description**                                     |
+--------------+--------+-----------------------------------------------------+
| contact      | Dict   | Contact information registered with an RIR object.  |
|              |        | See                                                 |
|              |        | `Contact Dictionary <#objects-contact-dictionary>`_.|
+--------------+--------+-----------------------------------------------------+
| entities     | List   | List of object names referenced by an RIR object.   |
|              |        | Map these to other objects dictionary keys.         |
+--------------+--------+-----------------------------------------------------+
| events       | List   | List of event dictionaries. See                     |
|              |        | `Events Dictionary <#events-dictionary>`_.          |
+--------------+--------+-----------------------------------------------------+
| events_actor | List   | List of event (no actor) dictionaries. See          |
|              |        | `Events Dictionary <#events-dictionary>`_.          |
+--------------+--------+-----------------------------------------------------+
| handle       | String | Unique identifier for a registered object.          |
+--------------+--------+-----------------------------------------------------+
| links        | List   | List of HTTP/HTTPS links provided for an RIR object.|
+--------------+--------+-----------------------------------------------------+
| notices      | List   | List of notice dictionaries. See                    |
|              |        | `Notices Dictionary <#notices-dictionary>`_.        |
+--------------+--------+-----------------------------------------------------+
| remarks      | List   | List of remark (notice) dictionaries. See           |
|              |        | `Notices Dictionary <#notices-dictionary>`_.        |
+--------------+--------+-----------------------------------------------------+
| roles        | List   | List of roles assigned to a registered object.      |
+--------------+--------+-----------------------------------------------------+
| status       | List   | List indicating the state of a registered object.   |
+--------------+--------+-----------------------------------------------------+

Objects Contact Dictionary
^^^^^^^^^^^^^^^^^^^^^^^^^^

The contact information dictionary registered to an RIR object. This is the
contact key contained in `Objects Dictionary <#objects-dictionary>`_.

+---------+--------+----------------------------------------------------------+
| **Key** |**Type**| **Description**                                          |
+---------+--------+----------------------------------------------------------+
| address | Dict   | The contact postal address. Contains key type and value. |
+---------+--------+----------------------------------------------------------+
| email   | Dict   | The contact email address. Contains key type and value.  |
+---------+--------+----------------------------------------------------------+
| kind    | String | The contact information kind (individual, group, org).   |
+---------+--------+----------------------------------------------------------+
| name    | String | The contact name.                                        |
+---------+--------+----------------------------------------------------------+
| phone   | Dict   | The contact phone number. Contains key type and value.   |
+---------+--------+----------------------------------------------------------+
| role    | String | The contact's role.                                      |
+---------+--------+----------------------------------------------------------+
| title   | String | The contact's position or job title.                     |
+---------+--------+----------------------------------------------------------+

Events Dictionary
^^^^^^^^^^^^^^^^^

Common to lists in `Network <#network-dictionary>`_ and
`Objects <#objects-dictionary>`_.
Contained in events and events_actor (no actor).

+-----------+--------+-------------------------------------------------+
| **Key**   |**Type**| **Description**                                 |
+-----------+--------+-------------------------------------------------+
| action    | String | The reason for an event.                        |
+-----------+--------+-------------------------------------------------+
| timestamp | String | The date an event occured in ISO 8601 format.   |
+-----------+--------+-------------------------------------------------+
| actor     | String | The identifier for an event initiator (if any). |
+-----------+--------+-------------------------------------------------+

Notices Dictionary
^^^^^^^^^^^^^^^^^^

Common to lists in `Network <#network-dictionary>`_ and
`Objects <#objects-dictionary>`_. Contained in notices and remarks.

+-------------+--------+-------------------------------------------------+
| **Key**     |**Type**| **Description**                                 |
+-------------+--------+-------------------------------------------------+
| title       | String | The title/header for a notice.                  |
+-------------+--------+-------------------------------------------------+
| description | String | The description/body of a notice.               |
+-------------+--------+-------------------------------------------------+
| links       | List   | List of HTTP/HTTPS links provided for a notice. |
+-------------+--------+-------------------------------------------------+

Upgrading from 0.10 to 0.11
===========================

Considerable changes were made between v0.10.3 and v0.11.0. The new RDAP return
format was introduced and split off from the legacy whois return format. Using
RDAP lookup is the recommended method to maximize indexable values.

RDAP return data is different in nearly every way from the legacy whois data.

For information on raw RDAP responses, please see the RFC:
https://tools.ietf.org/html/rfc7483

Usage Examples
==============

Basic usage
-----------

::

    >>>> from ipwhois import IPWhois
    >>>> from pprint import pprint

    >>>> obj = IPWhois('74.125.225.229')
    >>>> results = obj.lookup_rdap(depth=1)
    >>>> pprint(results)

    {
    'asn': '15169',
    'asn_cidr': '74.125.225.0/24',
    'asn_country_code': 'US',
    'asn_date': '2007-03-13',
    'asn_registry': 'arin',
    'entities': [u'GOGL'],
    'network': {
        'cidr': '74.125.0.0/16',
        'country': None,
        'end_address': '74.125.255.255',
        'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2012-02-24T09:44:34-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2007-03-13T12:09:54-04:00'
            }
        ],
        'handle': u'NET-74-125-0-0-1',
        'ip_version': u'v4',
        'links': [
            u'https://rdap.arin.net/registry/ip/074.125.000.000',
            u'https://whois.arin.net/rest/net/NET-74-125-0-0-1'
        ],
        'name': u'GOOGLE',
        'notices': [{
            'description': u'By using the ARIN RDAP/Whois service, you are
                agreeing to the RDAP/Whois Terms of Use',
            'links': [u'https://www.arin.net/whois_tou.html'],
            'title': u'Terms of Service'
        }],
        'parent_handle': u'NET-74-0-0-0-0',
        'raw': None,
        'remarks': None,
        'start_address': '74.125.0.0',
        'status': None,
        'type': None
    },
    'objects': {
        u'ABUSE5250-ARIN': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': [{
                    'type': None,
                    'value': u'network-abuse@google.com'
                }],
                'kind': u'group',
                'name': u'Abuse',
                'phone': [{
                    'type': [u'work', u'voice'],
                    'value': u'+1-650-253-0000'
                }],
                'role': None,
                'title': None
            },
            'entities': None,
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-11-06T15:36:35-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2015-11-06T15:36:35-05:00'
            }],
            'events_actor': None,
            'handle': u'ABUSE5250-ARIN',
            'links': [
                u'https://rdap.arin.net/registry/entity/ABUSE5250-ARIN',
                u'https://whois.arin.net/rest/poc/ABUSE5250-ARIN'
            ],
            'notices': [{
                'description': u'By using the ARIN RDAP/Whois service, you are
                    agreeing to the RDAP/Whois Terms of Use',
                'links': [u'https://www.arin.net/whois_tou.html'],
                'title': u'Terms of Service'}],
            'raw': None,
            'remarks': [{
                'description': u'Please note that the recommended way to file
                    abuse complaints are located in the following links.\r\n\r
                    \nToreport abuse and illegal activity:
                    https://www.google.com/intl/en_US/goodtoknow/online-safety
                    /reporting-abuse/ \r\n\r\nFor legal requests:
                    http://support.google.com/legal \r\n\r\n
                    Regards,\r\nThe Google Team',
                'links': None,
                'title': u'Registration Comments'
            }],
            'roles': None,
            'status': [u'validated']
        },
        u'GOGL': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': None,
                'kind': u'org',
                'name': u'Google Inc.',
                'phone': None,
                'role': None,
                'title': None
            },
            'entities': [u'ABUSE5250-ARIN', u'ZG39-ARIN'],
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-11-06T15:45:54-05:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2000-03-30T00:00:00-05:00'
            }],
            'events_actor': None,
            'handle': u'GOGL',
            'links': [
                u'https://rdap.arin.net/registry/entity/GOGL',
                u'https://whois.arin.net/rest/org/GOGL'
            ],
            'notices': None,
            'raw': None,
            'remarks': None,
            'roles': [u'registrant'],
            'status': None
        },
        u'ZG39-ARIN': {
            'contact': {
                'address': [{
                    'type': None,
                    'value': u'1600 Amphitheatre Parkway\nMountain View\nCA\n
                        94043\nUNITED STATES'
                }],
                'email': [{
                    'type': None,
                    'value': u'arin-contact@google.com'
                }],
                'kind': u'group',
                'name': u'Google Inc',
                'phone': [{
                    'type': [u'work', u'voice'],
                    'value': u'+1-650-253-0000'
                }],
                'role': None,
                'title': None
            },
            'entities': None,
            'events': [{
                'action': u'last changed',
                'actor': None,
                'timestamp': u'2015-09-01T14:03:11-04:00'
            },
            {
                'action': u'registration',
                'actor': None,
                'timestamp': u'2000-11-30T13:54:08-05:00'
            }],
            'events_actor': None,
            'handle': u'ZG39-ARIN',
            'links': [
                u'https://rdap.arin.net/registry/entity/ZG39-ARIN',
                u'https://whois.arin.net/rest/poc/ZG39-ARIN'
            ],
            'notices': [{
                'description': u'By using the ARIN RDAP/Whois service, you are
                    agreeing to the RDAP/Whois Terms of Use',
                'links': [u'https://www.arin.net/whois_tou.html'],
                'title': u'Terms of Service'
            }],
            'raw': None,
            'remarks': None,
            'roles': None,
            'status': [u'validated']
        }
    },
    'query': '74.125.225.229',
    'raw': None
    }

Use a proxy
-----------

::

	>>>> from urllib import request
	>>>> from ipwhois import IPWhois
	>>>> handler = request.ProxyHandler({'http': 'http://192.168.0.1:80/'})
	>>>> opener = request.build_opener(handler)
	>>>> obj = IPWhois('74.125.225.229', proxy_opener = opener)

Optimizing queries for your network
-----------------------------------

Multiple factors will slow your queries down. Several `Input <#input>`_
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

When performing bulk IP lookups, the goal should be to acquire as much data, as
fast as possible. If you have multiple IP lookups, in a row, that belong to the
same RIR (generally LACNIC), the chance to hit rate limiting errors increases
(also depending on bootstrap, depth, network speeds).

One option to increase bulk query performance is to disable retries and store
the errored IPs in a list for the next round of lookups (loop your bulk queries
until all IPs resolve). Disable retries by setting retry_count=0

rate_limit_timeout
^^^^^^^^^^^^^^^^^^

When a HTTPRateLimitError is raised, and retry_count > 0, this is the amount of
seconds to sleep before retrying the query. Using the default value, or setting
this too high, will have a large impact on bulk IP queries. I recommend setting
this very low for bulk queries, or disable completely by setting retry_count=0.

Note that setting this result too low may cause a larger number of IP lookups
to fail.
