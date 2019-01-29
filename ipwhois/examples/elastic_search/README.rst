==============================
ipwhois: ElasticSearch example
==============================

Basic example Python CLI showing how to use ipwhois (RDAP) data with
ElasticSearch and Kibana. This example uses some other libararies to obtain
geo information for various country and address fields, formatted for mapping
in Kibana.

One purpose for using this example would be to locally track, cache, and
report on whois data.

I do not re-distribute the GeoLite2 database. For geolite2 data, download the
GeoLite2 database GeoLite2-City.mmdb and place in the data directory:
https://dev.maxmind.com/geoip/geoip2/geolite2/

Dependencies
============

Tested using::

    ElasticSearch 5.5.1
    Kibana 5.5.1

Python 2.7, 3.4+ (requirements.txt)::

    ipwhois
    elasticsearch
    geoip2
    geopy


Usage
=====

elastic_search.py [-h] [--create] [--delete] [--insert "IP"] [--update]
                         [--expires INTEGER] [--depth INTEGER]
                         [--kexport "FILEPATH"] [--kimport "FILEPATH"]
                         [--host "HOST"] [--port PORT]

Populate ElasticSearch with ipwhois data. Index: ipwhois Doc Types: base,
entity

arguments:
  -h, --help            show this help message and exit
  --create              Create the ipwhois ElasticSearch index.
  --delete              Delete the ipwhois ElasticSearch index.
  --insert IP           An IPv4 or IPv6 address as a string.
  --update              Update entries rather than inserting new.
  --expires INTEGER     Only insert/update/query an IP address if it is older
                        than EXPIRES (days). Default: 7.
  --depth INTEGER       How many levels deep to run queries when additional
                        referenced objects (IP entities) are found. Default:
                        1.
  --kexport FILEPATH    Export the ipwhois Kibana configuration (Index:
                        .kibana) to a jsonfile (FILEPATH).
  --kimport FILEPATH    Import the ipwhois default Kibana configuration
                        (Index: .kibana) from a json file (FILEPATH).
  --host HOST           The ElasticSearch host to connect to. Default:
                        "localhost".
  --port PORT           The ElasticSearch port to connect to. Default: 9200.

Usage Examples
==============

Create the ipwhois ElasticSearch index
--------------------------------------

::

    elastic_search.py --create

Delete the ipwhois ElasticSearch index
--------------------------------------

::

    elastic_search.py --delete

Query an IP address and enter the data
--------------------------------------

::

    elastic_search.py --insert "74.125.225.229"

Update data for an IP address if the last entry is older than 7 days
--------------------------------------------------------------------

::

    elastic_search.py --insert "74.125.225.229" --update --expires 7

Update data for an IP address regardless of age
-----------------------------------------------

::

    elastic_search.py --insert "74.125.225.229" --update --expires 0

Query an IP address but don't query for sub-entities
----------------------------------------------------

::

    elastic_search.py --insert "74.125.225.229" --depth 0

Export Kibana config (dashboard, search, visualization, ipwhois) to json file
-----------------------------------------------------------------------------

::

    elastic_search.py --kexport "/tmp/ipwhois-kibana.json"

Import Kibana config (dashboard, search, visualization, ipwhois) from json file
-------------------------------------------------------------------------------

::

    elastic_search.py --kimport "/tmp/ipwhois-kibana.json"

Create ipwhois index on custom ElasticSearch host and port
----------------------------------------------------------

::

    elastic_search.py --create --host "192.168.0.1" --port 1234

Import Kibana Config
====================

There is a default Kibana configuration for ipwhois in the data directory.

Replace EXAMPLES_DIR with the file path to the ipwhois examples directory:

::

    elastic_search.py --kimport "EXAMPLES_DIR/elastic_search/data/kibana.json"

