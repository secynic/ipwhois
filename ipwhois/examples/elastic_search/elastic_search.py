# Basic example showing how to use ipwhois with elasticsearch/kibana.
#
# For geolite2 data, download the GeoLite2 database GeoLite2-City.mmdb and
# place in the data directory:
# https://dev.maxmind.com/geoip/geoip2/geolite2/

import argparse
import elasticsearch
from elasticsearch.helpers import scan
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from datetime import datetime
import geoip2.database
import json
import io
import sys
from os import path

# geopy does not support lower than Python 2.7
if sys.version_info >= (2, 7):

    from geopy.geocoders import Nominatim
    from geopy.exc import (GeocoderQueryError, GeocoderTimedOut)

    # Used to convert addresses to geo locations.
    GEOLOCATOR = Nominatim()

# Setup the arg parser.
parser = argparse.ArgumentParser(
    description='Populate ElasticSearch with ipwhois data.\n'
                'Index: ipwhois\nDoc Types: base, entity'
)
parser.add_argument(
    '--create',
    action='store_true',
    help='Create the ipwhois ElasticSearch index.'
)
parser.add_argument(
    '--delete',
    action='store_true',
    help='Delete the ipwhois ElasticSearch index.'
)
parser.add_argument(
    '--insert',
    type=str,
    nargs=1,
    metavar='"IP"',
    help='An IPv4 or IPv6 address as a string.'
)
parser.add_argument(
    '--update',
    action='store_true',
    help='Update entries rather than inserting new.'
)
parser.add_argument(
    '--expires',
    type=int,
    default=7,
    metavar='INTEGER',
    help='Only insert/update/query an IP address if it is '
         'older than EXPIRES (days). Default: 7.'
)
parser.add_argument(
    '--depth',
    type=int,
    default=1,
    metavar='INTEGER',
    help='How many levels deep to run queries when additional '
         'referenced objects (IP entities) are found. Default: 1.'
)
parser.add_argument(
    '--kexport',
    type=str,
    nargs=1,
    metavar='"FILEPATH"',
    help='Export the ipwhois Kibana configuration (Index: .kibana) to a json'
         'file (FILEPATH).'
)
parser.add_argument(
    '--kimport',
    type=str,
    nargs=1,
    metavar='"FILEPATH"',
    help='Import the ipwhois default Kibana configuration (Index: .kibana) '
         'from a json file (FILEPATH).'
)
parser.add_argument(
    '--host',
    type=str,
    nargs=1,
    metavar='"HOST"',
    default='localhost',
    help='The ElasticSearch host to connect to. Default: "localhost".'
)
parser.add_argument(
    '--port',
    type=int,
    metavar='PORT',
    default=9200,
    help='The ElasticSearch port to connect to. Default: 9200.'
)

# Get the args
args = parser.parse_args()

# Common es mapping.
DEFAULT_MAPPING = {
    "date_detection": 1,
    "_id": {
        "index": "not_analyzed",
        "store": True
    },
    "properties": {
        "@version": {
            "type": "string",
            "index": "not_analyzed"
        },
        "updated": {
            "type": "date",
            "format": "yyyy-MM-dd'T'HH:mm:ssZ",
            "ignore_malformed": "false"
        }
    },
    "_all": {"enabled": "true"},
    "dynamic_templates": [
        {
            "string_fields": {
                "match": "*",
                "match_mapping_type": "string",
                "mapping": {
                    "type": "multi_field",
                    "fields": {
                        "{name}": {
                            "type": "string",
                            "index": "not_analyzed"
                        },
                        "{name}.raw": {
                            "type": "string",
                            "index": "not_analyzed",
                            "ignore_above": 256
                        }
                    }
                }
            }
        }
    ]
}

# Get the current working directory.
CUR_DIR = path.dirname(__file__)

# Load the geo json for mapping ISO country codes to lat/lon geo coords.
with io.open(str(CUR_DIR) + '/data/geo_coord.json', 'r') as data_file:
    GEO_COORD = json.load(data_file)

# Get the ISO country code mappings.
COUNTRIES = get_countries()

# Default: localhost:9200
es = elasticsearch.Elasticsearch(host=args.host, port=args.port)


def delete_index():

    try:

        # Delete existing entries
        es.indices.delete(index='ipwhois')

    except elasticsearch.exceptions.NotFoundError:

        pass


def create_index():

    # Create the ipwhois index
    es.indices.create(index='ipwhois', ignore=400, body={
        "settings": {
            "index.refresh_interval": "5s",
            "analysis": {
                "analyzer": {
                    "base": {
                        "type": "standard",
                        "stopwords": "_none_"
                    },
                    "entity": {
                        "type": "standard",
                        "stopwords": "_none_"
                    }
                }
            }
        }
    })

    # base doc type mapping
    mapping = DEFAULT_MAPPING.copy()
    mapping.update({
        "properties": {
            "asn_date": {
                "type": "date",
                "format": "date",
                "ignore_malformed": "true"
            },
            "network.events.timestamp": {
                "type": "date",
                "format": "yyyy-MM-dd'T'HH:mm:ssZ",
                "ignore_malformed": "false"
            },
            "query": {
                "type": "ip",
                "store": True,
                "ignore_malformed": True
            },
            "query_geo": {
                "type": "geo_point",
                "lat_lon": True,
                "geohash": True
            },
            "network": {
                "properties": {
                    "country_geo": {
                        "type": "geo_point",
                        "lat_lon": True,
                        "geohash": True
                    },
                    "start_address": {
                        "type": "ip",
                        "store": True,
                        "ignore_malformed": True
                    },
                    "end_address": {
                        "type": "ip",
                        "store": True,
                        "ignore_malformed": True
                    }
                }
            }
        }
    })
    es.indices.put_mapping(
        index='ipwhois',
        doc_type='base',
        body=mapping,
        allow_no_indices=True
    )

    # entity doc type mapping
    mapping = DEFAULT_MAPPING.copy()
    mapping.update({
        "properties": {
            "contact": {
                "properties": {
                    "address": {
                        "properties": {
                            "geo": {
                                "type": "geo_point",
                                "lat_lon": True,
                                "geohash": True
                            },
                            "value": {
                                "type": "string",
                            }
                        }
                    }
                }
            }
        }
    })
    es.indices.put_mapping(
        index='ipwhois',
        doc_type='entity',
        body=mapping,
        allow_no_indices=True
    )


def insert(input_ip='', update=True, expires=7, depth=1):

    if update:

        try:
            # Only update if older than x days.
            tmp = es.search(
                index='ipwhois',
                doc_type='base',
                body={
                    'query': {
                        "bool": {
                            "must": [{
                                'range': {
                                    "updated": {
                                        "gt": "now-{0}d".format(expires)
                                    }
                                }
                            }, {
                                'term': {
                                    'query': str(input_ip)
                                }
                            }]
                        }
                    }
                }
            )

            if len(tmp['hits']['hits']) > 0:

                return

        # A generic exception is raised, unfortunately.
        except Exception as e:
            print(e)
            pass

    # Perform the RDAP lookup for the input IP address retriving all entities
    # up to depth.
    result = IPWhois(input_ip)
    ret = result.lookup_rdap(depth=depth)

    tmp_objects = ret['objects'].items()

    for ent_k, ent_v in tmp_objects:

        if update:

            try:

                # Only update if older than 7 days.
                es_tmp = es.search(
                    index='ipwhois',
                    doc_type='entity',
                    body={
                        'query': {
                            "bool": {
                                "must": [
                                    {
                                        'range': {
                                            "updated": {
                                                "gt": "now-{0}d".format(expires)
                                            }
                                        }
                                    },
                                    {
                                        'term': {
                                            'handle': str(ent_k)
                                        }
                                    }
                                ]
                            }
                        }
                    }
                )

                if len(es_tmp['hits']['hits']) > 0:

                    continue

            # A generic exception is raised, unfortunately.
            except Exception as e:
                print(e)
                pass

        ent = ent_v

        if sys.version_info >= (2, 7):

            # Iterate the contact addresses.
            for addr_k, addr_v in enumerate(ent_v['contact']['address']):

                try:

                    # Attempt to translate the contact address to geo
                    # coordinates via geopy.
                    location = GEOLOCATOR.geocode(addr_v['value'].replace(
                        '\n', ' '))

                    # Add the geo coordinates for the contact address.
                    ent['contact']['address'][addr_k]['geo'] = {
                        'lat': location.latitude,
                        'lon': location.longitude
                    }

                except (AttributeError, KeyError, GeocoderQueryError,
                        GeocoderTimedOut):

                    pass

        # Set the entity updated timestamp.
        ent['updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        if update:

            try:

                ent_search = es.search(
                    index='ipwhois',
                    doc_type='entity',
                    body={
                        'query': {
                            "match": {
                                "handle": ent['handle']
                            }
                        }
                    }
                )

                for hit in ent_search['hits']['hits']:

                    es.delete(index='ipwhois', doc_type='entity',
                              id=hit['_id'])

            except KeyError:

                pass

        # Index the entity in elasticsearch.
        es.index(index='ipwhois', doc_type='entity', body=ent)

        # Refresh the index for searching duplicates.
        es.indices.refresh(index="ipwhois")

    # Don't need the objects key since that data has been entered as the
    # entities doc_type.
    del ret['objects']

    try:

        # Get the network ISO country code
        cc = ret['network']['country']

        # Add the geo coordinates for the country, defined in GEO_COORD.json.
        ret['network']['country_geo'] = {
            'lat': GEO_COORD[cc]['latitude'],
            'lon': GEO_COORD[cc]['longitude']
        }

        # Set the network country name.
        ret['network']['country_name'] = COUNTRIES[cc]

    except KeyError:

        pass

    try:

        # Get the MaxMind geo data for the query.
        # I do not redistribute the GeoLite2 database, download
        # GeoLite2-City.mmdb from:
        # https://dev.maxmind.com/geoip/geoip2/geolite2/
        mm_reader = geoip2.database.Reader(str(CUR_DIR) +
                                           '/data/GeoLite2-City.mmdb')

        # Query the database.
        mm_response = mm_reader.city(ret['query'])

        # Set the JSON geo data.
        ret['query_geo'] = {
            'lat': mm_response.location.latitude,
            'lon': mm_response.location.longitude
        }
        ret['query_country_name'] = COUNTRIES[mm_response.country.iso_code]

    # Generic exception. Need to determine all raised and update handling.
    # geoip2.errors.AddressNotFoundError, TypeError, etc.
    except Exception as e:

        print(e)
        pass

    # Set the base updated timestamp.
    ret['updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    if update:

        try:

            ip_search = es.search(
                index='ipwhois',
                doc_type='base',
                body={
                    'query': {
                        "match": {
                            "query": ret['query']
                        }
                    }
                }
            )

            for hit in ip_search['hits']['hits']:

                es.delete(index='ipwhois', doc_type='base', id=hit['_id'])

        except KeyError:

            pass

    # Index the base in elasticsearch.
    es.index(index='ipwhois', doc_type='base', body=ret)

    # Refresh the index for searching duplicates.
    es.indices.refresh(index="ipwhois")

if args.delete:

    delete_index()

if args.create:

    create_index()

if args.insert:

    insert(args.insert[0], args.update, args.expires, args.depth)

if args.kexport:

    # Export dashboards, searches, and visualizations.
    kibana_export = list(scan(
        client=es, index='.kibana',
        doc_type="dashboard,search,visualization")
    )

    # Export the ipwhois index pattern.
    kibana_idx_export = list(scan(
        client=es,
        index='.kibana',
        doc_type="index-pattern",
        query={"query": {"match": {"_id": "ipwhois"}}}
    ))

    # Dump exports to json file.
    with io.open(args.kexport[0], 'w') as data_file:

        json.dump(kibana_export + kibana_idx_export, data_file)

if args.kimport:

    # Open kibana json file.
    with io.open(args.kimport[0], 'r') as data_file:

        kibana_import = json.load(data_file)

    # Update or Insert kibana config for ipwhois.
    for item in kibana_import:

        es.update(index=".kibana", doc_type=item['_type'], id=item["_id"],
                  body={'doc': item['_source'], 'doc_as_upsert': True})
