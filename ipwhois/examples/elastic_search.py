# Basic example showing how to use ipwhois with elasticsearch/kibana.
#
# For geolite2 data, download the GeoLite2 database GeoLite2-City.mmdb and
# place in the data directory:
# https://dev.maxmind.com/geoip/geoip2/geolite2/
#
# To-do:
# - Add file/cli input option.
# - Move to functions Create, Delete, Index, and Search.
# - Add kibana config export.
# - Support more field parsing.

import elasticsearch
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from datetime import datetime
from geopy.geocoders import Nominatim
from geopy.exc import (GeocoderQueryError, GeocoderTimedOut)
import geoip2.database
import json
import io
from os import path

# Replace with input file/cli
INPUT = [
    '74.125.225.229',  # ARIN
    '2001:4860:4860::8888',
    '62.239.237.1',  # RIPE
    '2a00:2381:ffff::1',
    '210.107.73.73',  # APNIC
    '2001:240:10c:1::ca20:9d1d',
    '200.57.141.161',  # LACNIC
    '2801:10:c000::',
    '196.11.240.215',  # AFRINIC
    '2001:43f8:7b0::'
]

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
with io.open(str(CUR_DIR) + '/data/GEO_COORD.json', 'r') as data_file:
    GEO_COORD = json.load(data_file)

# Get the ISO country code mappings.
countries = get_countries()

# Used to convert addresses to geo locations.
geolocator = Nominatim()

# Default: localhost:9200
es = elasticsearch.Elasticsearch()

try:

    # Delete existing entries
    es.indices.delete(index='ipwhois')

except elasticsearch.exceptions.NotFoundError:

    pass

# Create the ipwhois index
es.indices.create(index='ipwhois', body={
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

# Iterate through the input, lookup each address, and store in elasticsearch
for ip in INPUT:

    try:
        # Only update if older than 7 days.
        tmp = es.search(
            index='ipwhois',
            doc_type='base',
            body={
                'query': {
                    "bool": {
                        "must": [{
                            'range': {
                                "updated": {
                                    "gt": "now-7d"
                                }
                            }
                        }, {
                            'term': {
                                'query': str(ip)
                            }
                        }]
                    }
                }
            }
        )

        if len(tmp['hits']['hits']) > 0:

            continue

    # A generic exception is raised, unfortunately.
    except Exception as e:
        print(e)
        pass

    # Perform the RDAP lookup for the input IP address retriving all entities
    # up to 1 level deep.
    result = IPWhois(ip)
    ret = result.lookup_rdap(depth=1)

    tmp_objects = ret['objects'].items()

    for ent_k, ent_v in tmp_objects:

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
                                            "gt": "now-7d"
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

        # Iterate the contact addresses.
        for addr_k, addr_v in enumerate(ent_v['contact']['address']):

            try:

                # Attempt to translate the contact address to geo coordinates
                # via geopy.
                location = geolocator.geocode(addr_v['value'].replace(
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
        ret['network']['country_name'] = countries[cc]

    except KeyError:

        pass

    try:

        # Get the MaxMind geo data for the query.
        # I do not want to redistribute the GeoLite2 database, download
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
        ret['query_country_name'] = countries[mm_response.country.iso_code]

    # Generic exception. Need to determine all raised and update handling.
    # geoip2.errors.AddressNotFoundError, TypeError, etc.
    except Exception as e:

        print(e)
        pass

    # Set the base updated timestamp.
    ret['updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Index the base in elasticsearch.
    es.index(index='ipwhois', doc_type='base', body=ret)

    # Refresh the index for searching duplicates.
    es.indices.refresh(index="ipwhois")
