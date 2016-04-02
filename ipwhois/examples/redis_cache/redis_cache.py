# Basic example showing how to cache ipwhois RDAP results with Redis.

import argparse
import redis
from os import path
from ipwhois import IPWhois
from datetime import datetime, timedelta
import pickle
from pprint import pprint

# Setup the arg parser.
parser = argparse.ArgumentParser(
    description='ipwhois RDAP result caching with Redis.'
)
parser.add_argument(
    '--addr',
    type=str,
    nargs=1,
    metavar='"IP"',
    help='An IPv4 or IPv6 address as a string.',
    required=True
)
parser.add_argument(
    '--set',
    action='store_true',
    help='Update the cache with RDAP results for addr if new or if the '
         'existing entry is older than expires.'
)
parser.add_argument(
    '--get',
    action='store_true',
    help='Get the cached RDAP results for addr. Can be combined with set.'
)
parser.add_argument(
    '--expires',
    type=int,
    default=7,
    metavar='EXPIRES',
    help=('Updates the cache if the --addr cache data is older than '
          'EXPIRES (in days). Default: 7. Setting to 0 forces '
          'an update.')
)
parser.add_argument(
    '--depth',
    type=int,
    default=1,
    metavar='DEPTH',
    help='How many levels deep to run queries when additional '
         'referenced objects (IP entities) are found. Default: 1.'
)
parser.add_argument(
    '--host',
    type=str,
    nargs=1,
    metavar='"HOST"',
    default='localhost',
    help='The Redis host to connect to. Default: localhost.'
)
parser.add_argument(
    '--port',
    type=int,
    metavar='PORT',
    default=6379,
    help='The Redis port to connect to. Default: 6379.'
)
parser.add_argument(
    '--db',
    type=int,
    metavar='DATABASE',
    default=0,
    help='The Redis database to connect to. Default: 0.'
)

# Get the args
args = parser.parse_args()

# Get the current working directory.
CUR_DIR = path.dirname(__file__)


class IPWhoisRedisCache:

    def __init__(self, connection_pool=None, addr=''):

        if not isinstance(connection_pool, redis.ConnectionPool):
            raise ValueError('connection_pool must be an instance of '
                             'redis.ConnectionPool')

        self.conn = redis.Redis(connection_pool=connection_pool)
        self.addr = addr

    def get_ipwhois(self, depth=1):

        # Perform the RDAP lookup for self.addr retrieving all
        # entities up to depth.
        obj = IPWhois(self.addr)
        ret = obj.lookup_rdap(depth=depth)

        # Set the updated timestamp for cache expiration.
        ret['updated'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        return ret

    def get(self):

        ret = self.conn.get(self.addr)
        return pickle.loads(ret) if ret else ret

    def set(self, expires=7, depth=1):

        existing_data = self.get()
        existing_updated = None

        if existing_data is not None:
            existing_updated = datetime.strptime(existing_data['updated'],
                                                 '%Y-%m-%dT%H:%M:%SZ')

        if (expires == 0 or existing_data is None or existing_updated < (
                    datetime.utcnow() - timedelta(days=expires))):

            result = self.get_ipwhois(depth)

            self.conn.set(self.addr, pickle.dumps(result))
            return True

        else:

            return False

# Redis connection init
pool = redis.ConnectionPool(host=args.host, port=args.port, db=args.db)
cache = IPWhoisRedisCache(pool, args.addr[0])

if args.set:
    set_result = cache.set(args.expires, args.depth)
    if set_result:
        print('Redis cache updated.')
    else:
        print('Redis cache has not expired.')

if args.get:
    pprint(cache.get())

if not args.set and not args.get:
    print('Nothing done. --set and/or --get required.')
