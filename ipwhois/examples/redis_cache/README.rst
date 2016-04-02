==================================
ipwhois: Caching via Redis example
==================================

Example Python CLI showing how to cache ipwhois (RDAP) data with
Redis. The intent here is to reduce duplicate queries, configurable by
cache timeouts. In this example, get (--get) just pretty prints (pprint) to
stdout. You could easily convert this example for non-cli use by using the
class embedded in this file (IPWhoisRedisCache).

Dependencies
============

Python 2.6 (requirements26.txt)::

    ipwhois
    redis
    argparse

Python 2.7, 3.3+ (requirements.txt)::

    ipwhois
    redis

Usage
=====

redis_cache.py [-h] [--addr "IP"] [--set] [--get] [--expires EXPIRES]
                         [--depth DEPTH] [--host "HOST"] [--port PORT]
                         [--db DATABASE]

Cache ipwhois data with Redis.

arguments:
  -h, --help            show this help message and exit
  --addr IP             An IPv4 or IPv6 address as a string.
  --set                 Update the cache with RDAP results for addr if new or
                        if the existing entry is older than expires. This will
                        run first if combined with get.
  --get                 Get the cached RDAP results for addr. Can be combined
                        with set, and will run after set.
  --expires EXPIRES     Updates the cache if the --addr cache data is older
                        than EXPIRES (in days). Default: 7. Setting to 0
                        forces an update.
  --depth DEPTH         How many levels deep to run queries when additional
                        referenced objects (IP entities) are found. Default:
                        1.
  --host HOST           The Redis host. Default: localhost.
  --port PORT           The Redis port. Default: 6379.
  --db DATABASE         The Redis database. Default: 0.

Usage Examples
==============

Update cache for an IP address if empty or expired, and get
-----------------------------------------------------------

::

    redis_cache.py --addr "74.125.225.229" --set --get

Get cache results for an IP address
-----------------------------------

::

    redis_cache.py --addr "74.125.225.229" --get

Update cache for an IP address if empty or older than one day
-------------------------------------------------------------

::

    redis_cache.py --addr "74.125.225.229" --set --expires 1

Force update cache for an IP address
------------------------------------

::

    redis_cache.py --addr "74.125.225.229" --set --expires 0

Set but don't query for sub-entities
------------------------------------

::

    redis_cache.py --addr "74.125.225.229" --set --depth 0

Override the default Redis host, port, and db
---------------------------------------------

::

    redis_cache.py --addr "74.125.225.229" --set --host "192.168.0.1"
        --port 1234 --db 1

