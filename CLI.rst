===
CLI
===

ipwhois_cli.py is a command line interface for the ipwhois library. When
using pip to install ipwhois, the CLI is installed to your Python
environment Scripts directory.

It currently has full ipwhois.py functionality. The others (net.py, rdap.py,
utils.py, whois.py) will be included in a future release.

Usage
=====

ipwhois_cli.py [-h] --addr IP [--whois] [--hr] [--show_name] [--colorize]
                      [--timeout TIMEOUT] [--proxy_http "PROXY_HTTP"]
                      [--proxy_https "PROXY_HTTPS"] [--disallow_permutations]
                      [--inc_raw] [--retry_count RETRY_COUNT]
                      [--asn_alts "ASN_ALTS"] [--extra_org_map "ASN_ALTS"]
                      [--depth COLOR_DEPTH]
                      [--excluded_entities "EXCLUDED_ENTITIES"] [--bootstrap]
                      [--rate_limit_timeout RATE_LIMIT_TIMEOUT]
                      [--get_referral] [--extra_blacklist "EXTRA_BLACKLIST"]
                      [--ignore_referral_errors] [--field_list "FIELD_LIST"]

ipwhois CLI interface

optional arguments:
  -h, --help            show this help message and exit
  --whois               Retrieve whois data via legacy Whois (port 43) instead
                        of RDAP (default).

Output options:
  --hr                  If set, returns results with human readable key
                        translations.
  --show_name           If this and --hr are set, the key name is shown in
                        parentheses after its short value
  --colorize            If set, colorizes the output using ANSI. Should work
                        in most platform consoles.

IPWhois settings:
  --timeout TIMEOUT     The default timeout for socket connections in seconds.
  --proxy_http PROXY_HTTP
                        The proxy HTTP address passed to request.ProxyHandler.
                        User auth can be passed like
                        "http://user:pass@192.168.0.1:80"
  --proxy_https PROXY_HTTPS
                        The proxy HTTPS address passed to
                        request.ProxyHandler. User auth can be passed like
                        "https://user:pass@192.168.0.1:443"
  --disallow_permutations
                        Disable additional methods if DNS lookups to Cymru
                        fail. This is the opposite of the ipwhois
                        allow_permutations, in order to enable
                        allow_permutations by default in the CLI.

Common settings (RDAP & Legacy Whois):
  --inc_raw             Include the raw whois results in the output.
  --retry_count RETRY_COUNT
                        The number of times to retry in case socket errors,
                        timeouts, connection resets, etc. are encountered.
  --asn_alts ASN_ALTS
                        A comma delimited list of additional lookup types to
                        attempt if the ASN dns lookup fails. Allow
                        permutations must be enabled. Defaults to all:
                        "whois,http"
  --extra_org_map ASN_ALTS
                        Dictionary mapping org handles to RIRs. This is for
                        limited cases where ARIN REST (ASN fallback HTTP
                        lookup) does not show an RIR as the org handle e.g.,
                        DNIC (which is now the built in ORG_MAP) e.g.,
                        {\"DNIC\": \"arin\"}. Valid RIR values are (note the
                        case-sensitive - this is meant to match the REST
                        result): 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'

RDAP settings:
  --depth COLOR_DEPTH   If not --whois, how many levels deep to run RDAP
                        queries when additional referenced objects are found.
  --excluded_entities EXCLUDED_ENTITIES
                        If not --whois, a comma delimited list of entity
                        handles to not perform lookups.
  --bootstrap           If not --whois, performs lookups via ARIN bootstrap
                        rather than lookups based on ASN data. ASN lookups are
                        not performed and no output for any of the asn* fields
                        is provided.
  --rate_limit_timeout RATE_LIMIT_TIMEOUT
                        If not --whois, the number of seconds to wait before
                        retrying when a rate limit notice is returned via
                        rdap+json.

Legacy Whois settings:
  --get_referral        If --whois, retrieve referral whois information, if
                        available.
  --extra_blacklist EXTRA_BLACKLIST
                        If --whois, A list of blacklisted whois servers in
                        addition to the global BLACKLIST.
  --ignore_referral_errors
                        If --whois, ignore and continue when an exception is
                        encountered on referral whois lookups.
  --field_list FIELD_LIST
                        If --whois, a list of fields to parse: ['name',
                        'handle', 'description', 'country', 'state', 'city',
                        'address', 'postal_code', 'emails', 'created',
                        'updated']

Input (Required):
  --addr IP             An IPv4 or IPv6 address as a string.

Usage Examples
==============

Basic usage
-----------

::

    ipwhois_cli.py --addr 74.125.225.229 --hr --show_name --colorize --depth 1

