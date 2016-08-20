===
CLI
===

ipwhois_cli.py and ipwhois_utils_cli.py are command line interfaces for the
ipwhois library. When using pip to install ipwhois, the CLI scripts are
installed to your Python environment Scripts directory.

- ipwhois_cli.py has full ipwhois.py functionality.
- ipwhois_utils_cli.py has full utils.py functionality.
- The others (net.py, rdap.py, whois.py) will be included in a future release.

ipwhois_cli.py
==============

Usage
-----

ipwhois_cli.py [-h] [--whois] [--exclude_nir] [--json] [--hr]
                      [--show_name] [--colorize] [--timeout TIMEOUT]
                      [--proxy_http "PROXY_HTTP"]
                      [--proxy_https "PROXY_HTTPS"] [--disallow_permutations]
                      [--inc_raw] [--retry_count RETRY_COUNT]
                      [--asn_alts "ASN_ALTS"] [--extra_org_map "ASN_ALTS"]
                      [--depth COLOR_DEPTH]
                      [--excluded_entities "EXCLUDED_ENTITIES"] [--bootstrap]
                      [--rate_limit_timeout RATE_LIMIT_TIMEOUT]
                      [--get_referral] [--extra_blacklist "EXTRA_BLACKLIST"]
                      [--ignore_referral_errors] [--field_list "FIELD_LIST"]
                      [--nir_field_list "NIR_FIELD_LIST"] --addr "IP"

ipwhois CLI interface

optional arguments:
  -h, --help            show this help message and exit
  --whois               Retrieve whois data via legacy Whois (port 43) instead
                        of RDAP (default).
  --exclude_nir         Disable NIR whois lookups (JPNIC, KRNIC). This is the
                        opposite of the ipwhois inc_nir, in order to enable
                        inc_nir by default in the CLI.
  --json                Output results in JSON format.

Output options:
  --hr                  If set, returns results with human readable key
                        translations.
  --show_name           If this and --hr are set, the key name is shown in
                        parentheses afterits short value
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

NIR (National Internet Registry) settings:
  --nir_field_list NIR_FIELD_LIST
                        If not --exclude_nir, a list of fields to parse:
                        ['name', 'handle', 'country', 'address',
                        'postal_code', 'nameservers', 'created', 'updated',
                        'contact_admin', 'contact_tech']

Input (Required):
  --addr IP             An IPv4 or IPv6 address as a string.

Usage Examples
--------------

Basic usage
^^^^^^^^^^^

::

    ipwhois_cli.py --addr 74.125.225.229 --hr --show_name --colorize --depth 1

ipwhois_utils_cli.py
====================

Usage
-----

ipwhois_utils_cli.py [-h] [--ipv4_lstrip_zeros IPADDRESS]
                     [--calculate_cidr IPADDRESS IPADDRESS]
                     [--get_countries] [--get_country COUNTRYCODE]
                     [--ipv4_is_defined IPADDRESS]
                     [--ipv6_is_defined IPADDRESS]
                     [--unique_everseen ITERABLE]
                     [--unique_addresses FILEPATH] [--colorize]

ipwhois utilities CLI interface

optional arguments:
  -h, --help            show this help message and exit
  --ipv4_lstrip_zeros IPADDRESS
                        Strip leading zeros in each octet of an IPv4 address.
  --calculate_cidr IPADDRESSRANGE
                        Calculate a CIDR range(s) from a start and end IP
                        address. Separate start and end address arguments by
                        space.
  --get_countries       Output a dictionary containing ISO_3166-1 country
                        codes to names.
  --get_country COUNTRYCODE
                        Output the ISO_3166-1 name for a country code.
  --ipv4_is_defined IPADDRESS
                        Check if an IPv4 address is defined (in a reserved
                        address range).
  --ipv6_is_defined IPADDRESS
                        Check if an IPv6 address is defined (in a reserved
                        address range).
  --unique_everseen ITERABLE
                        List unique elements from input iterable, preserving
                        the order.
  --unique_addresses FILEPATH
                        Search an input file, extracting, counting, and
                        summarizing IPv4/IPv6 addresses/networks.

Output options:
  --colorize            If set, colorizes the output using ANSI. Should work
                        in most platform consoles.

Usage Examples
--------------

ipv4_lstrip_zeros
^^^^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --ipv4_lstrip_zeros 074.125.025.229

    74.125.25.229

calculate_cidr
^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --calculate_cidr 192.168.0.9 192.168.5.4

    Found 12 CIDR blocks for (192.168.0.9, 192.168.5.4):
    192.168.0.9/32
    192.168.0.10/31
    192.168.0.12/30
    192.168.0.16/28
    192.168.0.32/27
    192.168.0.64/26
    192.168.0.128/25
    192.168.1.0/24
    192.168.2.0/23
    192.168.4.0/24
    192.168.5.0/30
    192.168.5.4/32

get_countries
^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --get_countries

    Found 252 countries:
    AD: Andorra
    AE: United Arab Emirates
    AF: Afghanistan
    AG: Antigua and Barbuda
    AI: Anguilla
    AL: Albania
    AM: Armenia
    ...

get_country
^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --get_country US

    Match found for country code (US):
    United States

ipv4_is_defined
^^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --ipv4_is_defined 192.168.0.1

    192.168.0.1 is defined:
    Name: Private-Use Networks
    RFC: RFC 1918

ipv6_is_defined
^^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --ipv6_is_defined fc00::

    fc00:: is defined:
    Name: Unique Local Unicast
    RFC: RFC 4193

unique_everseen
^^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --unique_everseen [4,2,6,4,6,2]

    Unique everseen:
    [4, 2, 6]

unique_addresses
^^^^^^^^^^^^^^^^

::

    >>>> ipwhois_utils_cli.py --unique_addresses /tmp/some.file

    Found 477 unique addresses:
    74.125.225.229: Count: 5, Ports: {'22': 1}
    2001:4860::/32: Count: 4, Ports: {'443': 1, '80': 2}
    2001:4860:4860::8888: Count: 3, Ports: {}
    ...

