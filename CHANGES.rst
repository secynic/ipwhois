Changelog
=========

1.2.0 (TBD)
------------------

- Removed deprecated functions: asn.IPASN._parse_fields_http,
  asn.IPASN._parse_fields_dns, asn.IPASN._parse_fields_whois,
  asn.ASNOrigin._parse_fields, asn.ASNOrigin._get_nets_radb,
  net.Net.lookup_asn, whois.Whois._parse_fields, whois.Whois._get_nets_arin
  whois.Whois._get_nets_lacnic, whois.Whois._get_nets_other,
  nir.NIRWhois._parse_fields, nir.NIRWhois._get_nets_jpnic
  nir.NIRWhois._get_nets_krnic, nir.NIRWhois._get_contact (#230)
- Removed deprecated asn_alts parameter (#230)
- Removed deprecated allow_permutations parameter (#230)
- Fixed ASNOrigin lookups (#216)
- Fixed bug in ASNOrigin lookups when multiple asn_methods provided (#216)
- Fixed bug in KRNIC queries due to a change in their service (#243)
- Fixed bug in experimental.bulk_lookup_rdap where only the last 
  result was returned (#262 - ameidatou)

1.1.0 (2019-02-01)
------------------

- Exceptions now inherit a new BaseIpwhoisException rather than Exception
  (#205 - Darkheir)
- Fixed list output for generate_examples.py (#196)
- Fixed bug in ASN HTTP lookup where the ARIN results were reversed, and
  parsing would fail on the first item (#220)
- Removed support for Python 2.6/3.3, added support for 3.7 (#221)
- Fixed deprecation warnings in core code (#203 - cstranex)
- Fixed bug in host argument for elastic_search.py example (#202)
- Set user agent in elastic_search.py example to avoid default user agent
- Updated elastic_search.py example for ES 6.6.0
- Readme update for RDAP vs Legacy Whois output (#204)
- Removed the disallow_permutations argument from ipwhois_cli.py (#226)

1.0.0 (2017-07-30)
------------------

- Deprecated asn_alts, allow_permutations in favor of new asn_methods (#158)
- Added new exception ASNOriginLookupError (#158)
- KRNIC lookups changed to HTTPS (#166)
- Added experimental functions - get_bulk_asn_whois, bulk_lookup_rdap (#134)
- Fixed bug in NIR lookups that caused addresses with multi-line contacts to
  error (#172 - kwheeles)
- Added IANA Reserved CIDR 198.97.38.0/24 to ipv4_is_defined (#174)
- Fixed bug in RDAP notices/remarks parsing that would omit partial entries
  missing one or more of title, description, links (#176)
- Added new return key asn_description via verbose ASN DNS lookup support and
  modified ASN whois lookups. New argument get_asn_description (#176)
- Fixed some test function naming errors
- Added new generators to utils.py: ipv4_generate_random and
  ipv6_generate_random (#183)
- Moved upgrade notes to new UPGRADING.rst
- Deprecated unnecessary protected class functions, changed to public in
  asn.py, nir.py, and whois.py (#184)
- net.Net.get_host(), utils.ipv4_is_defined(), and utils.ipv6_is_defined now
  return namedtuple instead of tuple.
- Changed docstrings to Google standard for better napoleon parsing (#185)
- Removed deprecated IPWhois.lookup() - This was moved to
  IPWhois.lookup_whois()
- Fixed 'nets'->'range' bug for legacy whois CIDR net_range values (#188)
- Fixed a bug in IPASN/Net that caused the ASN result to vary if Cymru has
  more than one ASN listed for an IP (#190)
- Updated ElasticSearch example for ES v5.5.1 (#138)

0.15.1 (2017-02-16)
-------------------

- Fixed IPv6 parsing for ASN origin lookups and added tests (#162 - ti-mo)
- Fixed recursive role parsing at depths greater than 0 (#161 - cdubz)

0.15.0 (2017-02-02)
-------------------

- Python 3.3+ dnspython3 requirement changed to dnspython (#155)
- Added ASN origin lookup support (#149)
- Moved ASN parsing from net.Net.get_asn_*() to new class asn.IPASN.
  The original functions now return the raw query (#157)
- net.Net.lookup_asn() is deprecated in favor of asn.IPASN.lookup() (#157)
- Added new exception ASNParseError (#157)
- Fixed rate-limiting exception handling for when HTTP errors are returned
  rather than JSON errors (rikonor - #144)
- Fixed rate-limit infinite recursion bug for legacy whois (rikonor - #144)
- Fixed bug in net.Net.get_http_raw() that would pass the encoded form_data on
  retry rather than the original argument.
- Removed nose requirements and fixed travis.yml for updated pip
- Documentation updates
- Code style tweaks
- Updated tests and version info for Python 3.6
- Added basic stress tests (#144)
- Minor tweaks to existing tests

0.14.0 (2016-08-29)
-------------------

- Changed legacy whois emails output type to list (#133)
- Fixed retry count non-decrementing infinite loop in
  ipwhois.net.Net.get_whois() (issue #125 - krader1961)
- Added new function ipwhois.net.Net.get_http_raw() and tests (#67)
- Added National Internet Registry (JPNIC, KRNIC) support (#67). Enabled by
  default in IPWhois.lookup_*(). Disable by passing inc_nir=False. Optionally,
  lower level code can call nir.NIRWhois(). This enhancement results in extra
  network queries, but more detailed information for NIRs.
- Added utils CLI (ipwhois_utils_cli.py) - #121. Installed to your environments
  Scripts dir. This is a wrapper for utils.py.
- Documentation improvements (#123)
- kw arg readability (#115)
- Replaced usage of args with script_args in ipwhois_cli.py
- Minor optimization in whois.py and online/test_whois.py
- Added coveralls integration and re-enabled online tests with Travis CI
- Added Read the Docs support (#132)
- Added documentation (Sphinx) requirements.txt (#132)
- Fixed test imports
- Added --json argument (output in JSON format) to ipwhois_cli.py (#135)

0.13.0 (2016-04-18)
-------------------

- Added events_actor parsing for RDAP results.
- Added example for caching data via Redis (#81)
- Added normalization (human-readable field information) in hr.py (#47)
- README word wrap fix (#102)
- Fixed bug in exception handling for ASN HTTP lookups.
- Fixed bug in IPWhois.lookup_rdap() that caused ASN HTTP lookup responses to
  be used in place of RDAP responses.
- Added new function Net.get_asn_http() and migrated code from
  Net.lookup_asn() + new tests.
- Fixed bug in ASN HTTP fallback lookups for DNIC (#108).
- Added new parameter extra_org_map in Net.get_asn_http(), Net.lookup_asn(),
  and IPWhois.lookup*() (#108).
- Fixed _RDAPCommon.summarize_notices() None check - changed len() to all().
- Added CLI (ipwhois_cli.py) - #46. Installed to your environments Scripts dir.
  This is a wrapper for ipwhois.py (IPWhois). Utils CLI will be in a future
  release (#121).
- Documentation split up and added more detail (#81).

0.12.0 (2016-03-28)
-------------------

- Added headers parameter to ipwhois.Net.get_http_json() (issue #98).
- Fixed ASN HTTP lookup (fallback) Accept headers (issue #98).
- Fixed HTTP decoding, set to utf-8 (italomaia - issue #97)
- IPWhois.lookup() deprecated (issue #96), and will be removed in a future
  release (TBD). Use IPWhois.lookup_whois() instead.
- Added rate_limit_timeout parameter (issue #99) to Net.get_http_json(),
  IPWhois.lookup_rdap(), and RDAP.lookup(). New exception HTTPRateLimitError.
- Added new parameter asn_alts to Net.lookup_asn(), IPWhois.lookup_rdap() and
  IPWhois.lookup(). Takes a list of lookup types to attempt if the
  ASN dns lookup fails. Allow permutations must be enabled. Defaults to all
  ['whois', 'http'] (issue #93).
- Fixed socket exception handling in Net.get_http_json() for Python 2.6.
- Fixed assertIsInstance for Python 2.6 tests (issue #100). Implemented
  unittest._formatMessage and unittest.util.safe_repr for Python 2.6.
- Moved TestCommon to tests\\__init__.py to avoid duplicate code.
- Replaced remaining % with str.format (issue #95).

0.11.2 (2016-02-25)
-------------------

- Added allow_permutations parameter (bool) to net.Net() and ipwhois.IPWhois()
  to allow alternate ASN lookups if DNS lookups fail. (FirefighterBlu3)
- Fixed ASN DNS resolver timeout/retry_count support. Retry count is used as a
  multiplier of timeout, to determine a limetime interval. (FirefighterBlu3)
- Fixed bug where remarks would return None if missing a title.
- Added CONTRIBUTING.rst
- Added tests

0.11.1 (2015-12-17)
-------------------

- Re-added CIDR calculation for RDAP lookups.
- Improved tests - core code coverage now 100%. See '# pragma: no cover' for
  exclusions. A few bugs were identified in the process, detailed below.
- Moved IP zero stripping from rdap._RDAPNetwork.parse() to new helper function
  utils.ipv4_lstrip_zeros().
- Moved CIDR calculation from rdap._RDAPNetwork.parse() to new helper function
  utils.calculate_cidr().
- Fixed utils.ipv4_is_defined() if statement ordering for RFC 1918 conflict.
- Fixed utils.ipv6_is_defined() if statement ordering for Unspecified and
  Loopback (conflict with Reserved).
- Added is_offline parameter to whois.Whois.lookup() primarily for testing.
- Fixed bug in whois.Whois._parse_fields() that attempted to parse 'val2' of
  regex, which is no longer used. Also fixed the expected Exception to be
  IndexError.
- Fixed bug in ipwhois.IPWhois.lookup() where the argument order was mixed up,
  causing referral lookups to be skipped when get_referral=True.
- Fixed bug in rdap._RDAPCommon.summarize_notices() output for links.
- Fixed bug in root entity iteration exception handling in rdap.RDAP.lookup().

0.11.0 (2015-11-02)
-------------------

- Support for REST lookups replaced with RDAP.
- Split code for a more structured system (net, whois, rdap, exceptions).
- Tests match the data new structure.
- Split tests for online and offline testing.
- Performance enhancements for parsing.
- Added an optional bootstrap parameter for RDAP lookups, in order to replace
  ASN lookups or use both. Will default to False. Afrinic is currently not
  supported, so I would not use this for now. ARIN acknowledged my issue
  for this, and will be adding support back in for Afrinic bootstrap.
- Added field_list parameter (inclusion list) for WHOIS lookups.
- Added logging.
- Added examples directory.

0.10.3 (2015-08-14)
-------------------

- Fixed LACNIC lookup_rws() queries, since they switched to RDAP. This is
  temporary to get it working until the major library transition to RDAP and
  new parsed formatting is complete.

0.10.2 (2015-05-19)
-------------------

- Fixed APNIC parsing for updated field.
- Fixed datetime parsing and validation when Zulu (Z) is appended.
- Added RIPE parsing for created and updated fields (whois and RWS).
- Removed unnecessary parentheses in IPWhois class declaration.
- Some documentation and comment tweaking to work with Sphinx.
- Minor PEP 8 tweaks.

0.10.1 (2015-02-09)
-------------------

- Fixed setup.py bug.

0.10.0 (2015-02-09)
-------------------

- Added .csv support for country code source. You can no longer download
  country code information from iso.org.
- Added support for IPv4Address or IPv6Address as the address arg in IPWhois.
- Fixed file open encoding bug. Moved from open to io.open.
- Fixed parameter in IPWhois ip defined checks.
- Fixed TestIPWhois.test_ip_invalid() assertions.
