=============
Upgrade Notes
=============

Version upgrade notes, warnings, and critical changes will be displayed here.
This does not supplement the changelog, but serves to provide information on
any changes that may affect user experience when upgrading to a new release.

This page is new as of version 1.0.0. Any information on older versions is
likely missing or incomplete.

******
v1.0.0
******

- Removed deprecated IPWhois.lookup() - This was moved to
  IPWhois.lookup_whois()
- HTTPS (port 443) requirement added for KRNIC lookups.
- Experimental bulk functions added: experimental.get_bulk_asn_whois and
  experimental.bulk_lookup_rdap.
- Added new return key asn_description to net.Net.get_asn_whois,
  experimental.get_bulk_asn_whois, and hr.py. New argument get_asn_description
  to disable additional DNS lookups added to CLI.
- The IPWhois argument allow_permutations and the lookup argument asn_alts
  have been deprecated in favor of new argument asn_methods.
- Deprecated unnecessary protected class functions, changed to public in
  asn.py, nir.py, and whois.py (#184): asn.IPASN._parse_fields_dns,
  asn.IPASN._parse_fields_whois, asn.IPASN._parse_fields_http,
  asn.ASNOrigin._parse_fields, asn.ASNOrigin._get_nets_radb,
  nir.NIRWhois._parse_fields, nir.NIRWhois._get_nets_jpnic,
  nir.NIRWhois._get_nets_krnic, nir.NIRWhois._get_contact,
  whois.Whois._parse_fields, whois.Whois._get_nets_arin,
  whois.Whois._get_nets_lacnic, whois.Whois._get_nets_other
- New IP generators added: utils.ipv4_generate_random and
  utils.ipv6_generate_random
- net.Net.get_host(), utils.ipv4_is_defined(), and utils.ipv6_is_defined now
  return namedtuple instead of tuple.

*******
v0.14.0
*******

- NIR (National Internet Registry) lookups are enabled by default. This is
  currently only performed for JPNIC and KRNIC addresses. To disable,
  set inc_nir=False in your IPWhois.lookup_*() query.
- The 'nets' -> 'emails' key in IPWhois.lookup_whois() was changed from a
  '\\n' separated string to a list.

*******
v0.11.0
*******

- The new RDAP return format was introduced and split off from the legacy
  whois return format. Using RDAP lookup (IPWhois.lookup_rdap()) is now the
  recommended method to maximize indexable values. RDAP return data is
  different in nearly every way from the legacy whois data. For information on
  raw RDAP responses, please see the RFC: https://tools.ietf.org/html/rfc7483