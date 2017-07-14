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

- The IPWhois argument allow_permutations and the lookup argument asn_alts
  have been deprecated in favor of new argument asn_methods.
- TODO

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