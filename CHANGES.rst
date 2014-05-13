Changelog
=========

0.8.2 (2014-05-12)
------------------

- Fixed multi-line field parsing (Issue #36).
- Added unique_everseen() to ipwhois.utils to fix multi-line field order.
- Re-added support for RIPE RWS now that their API is fixed.

0.8.1 (2014-03-05)
------------------

- Fixed encoding error in IPWhois.get_whois().

0.8.0 (2014-02-18)
------------------

- Added ASNRegistryError to handle unknown ASN registry return values.
- Added ASN registry lookup third tier fallback to ARIN.
- Fixed variable naming to avoid shadows built-in confusion.
- Fixed some type errors: Expected type 'str', got 'dict[str, dict]' instead.
- Fixed RIPE RWS links, since they changed their API.
- Temporarily removed RIPE RWS functionality until they fix their API.
- Removed RADB fallback, since RIPE removed it.

0.7.0 (2014-01-14)
------------------

- Added Python 2.6+ support.
- The country field in net dicts is now forced uppercase.

0.6.0 (2014-01-13)
------------------

- Added APNIC RWS support for IPWhois.lookup_rws().
- Fixed issue in IPWhois.lookup_rws() for radb-grs fallback.

0.5.2 (2013-12-07)
------------------

- Fixed special character issue in countries XML file (Issue #23).

0.5.1 (2013-12-03)
------------------

- Moved regex string literal declarations to NIC_WHOIS dict.
- Moved RWS parsing to own private functions.
- Moved base_net dict to global BASE_NET.
- More granular exception handling in lookup functions.
- Fixed email parsing for ARIN and RIPE RWS.
- Changed some 'if key in dict' statements to try/except for slight performance
  increase in lookup functions.
- Removed generic exception handling (returned blank dict) on get_countries().
- More PEP 8 reformatting.
- Minor docstring modifications.
- Added some unit tests to test_lookup() and test_lookup_rws().

0.5.0 (2013-11-20)
------------------

- Reformatting for PEP 8 compliance.
- Added LACNIC RWS (Beta v2) support for IPWhois.lookup_rws().

0.4.0 (2013-10-17)
------------------

- Added support for network registered and updated time stamps (keys: created,
  updated). Value in ISO 8601 format.
- Added value assertion to test_utils.py.
- Fixed IPWhois.lookup() handling of processed values. If processing throws
  an exception, discard the value and not the net dictionary.

0.3.0 (2013-09-30)
------------------

- Fixed get_countries() to work with frozen executables.
- Added dnspython3 rdtypes import to fix issue with frozen executables.
- Moved iso_3166-1_list_en.xml to /data.
- Added retry_count to IPWhois.lookup() and IPWhois.lookup_rws().

0.2.1 (2013-09-27)
------------------

- Fixed LACNIC CIDR validation on IPWhois.lookup().
- Fixed bug in IPWhois.get_whois() for query rate limiting. This was discovered
  via testing multiprocessing with 8+ processes running asynchronously.

0.2.0 (2013-09-23)
------------------

- Added support for emails (keys: abuse_emails, tech_emails, misc_emails).
- Changed regex to use group naming for more complex searching.
- Added some missing exception handling in lookup_rws().

0.1.9 (2013-09-18)
------------------

- Added exceptions to import in __init__.py.
- Added IPWhois.__repr__().
- Moved exceptions to get_*() functions.
- Added exception HostLookupError.
- Various optimizations.
- Added some unit tests.

0.1.8 (2013-09-17)
------------------

- Removed set_proxy() in favor of having the user provide their own
  urllib.request.OpenerDirector instance as a parameter to IPWhois().
- Restructured package in favor of modularity. get_countries() is now located
  in ipwhois.utils.
- Added exception WhoisLookupError for IPWhois.lookup() and
  IPWhois.lookup_rws().

0.1.7 (2013-09-16)
------------------

- Fixed bug in set_proxy().
- Removed ARIN top level network entries from return dictionary of
  IPWhois.lookup_rws().
- Fixed bug in ARIN RWS parsing when only one network.

0.1.6 (2013-09-16)
------------------

- Added IPWhois.get_host() to resolve hostname information.
- Added address and postal_code fields to parsed results.
- Normalized single/double quote use.

0.1.5 (2013-09-13)
------------------

- Added set_proxy() function for proxy support in Whois-RWS queries.
- Added IPWhois.lookup_rws() function for Whois-RWS queries.

0.1.4 (2013-09-12)
------------------

- Added validity checks for the asn_registry value due to a bug in the Team
  Cymru ASN lookup over night.
- Added timeout argument to IPWhois(). This is the default timeout in seconds
  for socket connections.
- Fixed decoding issue in IPWhois.get_whois().

0.1.3 (2013-09-11)
------------------

- Added exception handling with query retry support for socket errors,
  timeouts, connection resets.
- Moved ASN queries to their own functions (IPWhois.get_asn_dns() and
  IPWhois.get_asn_whois())
- Moved whois query to its own function (IPWhois.get_whois())
- Country codes are now forced as upper case in the return dictionary.

0.1.2 (2013-09-10)
------------------

- Fixed file path for get_countries().
- Fixed variable names that conflicted with builtins.
- Added content to README.
- Moved CHANGES.txt to CHANGES.rst and added to setup.py.
- Download URL now points to GitHub master tarball.

0.1.1 (2013-09-09)
------------------

- Fixed README issue.

0.1.0 (2013-09-06)
------------------

- Initial release.