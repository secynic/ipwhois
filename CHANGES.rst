Changelog
=========

0.9.1 (TBD)
-----------

- Fixed ipaddress import conflicts with alternate ipaddress module.
- Tuned import exception in ipwhois.utils.
- Fixed retry handling in IPWhois.get_whois().

0.9.0 (2014-07-27)
------------------

- Fixed order on REST email fields
- Fixed setup error for initial install when dependencies don't exist.
- Added RWhois support.
- Added server and port parameters to IPWhois.get_whois().
- Added unique_addresses() to ipwhois.utils and unit tests.
- Added some unit tests to test_lookup().
- Replaced dict.copy() with copy.deepcopy(dict).
- Fixed bug in abuse emails parsing.
- Added handle and range values to returned nets dictionary.

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