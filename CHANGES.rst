Changelog
=========

0.1.5 ()
------------------

- Added set_proxy() function for proxy support in Whois-RWS queries.
- Added IPWhois.lookup_rws() function for Whois-RWS queries.

0.1.4 (2013-09-12)
------------------

- Added validity checks for the asn_registry value due to a bug in the Team Cymru ASN lookup over night.
- Added timeout argument to IPWhois(). This is the default timeout in seconds for socket connections.
- Fixed decoding issue in IPWhois.get_whois().

0.1.3 (2013-09-11)
------------------

- Added exception handling with query retry support for socket errors, timeouts, connection resets.
- Moved ASN queries to their own functions (IPWhois.get_asn_dns() and IPWhois.get_asn_whois())
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