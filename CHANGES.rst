Changelog
=========

0.11.1 (2015-12-21)
-------------------

- Re-added CIDR parsing for RDAP lookups.
- Improved tests - core code coverage now 100%. See '# pragma: no cover' for
  exclusions. A few bugs were identified in the process, detailed below.
- Moved IP zero stripping from rdap._RDAPNetwork.parse() to new helper function
  utils.ipv4_lstrip_zeros().
- Moved CIDR calculation from rdap._RDAPNetwork.parse() to new helper function
  utils.calculate_cidr().
- Fixed utils.ipv6_is_defined() if statement ordering for Unspecified and
  Loopback (conflict with Reserved).
- Added is_offline parameter to whois.Whois.lookup() primarily for testing.
- Fixed bug in whois.Whois._parse_fields() that attempted to parse 'val2' of
  regex, which is no longer used. Also fixed the expected Exception to be
  IndexError.
- Fixed bug in ipwhois.IPWhois.lookup() where the argument order was mixed up,
  causing referral lookups to be skipped when get_referral=True.
- Fixed bug in rdap._RDAPCommon.summarize_notices() output for links.

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