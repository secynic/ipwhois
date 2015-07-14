# Copyright (c) 2013, 2014, 2015 Philip Hane
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys

if sys.version_info >= (3, 3):
    from ipaddress import (ip_address,
                           IPv4Address,
                           IPv6Address,
                           ip_network,
                           summarize_address_range,
                           collapse_addresses)
else:
    from ipaddr import (IPAddress as ip_address,
                        IPv4Address,
                        IPv6Address,
                        IPNetwork as ip_network,
                        summarize_address_range,
                        collapse_address_list as collapse_addresses)

import socket
import dns.resolver
import re
import copy
import json
from .utils import ipv4_is_defined, ipv6_is_defined, unique_everseen

try:
    from urllib.request import (OpenerDirector,
                                ProxyHandler,
                                build_opener,
                                Request)
except ImportError:
    from urllib2 import (OpenerDirector,
                         ProxyHandler,
                         build_opener,
                         Request)

from time import sleep
from datetime import datetime

# Import the dnspython3 rdtypes to fix the dynamic import problem when frozen.
import dns.rdtypes.ANY.TXT  # @UnusedImport

IETF_RFC_REFERENCES = {
    # IPv4
    'RFC 1122, Section 3.2.1.3':
    'http://tools.ietf.org/html/rfc1122#section-3.2.1.3',
    'RFC 1918': 'http://tools.ietf.org/html/rfc1918',
    'RFC 3927': 'http://tools.ietf.org/html/rfc3927',
    'RFC 5736': 'http://tools.ietf.org/html/rfc5736',
    'RFC 5737': 'http://tools.ietf.org/html/rfc5737',
    'RFC 3068': 'http://tools.ietf.org/html/rfc3068',
    'RFC 2544': 'http://tools.ietf.org/html/rfc2544',
    'RFC 3171': 'http://tools.ietf.org/html/rfc3171',
    'RFC 919, Section 7': 'http://tools.ietf.org/html/rfc919#section-7',
    # IPv6
    'RFC 4291, Section 2.7': 'http://tools.ietf.org/html/rfc4291#section-2.7',
    'RFC 4291': 'http://tools.ietf.org/html/rfc4291',
    'RFC 4291, Section 2.5.2':
    'http://tools.ietf.org/html/rfc4291#section-2.5.2',
    'RFC 4291, Section 2.5.3':
    'http://tools.ietf.org/html/rfc4291#section-2.5.3',
    'RFC 4291, Section 2.5.6':
    'http://tools.ietf.org/html/rfc4291#section-2.5.6',
    'RFC 4291, Section 2.5.7':
    'http://tools.ietf.org/html/rfc4291#section-2.5.7',
    'RFC 4193': 'https://tools.ietf.org/html/rfc4193'
}

NIC_WHOIS = {
    'arin': {
        'server': 'whois.arin.net',
        'url': (
            'http://whois.arin.net/rest/nets;q={0}?'
            'showDetails=true&showARIN=true'
        ),
        'fields': {
            'name': r'(NetName):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(NetHandle):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(OrgName|CustName):[^\S\n]+(?P<val>.+?)'
                    '(?=(\n\S):?)',
            'country': r'(Country):[^\S\n]+(?P<val>.+?)\n',
            'state': r'(StateProv):[^\S\n]+(?P<val>.+?)\n',
            'city': r'(City):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(Address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'postal_code': r'(PostalCode):[^\S\n]+(?P<val>.+?)\n',
            'abuse_emails': r'(OrgAbuseEmail):[^\S\n]+(?P<val>.+?)\n',
            'tech_emails': r'(OrgTechEmail):[^\S\n]+(?P<val>.+?)\n',
            'created': r'(RegDate):[^\S\n]+(?P<val>.+?)\n',
            'updated': r'(Updated):[^\S\n]+(?P<val>.+?)\n',
        },
        'dt_format': '%Y-%m-%d',
        'dt_rws_format': '%Y-%m-%dT%H:%M:%S%z'
    },
    'ripencc': {
        'server': 'whois.ripe.net',
        'url': 'http://rest.db.ripe.net/search.json?query-string={0}',
        'fields': {
            'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(descr):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'abuse_emails': (
                r'(abuse-mailbox:[^\S\n]+(?P<val>.+?))\n|(((?!abuse-mailbox).+'
                '?:.*?[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.'
                '[\w\-]+)([^\S\n]+.*?)*?)\n)'
            ),
            'misc_emails': (
                r'(?!abuse-mailbox).+?:.*?[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@'
                '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
            ),
            'created': (
                r'(created):[^\S\n]+(?P<val>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]'
                '{2}:[0-9]{2}:[0-9]{2}Z).*?\n'
            ),
            'updated': (
                r'(last-modified):[^\S\n]+(?P<val>[0-9]{4}-[0-9]{2}-[0-9]{2}T'
                '[0-9]{2}:[0-9]{2}:[0-9]{2}Z).*?\n'
            )
        },
        'dt_format': '%Y-%m-%dT%H:%M:%SZ',
        'dt_rws_format': '%Y-%m-%dT%H:%M:%SZ'
    },
    'apnic': {
        'server': 'whois.apnic.net',
        'url': 'http://rdap.apnic.net/ip/{0}',
        'fields': {
            'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(descr):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'abuse_emails': (
                r'(abuse-mailbox:[^\S\n]+(?P<val>.+?))\n|(((?!abuse-mailbox).+'
                '?:.*?[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.'
                '[\w\-]+)([^\S\n]+.*?)*?)\n)'
            ),
            'misc_emails': (
                r'(?!abuse-mailbox).+?:.*?[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@'
                '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
            ),
            'updated': r'(changed):[^\S\n]+.*(?P<val>[0-9]{8}).*?\n'
        },
        'dt_format': '%Y%m%d',
        'dt_rws_format': '%Y-%m-%dT%H:%M:%SZ'
    },
    'lacnic': {
        'server': 'whois.lacnic.net',
        'url': 'http://restfulwhoisv2.labs.lacnic.net/restfulwhois/ip/{0}',
        'fields': {
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(owner):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'abuse_emails': (
                r'(abuse-mailbox:[^\S\n]+(?P<val>.+?))\n|(((?!abuse-mailbox).+'
                '?:.*?[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.'
                '[\w\-]+)([^\S\n]+.*?)*?)\n)'
            ),
            'misc_emails': (
                r'(?!abuse-mailbox).+?:.*?[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@'
                '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
            ),
            'created': r'(created):[^\S\n]+(?P<val>[0-9]{8}).*?\n',
            'updated': r'(changed):[^\S\n]+(?P<val>[0-9]{8}).*?\n'
        },
        'dt_format': '%Y%m%d',
        'dt_rws_format': '%Y%m%d'
    },
    'afrinic': {
        'server': 'whois.afrinic.net',
        'url': 'http://rest.db.ripe.net/search.json?query-string={0}',
        'fields': {
            'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(descr):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'abuse_emails': (
                r'(abuse-mailbox:[^\S\n]+(?P<val>.+?))\n|(((?!abuse-mailbox).+'
                '?:.*?[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.'
                '[\w\-]+)([^\S\n]+.*?)*?)\n)'
            ),
            'misc_emails': (
                r'(?!abuse-mailbox).+?:.*?[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@'
                '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
            )
        }
    }
}

RWHOIS = {
    'fields': {
        'cidr': r'(network:IP-Network):(?P<val>.+?)\n',
        'name': r'(network:ID):(?P<val>.+?)\n',
        'description': (
            r'(network:(Org-Name|Organization(;I)?)):(?P<val>.+?)\n'
        ),
        'country': r'(network:(Country|Country-Code)):(?P<val>.+?)\n',
        'state': r'(network:State):(?P<val>.+?)\n',
        'city': r'(network:City):(?P<val>.+?)\n',
        'address': r'(network:Street-Address):(?P<val>.+?)\n',
        'postal_code': r'(network:Postal-Code):(?P<val>.+?)\n',
        'abuse_emails': (
            r'(network:Abuse-Contact(;I)?):[^\S\n]+(?P<val>[\w\-\.]+?@'
            '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
        ),
        'tech_emails': (
            r'(network:Tech-Contact(;I)?):[^\S\n]+(?P<val>[\w\-\.]+?@'
            '[\w\-\.]+\.[\w\-]+)([^\S\n]+.*?)*?\n'
        ),
        'misc_emails': (
            r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)'
            '([^\S\n]+.*?)*?\n'
        ),
        'created': r'(network:Created):(?P<val>.+?)\n',
        'updated': r'(network:Updated):(?P<val>.+?)\n'
    }
}

BLACKLIST = [
    'root.rwhois.net'
]

ASN_REFERRALS = {
    'whois://whois.ripe.net': 'ripencc',
    'whois://whois.apnic.net': 'apnic',
    'whois://whois.lacnic.net': 'lacnic',
    'whois://whois.afrinic.net': 'afrinic',
}

CYMRU_WHOIS = 'whois.cymru.com'

IPV4_DNS_ZONE = '{0}.origin.asn.cymru.com'

IPV6_DNS_ZONE = '{0}.origin6.asn.cymru.com'

BASE_NET = {
    'cidr': None,
    'name': None,
    'handle': None,
    'range': None,
    'description': None,
    'country': None,
    'state': None,
    'city': None,
    'address': None,
    'postal_code': None,
    'abuse_emails': None,
    'tech_emails': None,
    'misc_emails': None,
    'created': None,
    'updated': None
}

BASE_PERSON = {
    'person': None,
    'address': None,
    'phone': None,
    'mnt-by': None,
    'nic-hdl': None,
    'created': None,
    'last-modified': None,
    'source': None
}


class IPDefinedError(Exception):
    """
    An Exception for when the IP is defined (does not need to be resolved).
    """


class ASNLookupError(Exception):
    """
    An Exception for when the ASN lookup failed.
    """


class ASNRegistryError(Exception):
    """
    An Exception for when the ASN registry does not match one of the five
    expected values (arin, ripencc, apnic, lacnic, afrinic).
    """


class WhoisLookupError(Exception):
    """
    An Exception for when the whois lookup failed.
    """


class HostLookupError(Exception):
    """
    An Exception for when the host lookup failed.
    """


class BlacklistError(Exception):
    """
    An Exception for when the server is in a blacklist.
    """


class IPWhois:
    """
    The class for performing ASN/whois lookups and parsing for IPv4 and IPv6
    addresses.

    Args:
        address: An IPv4 or IPv6 address as a string, integer, IPv4Address, or
            IPv6Address.
        timeout: The default timeout for socket connections in seconds.
        proxy_opener: The urllib.request.OpenerDirector request for proxy
            support or None.

    Raises:
        IPDefinedError: The address provided is defined (does not need to be
            resolved).
    """

    def __init__(self, address, timeout=5, proxy_opener=None):

        # IPv4Address or IPv6Address
        if isinstance(address, IPv4Address) or isinstance(
                address, IPv6Address):

            self.address = address

        else:

            # Use ipaddress package exception handling.
            self.address = ip_address(address)

        # Default timeout for socket connections.
        self.timeout = timeout

        # Proxy opener.
        if isinstance(proxy_opener, OpenerDirector):

            self.opener = proxy_opener

        else:

            handler = ProxyHandler()
            self.opener = build_opener(handler)

        # IP address in string format for use in queries.
        self.address_str = self.address.__str__()

        # Determine the IP version, 4 or 6
        self.version = self.address.version

        if self.version == 4:

            # Check if no ASN/whois resolution needs to occur.
            is_defined = ipv4_is_defined(self.address_str)

            if is_defined[0]:

                raise IPDefinedError(
                    'IPv4 address %r is already defined as %r via '
                    '%r.' % (
                        self.address_str, is_defined[1], is_defined[2]
                    )
                )

            # Reverse the IPv4Address for the DNS ASN query.
            split = self.address_str.split('.')
            split.reverse()
            self.reversed = '.'.join(split)

            self.dns_zone = IPV4_DNS_ZONE.format(self.reversed)

        else:

            # Check if no ASN/whois resolution needs to occur.
            is_defined = ipv6_is_defined(self.address_str)

            if is_defined[0]:

                raise IPDefinedError(
                    'IPv6 address %r is already defined as %r via '
                    '%r.' % (
                        self.address_str, is_defined[1], is_defined[2]
                    )
                )

            # Explode the IPv6Address to fill in any missing 0's.
            exploded = self.address.exploded

            # Cymru seems to timeout when the IPv6 address has trailing '0000'
            # groups. Remove these groups.
            groups = exploded.split(':')
            for index, value in reversed(list(enumerate(groups))):

                if value == '0000':

                    del groups[index]

                else:

                    break

            exploded = ':'.join(groups)

            # Reverse the IPv6Address for the DNS ASN query.
            val = str(exploded).replace(':', '')
            val = val[::-1]
            self.reversed = '.'.join(val)

            self.dns_zone = IPV6_DNS_ZONE.format(self.reversed)

    def __repr__(self):

        return 'IPWhois(%r, %r, %r)' % (
            self.address_str, self.timeout, self.opener
        )

    def get_asn_dns(self):
        """
        The function for retrieving ASN information for an IP address from
        Cymru via port 53 (DNS).

        Returns:
            Dictionary: A dictionary containing the following keys:
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNLookupError: The ASN lookup failed.
        """

        try:

            data = dns.resolver.query(self.dns_zone, 'TXT')

            # Parse out the ASN information.
            temp = str(data[0]).split('|')

            ret = {'asn_registry': temp[3].strip(' \n')}

            if ret['asn_registry'] not in NIC_WHOIS.keys():

                raise ASNRegistryError(
                    'ASN registry %r is not known.' % ret['asn_registry']
                )

            ret['asn'] = temp[0].strip(' "\n')
            ret['asn_cidr'] = temp[1].strip(' \n')
            ret['asn_country_code'] = temp[2].strip(' \n').upper()
            ret['asn_date'] = temp[4].strip(' "\n')

            return ret

        except ASNRegistryError:

            raise

        except:

            raise ASNLookupError(
                'ASN lookup failed for %r.' % self.address_str
            )

    def get_asn_whois(self, retry_count=3):
        """
        The function for retrieving ASN information for an IP address from
        Cymru via port 43 (WHOIS).

        Args:
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            Dictionary: A dictionary containing the following keys:
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNLookupError: The ASN lookup failed.
        """

        try:

            # Create the connection for the Cymru whois query.
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect((CYMRU_WHOIS, 43))

            # Query the Cymru whois server, and store the results.
            conn.send((
                ' -r -a -c -p -f -o %s%s' % (self.address_str, '\r\n')
            ).encode())

            data = ''
            while True:

                d = conn.recv(4096).decode()
                data += d

                if not d:

                    break

            conn.close()

            # Parse out the ASN information.
            temp = str(data).split('|')

            ret = {'asn_registry': temp[4].strip(' \n')}

            if ret['asn_registry'] not in NIC_WHOIS.keys():

                raise ASNRegistryError(
                    'ASN registry %r is not known.' % ret['asn_registry']
                )

            ret['asn'] = temp[0].strip(' \n')
            ret['asn_cidr'] = temp[2].strip(' \n')
            ret['asn_country_code'] = temp[3].strip(' \n').upper()
            ret['asn_date'] = temp[5].strip(' \n')

            return ret

        except (socket.timeout, socket.error):

            if retry_count > 0:

                return self.get_asn_whois(retry_count - 1)

            else:

                raise ASNLookupError(
                    'ASN lookup failed for %r.' % self.address_str
                )

        except ASNRegistryError:

            raise

        except:

            raise ASNLookupError(
                'ASN lookup failed for %r.' % self.address_str
            )

    def get_whois(self, asn_registry='arin', retry_count=3, server=None,
                  port=43, extra_blacklist=None):
        """
        The function for retrieving whois or rwhois information for an IP
        address via any port. Defaults to port 43 (WHOIS).

        Args:
            asn_registry: The NIC to run the query against.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.
            server: An optional server to connect to. If provided, asn_registry
                will be ignored.
            port: The network port to connect on.
            extra_blacklist: A list of blacklisted whois servers in addition to
                the global BLACKLIST.

        Returns:
            String: The raw whois data.

        Raises:
            BlacklistError: Raised if the whois server provided is in the
                global BLACKLIST or extra_blacklist.
            WhoisLookupError: The whois lookup failed.
        """

        try:

            extra_bl = extra_blacklist if extra_blacklist else []

            if server in (BLACKLIST, extra_bl):
                raise BlacklistError(
                    'The server %r is blacklisted.' % server
                )

            if server is None:
                server = NIC_WHOIS[asn_registry]['server']

            # Create the connection for the whois query.
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)

            conn.connect((server, port))

            # Prep the query.
            query = self.address_str + '\r\n'
            if asn_registry == 'arin':

                query = 'n + %s' % query

            # Query the whois server, and store the results.
            conn.send(query.encode())

            response = ''
            while True:

                d = conn.recv(4096).decode('ascii', 'ignore')

                response += d

                if not d:

                    break

            conn.close()

            if 'Query rate limit exceeded' in response:

                sleep(1)
                return self.get_whois(asn_registry, retry_count, server, port,
                                      extra_blacklist)

            elif 'error 501' in response or 'error 230' in response:

                raise ValueError

            return str(response)

        except (socket.timeout, socket.error):

            if retry_count > 0:

                return self.get_whois(asn_registry, retry_count - 1, server,
                                      port, extra_blacklist)

            else:

                raise WhoisLookupError(
                    'Whois lookup failed for %r.' % self.address_str
                )

        except:

            raise WhoisLookupError(
                'Whois lookup failed for %r.' % self.address_str
            )

    def get_rws(self, url=None, retry_count=3):
        """
        The function for retrieving Whois-RWS information for an IP address
        via HTTP (Whois-RWS).

        Args:
            url: The URL to retrieve.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            Dictionary: The whois data in Json format.

        Raises:
            WhoisLookupError: The whois RWS lookup failed.
        """

        try:

            # Create the connection for the whois query.
            conn = Request(url, headers={'Accept': 'application/json'})
            data = self.opener.open(conn, timeout=self.timeout)
            try:
                d = json.loads(data.readall().decode())
            except AttributeError:
                d = json.loads(data.read().decode('ascii', 'ignore'))

            return d

        except (socket.timeout, socket.error):

            if retry_count > 0:

                return self.get_rws(url, retry_count - 1)

            else:

                raise WhoisLookupError('Whois RWS lookup failed for %r.' %
                                       url)

        except:

            raise WhoisLookupError('Whois RWS lookup failed for %r.' % url)

    def get_host(self, retry_count=3):
        """
        The function for retrieving host information for an IP address.

        Args:
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            Tuple: hostname, aliaslist, ipaddrlist

        Raises:
            HostLookupError: The host lookup failed.
        """

        try:

            default_timeout_set = False
            if not socket.getdefaulttimeout():

                socket.setdefaulttimeout(self.timeout)
                default_timeout_set = True

            ret = socket.gethostbyaddr(self.address_str)

            if default_timeout_set:

                socket.setdefaulttimeout(None)

            return ret

        except (socket.timeout, socket.error):

            if retry_count > 0:

                return self.get_host(retry_count - 1)

            else:

                raise HostLookupError(
                    'Host lookup failed for %r.' % self.address_str
                )

        except:

            raise HostLookupError(
                'Host lookup failed for %r.' % self.address_str
            )

    def _parse_fields(self, response, fields_dict, net_start=None,
                      net_end=None, dt_format=None):
        """
        The function for parsing whois fields from a data input.

        Args:
            response: The response from the whois/rwhois server.
            fields_dict: The dictionary of fields -> regex search values.
            net_start: The starting point of the network (if parsing multiple
                networks).
            net_end: The ending point of the network (if parsing multiple
                networks).
            dt_format: The format of datetime fields if known.

        Returns:
            Dictionary: A dictionary of fields provided in fields_dict.
        """

        ret = {}

        for field in fields_dict:

            pattern = re.compile(
                str(fields_dict[field]),
                re.DOTALL
            )

            if net_start is not None:

                match = pattern.finditer(response, net_end, net_start)

            elif net_end is not None:

                match = pattern.finditer(response, net_end)

            else:

                match = pattern.finditer(response)

            values = []
            sub_section_end = None
            for m in match:

                if sub_section_end:

                    if field not in (
                        'abuse_emails',
                        'tech_emails',
                        'misc_emails'
                    ) and (sub_section_end != (m.start() - 1)):

                        break

                try:

                    values.append(m.group('val').strip())

                except AttributeError:

                    values.append(m.group('val2').strip())

                sub_section_end = m.end()

            if len(values) > 0:

                value = None
                try:

                    if field == 'country':

                        value = values[0].upper()

                    elif field in ['created', 'updated'] and dt_format:

                        value = datetime.strptime(
                            values[0],
                            str(dt_format)).isoformat('T')

                    else:

                        values = unique_everseen(values)
                        value = '\n'.join(values)

                except ValueError:

                    pass

                ret[field] = value

        return ret

    def lookup(self, inc_raw=False, retry_count=3, get_referral=False,
               extra_blacklist=None, ignore_referral_errors=False):
        """
        The function for retrieving and parsing whois information for an IP
        address via port 43 (WHOIS).

        Args:
            inc_raw: Boolean for whether to include the raw whois results in
                the returned dictionary.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.
            get_referral: Boolean for whether to retrieve referral whois
                information, if available.
            extra_blacklist: A list of blacklisted whois servers in addition to
                the global BLACKLIST.
            ignore_referral_errors: Boolean for whether to ignore and continue
                when an exception is encountered on referral whois lookups.

        Returns:
            Dictionary:

            :query: The IP address (String)
            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)
            :nets: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. (List)
            :persons: Dictionaries containing information related to persons
                e.g. admin-c, tech-c (List)
            :raw: Raw whois results if the inc_raw parameter is True. (String)
            :referral: Dictionary of referral whois information if get_referral
                is True and the server isn't blacklisted. Consists of fields
                listed in the RWHOIS dictionary. Additional referral server
                informaion is added in the server and port keys. (Dictionary)
            :raw_referral: Raw referral whois results if the inc_raw parameter
                is True. (String)
        """

        # Initialize the whois response.
        response = None

        # Attempt to resolve ASN info via Cymru. DNS is faster, try that first.
        try:

            asn_data = self.get_asn_dns()

        except (ASNLookupError, ASNRegistryError):

            try:

                asn_data = self.get_asn_whois(retry_count)

            except (ASNLookupError, ASNRegistryError):

                # Lets attempt to get the ASN registry information from ARIN.
                response = self.get_whois('arin', retry_count)

                asn_data = {
                    'asn_registry': None,
                    'asn': None,
                    'asn_cidr': None,
                    'asn_country_code': None,
                    'asn_date': None
                }

                matched = False
                for match in re.finditer(
                    r'^ReferralServer:[^\S\n]+(.+)$',
                    response,
                    re.MULTILINE
                ):

                    matched = True

                    try:

                        referral = match.group(1)
                        referral = referral.replace(':43', '')

                        asn_data['asn_registry'] = ASN_REFERRALS[referral]

                    except KeyError:

                        raise ASNRegistryError('ASN registry lookup failed.')

                    break

                if not matched:

                    asn_data['asn_registry'] = 'arin'

        # Create the return dictionary.
        results = {
            'query': self.address_str,
            'nets': [],
            'persons': [],
            'raw': None,
            'referral': None,
            'raw_referral': None
        }

        # Add the ASN information to the return dictionary.
        results.update(asn_data)

        # The referral server and port. Only used if get_referral is True.
        referral_server = None
        referral_port = 0

        # Only fetch the response if we haven't already.
        if response is None or results['asn_registry'] is not 'arin':

            # Retrieve the whois data.
            response = self.get_whois(results['asn_registry'], retry_count,
                                      extra_blacklist=extra_blacklist)

            if get_referral:

                # Search for a referral server.
                for match in re.finditer(
                    r'^ReferralServer:[^\S\n]+(.+:[0-9]+)$',
                    response,
                    re.MULTILINE
                ):

                    try:

                        temp = match.group(1)
                        if 'rwhois://' not in temp:
                            raise ValueError

                        temp = temp.replace('rwhois://', '').split(':')

                        if int(temp[1]) > 65535:
                            raise ValueError

                        referral_server = temp[0]
                        referral_port = int(temp[1])

                    except (ValueError, KeyError):

                        continue

                    break

        # Retrieve the referral whois data.
        if get_referral and referral_server:

            response_ref = None

            if ignore_referral_errors:

                try:

                    response_ref = self.get_whois('',
                                                  retry_count,
                                                  referral_server,
                                                  referral_port,
                                                  extra_blacklist)

                except (BlacklistError, WhoisLookupError):

                    pass

            else:

                response_ref = self.get_whois('', retry_count,
                                              referral_server, referral_port,
                                              extra_blacklist)

            if response_ref:

                if inc_raw:

                    results['raw_referral'] = response_ref

                temp_rnet = self._parse_fields(
                    response_ref,
                    RWHOIS['fields']
                )

                # Add the networks to the return dictionary.
                results['referral'] = temp_rnet

        # If inc_raw parameter is True, add the response to return dictionary.
        if inc_raw:

            results['raw'] = response

        nets = []

        persons = []

        if results['asn_registry'] == 'arin':

            # Find the first NetRange value.
            pattern = re.compile(
                r'^NetRange:[^\S\n]+(.+)$',
                re.MULTILINE
            )
            temp = pattern.search(response)
            net_range = None
            net_range_start = None
            if temp is not None:
                net_range = temp.group(1).strip()
                net_range_start = temp.start()

            # Iterate through all of the networks found, storing the CIDR value
            # and the start and end positions.
            for match in re.finditer(
                r'^CIDR:[^\S\n]+(.+?,[^\S\n].+|.+)$',
                response,
                re.MULTILINE
            ):

                try:

                    net = copy.deepcopy(BASE_NET)

                    if len(nets) > 0:
                        temp = pattern.search(response, match.start())
                        net_range = None
                        net_range_start = None
                        if temp is not None:
                            net_range = temp.group(1).strip()
                            net_range_start = temp.start()

                    if net_range is not None:
                        if net_range_start < match.start() or len(nets) > 0:
                            net['range'] = net_range

                    net['cidr'] = ', '.join(
                        [ip_network(c.strip()).__str__()
                         for c in match.group(1).split(', ')]
                    )
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)

                except ValueError:

                    pass

        elif results['asn_registry'] == 'lacnic':

            # Iterate through all of the networks found, storing the CIDR value
            # and the start and end positions.
            for match in re.finditer(
                r'^(inetnum|inet6num|route):[^\S\n]+(.+?,[^\S\n].+|.+)$',
                response,
                re.MULTILINE
            ):

                try:

                    net = copy.deepcopy(BASE_NET)
                    net['range'] = match.group(2).strip()

                    temp = []
                    for addr in match.group(2).strip().split(', '):

                        count = addr.count('.')
                        if count is not 0 and count < 4:

                            addr_split = addr.strip().split('/')
                            for i in range(count + 1, 4):
                                addr_split[0] += '.0'

                            addr = '/'.join(addr_split)

                        temp.append(ip_network(addr.strip()).__str__())

                    net['cidr'] = ', '.join(temp)
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)

                except ValueError:

                    pass

        else:

            # Iterate through all of the networks found, storing the CIDR value
            # and the start and end positions.
            for match in re.finditer(
                r'^(inetnum|inet6num|route):[^\S\n]+((.+?)[^\S\n]-[^\S\n](.+)|'
                    '.+)$',
                response,
                re.MULTILINE
            ):

                try:

                    net = copy.deepcopy(BASE_NET)
                    net['range'] = match.group(2)

                    if match.group(3) and match.group(4):

                        addrs = []
                        addrs.extend(summarize_address_range(
                            ip_address(match.group(3).strip()),
                            ip_address(match.group(4).strip())))

                        cidr = ', '.join(
                            [i.__str__() for i in collapse_addresses(addrs)]
                        )

                    else:

                        cidr = ip_network(match.group(2).strip()).__str__()

                    net['cidr'] = cidr
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)

                except (ValueError, TypeError):

                    pass

        # Iterate through all of the network sections and parse out the
        # appropriate fields for each.
        for index, net in enumerate(nets):

            section_end = None
            if index + 1 < len(nets):

                section_end = nets[index + 1]['start']

            try:

                dt_format = NIC_WHOIS[results['asn_registry']]['dt_format']

            except KeyError:

                dt_format = None

            temp_net = self._parse_fields(
                response,
                NIC_WHOIS[results['asn_registry']]['fields'],
                section_end,
                net['end'],
                dt_format
            )

            # Merge the net dictionaries.
            net.update(temp_net)

            # The start and end values are no longer needed.
            del net['start'], net['end']

        # Add the networks to the return dictionary.
        results['nets'] = nets

        return results

    def _lookup_rws_arin(self, response=None, retry_count=3):
        """
        The function for retrieving and parsing whois information for an ARIN
        IP address via HTTP (Whois-RWS).

        Args:
            response: The dictionary containing whois information to parse.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            List: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. Certain IPs
                have more granular network listings, hence the need for a list
                object.
        """

        nets = []

        try:

            net_list = response['nets']['net']

            if not isinstance(net_list, list):

                net_list = [net_list]

        except KeyError:

            net_list = []

        for n in net_list:

            if 'orgRef' in n and n['orgRef']['@handle'] in ('ARIN', 'VR-ARIN'):

                continue

            addrs = []
            net = copy.deepcopy(BASE_NET)

            try:

                addrs.extend(summarize_address_range(
                    ip_address(n['startAddress']['$'].strip()),
                    ip_address(n['endAddress']['$'].strip())))

                net['cidr'] = ', '.join(
                    [i.__str__() for i in collapse_addresses(addrs)]
                )

                net['range'] = (n['startAddress']['$'].strip() + ' - ' +
                                n['endAddress']['$'].strip())

            except (KeyError, ValueError, TypeError):

                pass

            for k, v in {
                'created': 'registrationDate',
                'updated': 'updateDate',
                'name': 'name'
            }.items():

                try:

                    net[k] = str(n[v]['$']).strip()

                except KeyError:

                    pass

            if 'handle' in n:

                net['handle'] = n['handle']['$'].strip()

            ref = None
            if 'customerRef' in n:

                ref = ['customerRef', 'customer']

            elif 'orgRef' in n:

                ref = ['orgRef', 'org']

            if ref is not None:

                try:

                    net['description'] = str(n[ref[0]]['@name']).strip()

                except KeyError:

                    pass

                try:

                    ref_url = n[ref[0]]['$'].strip() + '?showPocs=true'
                    ref_response = self.get_rws(ref_url, retry_count)

                except (KeyError, WhoisLookupError):

                    nets.append(net)
                    continue

                try:

                    addr_list = (
                        ref_response[ref[1]]['streetAddress']['line']
                    )

                    if not isinstance(addr_list, list):

                        addr_list = [addr_list]

                    net['address'] = '\n'.join(
                        [str(line['$']).strip() for line in addr_list]
                    )

                except KeyError:

                    pass

                for k, v in {
                    'postal_code': 'postalCode',
                    'city': 'city',
                    'state': 'iso3166-2'
                }.items():

                    try:

                        net[k] = str(ref_response[ref[1]][v]['$'])

                    except KeyError:

                        pass

                try:

                    net['country'] = (
                        str(ref_response[ref[1]]['iso3166-1']['code2']['$'])
                    ).upper()

                except KeyError:

                    pass

                try:

                    for poc in (
                        ref_response[ref[1]]['pocs']['pocLinkRef']
                    ):

                        if poc['@description'] in ('Abuse', 'Tech'):

                            poc_url = poc['$']
                            poc_response = self.get_rws(
                                poc_url,
                                retry_count
                            )

                            emails = poc_response['poc']['emails']['email']

                            if not isinstance(emails, list):

                                emails = [emails]

                            temp = []

                            for e in emails:

                                temp.append(str(e['$']).strip())

                            key = '%s_emails' % poc['@description'].lower()

                            net[key] = (
                                '\n'.join(unique_everseen(temp))
                                if len(temp) > 0 else None
                            )

                except (KeyError, WhoisLookupError):

                    pass

            nets.append(net)

        return nets

    def _lookup_rws_ripe(self, response=None):
        """
        The function for retrieving and parsing whois information for a RIPE
        IP address via HTTP (Whois-RWS).

        Args:
            response: The dictionary containing whois information to parse.

        Returns:
            List: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. Certain IPs
                have more granular network listings, hence the need for a list
                object.
        """

        nets = []

        persons = []

        try:

            object_list = response['objects']['object']

        except KeyError:

            object_list = []

        ripe_abuse_emails = []
        ripe_misc_emails = []

        net = copy.deepcopy(BASE_NET)

        for n in object_list:

            person = copy.deepcopy(BASE_PERSON)

            try:

                if n['type'] == 'role':


                    for attr in n['attributes']['attribute']:

                        if attr['name'] == 'abuse-mailbox':

                            ripe_abuse_emails.append(str(
                                attr['value']
                            ).strip())

                        elif attr['name'] == 'e-mail':

                            ripe_misc_emails.append(str(attr['value']).strip())

                        elif attr['name'] == 'address':

                            if net['address'] is not None:

                                net['address'] += '\n%s' % (
                                    str(attr['value']).strip()
                                )

                            else:

                                net['address'] = str(attr['value']).strip()

                elif n['type'] in ('person'):

                    for attr in n['attributes']['attribute']:

                        if attr['name'] in ('person'):

                            person['person'] = str(attr['value']).strip()

                        if attr['name'] in ('address'):

                            if person['address'] is not None:

                                person['address'] +=  '\n%s' % (str(attr['value']).strip())

                            else:

                                person['address'] = str(attr['value']).strip()

                        if attr['name'] in ('phone'):

                            person['phone'] = str(attr['value']).strip()

                        if attr['name'] in ('mnt-by'):

                            person['mnt-by'] = str(attr['value']).strip()

                        if attr['name'] in ('nic-hdl'):

                            person['nic-hdl'] = str(attr['value']).strip()

                        if attr['name'] in ('created'):

                            person['created'] = str(attr['value']).strip()

                        if attr['name'] in ('last-modified'):

                            person['last-modified'] = str(attr['value']).strip()

                        if attr['name'] in ('source'):

                            person['source'] = str(attr['value']).strip()

                elif n['type'] in ('inetnum', 'inet6num'):

                    for attr in n['attributes']['attribute']:

                        if attr['name'] in ('inetnum', 'inet6num'):

                            net['range'] = str(attr['value']).strip()
                            ipr = str(attr['value']).strip()
                            ip_range = ipr.split(' - ')

                            try:

                                if len(ip_range) > 1:

                                    addrs = []
                                    addrs.extend(
                                        summarize_address_range(
                                            ip_address(ip_range[0]),
                                            ip_address(ip_range[1])
                                        )
                                    )

                                    cidr = ', '.join(
                                        [i.__str__()
                                         for i in collapse_addresses(addrs)]
                                    )

                                else:

                                    cidr = ip_network(ip_range[0]).__str__()

                                net['cidr'] = cidr

                            except (ValueError, TypeError):

                                pass

                        elif attr['name'] == 'netname':

                            net['name'] = str(attr['value']).strip()

                        elif attr['name'] == 'nic-hdl':

                            net['handle'] = str(attr['value']).strip()

                        elif attr['name'] == 'descr':

                            if net['description'] is not None:

                                net['description'] += '\n%s' % (
                                    str(attr['value']).strip()
                                )

                            else:

                                net['description'] = str(attr['value']).strip()

                        elif attr['name'] == 'country':

                            net['country'] = str(attr['value']).strip().upper()

                        elif attr['name'] == 'created':

                            tmp = str(attr['value']).strip()

                            value = datetime.strptime(
                                tmp,
                                str(NIC_WHOIS['ripencc']['dt_rws_format'])
                            ).isoformat('T')

                            net['created'] = value

                        elif attr['name'] == 'last-modified':

                            tmp = str(attr['value']).strip()

                            value = datetime.strptime(
                                tmp,
                                str(NIC_WHOIS['ripencc']['dt_rws_format'])
                            ).isoformat('T')

                            net['updated'] = value

            except KeyError:

                pass

            # make sure to add all person records as long as they have data
            if person['nic-hdl'] is not None:
                persons.append(person)

        nets.append(net)

        # This is nasty. Since RIPE RWS doesn't provide a granular
        # contact to network relationship, we apply to all networks.
        if len(ripe_abuse_emails) > 0 or len(ripe_misc_emails) > 0:

            abuse = (
                '\n'.join(unique_everseen(ripe_abuse_emails))
                if len(ripe_abuse_emails) > 0 else None
            )
            misc = (
                '\n'.join(unique_everseen(ripe_misc_emails))
                if len(ripe_misc_emails) > 0 else None
            )

            for net in nets:

                net['abuse_emails'] = abuse
                net['misc_emails'] = misc

        return nets, persons

    def _lookup_rws_apnic(self, response=None):
        """
        The function for retrieving and parsing whois information for a APNIC
        IP address via HTTP (Whois-RWS).

        Args:
            response: The dictionary containing whois information to parse.

        Returns:
            List: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. Certain IPs
                have more granular network listings, hence the need for a list
                object.
        """

        addrs = []
        net = copy.deepcopy(BASE_NET)

        try:

            addrs.extend(summarize_address_range(
                ip_address(response['startAddress'].strip()),
                ip_address(response['endAddress'].strip())))

            net['cidr'] = ', '.join(
                [i.__str__() for i in collapse_addresses(addrs)]
            )

            net['range'] = (response['startAddress'].strip() + ' - ' +
                            response['endAddress'].strip())

        except (KeyError, ValueError, TypeError):

                pass

        try:

            net['country'] = str(response['country']).strip().upper()

        except KeyError:

            pass

        try:

            events = response['events']

            if not isinstance(events, list):

                events = [events]

        except KeyError:

            events = []

        for ev in events:

            try:

                if ev['eventAction'] == 'registration':

                    tmp = str(ev['eventDate']).strip()

                    value = datetime.strptime(
                        tmp,
                        str(NIC_WHOIS['apnic']['dt_rws_format'])
                    ).isoformat('T')

                    net['created'] = value

                elif ev['eventAction'] == 'last changed':

                    tmp = str(ev['eventDate']).strip()

                    value = datetime.strptime(
                        tmp,
                        str(NIC_WHOIS['apnic']['dt_rws_format'])
                    ).isoformat('T')

                    net['updated'] = value

            except (KeyError, ValueError):

                pass

        try:

            entities = response['entities']

            if not isinstance(entities, list):

                entities = [entities]

        except KeyError:

            entities = []

        for en in entities:

            try:

                if 'handle' in en:

                    net['handle'] = en['handle']

                temp = en['vcardArray'][1]

                for t in temp:

                    if 'administrative' in en['roles'] and t[0] == 'fn':

                        net['name'] = str(t[3]).strip()

                    elif 'administrative' in en['roles'] and t[0] == 'adr':

                        try:

                            net['address'] = str(t[1]['label']).strip()

                        except KeyError:

                            pass

                    elif t[0] == 'email':

                        key = None

                        if (len(en['roles']) > 1 or
                           en['roles'][0] == 'administrative'):

                            key = 'misc_emails'

                        elif en['roles'][0] == 'abuse':

                            key = 'abuse_emails'

                        elif en['roles'][0] == 'technical':

                            key = 'tech_emails'

                        if key is not None:

                            if net[key] is not None:

                                net[key] += '\n%s' % str(t[3]).strip()

                            else:

                                net[key] = str(t[3]).strip()

            except (KeyError, IndexError):

                pass

        try:

            remarks = response['remarks']

            if not isinstance(remarks, list):

                remarks = [remarks]

        except KeyError:

            remarks = []

        for rem in remarks:

            try:

                if rem['title'] == 'description':

                    net['description'] = str('\n'.join(rem['description']))

            except (KeyError, IndexError):

                pass

        return [net]

    def _lookup_rws_lacnic(self, response=None):
        """
        The function for retrieving and parsing whois information for a LACNIC
        IP address via HTTP (Whois-RWS).

        Args:
            response: The dictionary containing whois information to parse.

        Returns:
            List: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. Certain IPs
                have more granular network listings, hence the need for a list
                object.
        """

        addrs = []
        net = copy.deepcopy(BASE_NET)

        try:

            addrs.extend(summarize_address_range(
                ip_address(response['startAddress'].strip()),
                ip_address(response['endAddress'].strip())))

            net['cidr'] = ', '.join(
                [i.__str__() for i in collapse_addresses(addrs)]
            )

            net['range'] = (response['startAddress'].strip() + ' - ' +
                            response['endAddress'].strip())

        except (KeyError, ValueError, TypeError):

                pass

        try:

            net['country'] = str(response['country']).strip().upper()

        except KeyError:

            pass

        try:

            events = response['events']

            if not isinstance(events, list):

                events = [events]

        except KeyError:

            events = []

        for ev in events:

            try:

                if ev['eventAction'] == 'registration':

                    tmp = str(ev['eventDate']).strip()

                    value = datetime.strptime(
                        tmp,
                        str(NIC_WHOIS['lacnic']['dt_rws_format'])
                    ).isoformat('T')

                    net['created'] = value

                elif ev['eventAction'] == 'last changed':

                    tmp = str(ev['eventDate']).strip()

                    value = datetime.strptime(
                        tmp,
                        str(NIC_WHOIS['lacnic']['dt_rws_format'])
                    ).isoformat('T')

                    net['updated'] = value

            except (KeyError, ValueError):

                pass

        try:

            entities = response['entities']

            if not isinstance(entities, list):

                entities = [entities]

        except KeyError:

            entities = []

        for en in entities:

            try:

                if 'handle' in en:

                    net['handle'] = en['handle']

                if en['roles'][0] == 'registrant':

                    temp = en['vcardArray'][1]

                    for t in temp:

                        if t[0] == 'fn':

                            net['name'] = str(t[3]).strip()

                        elif t[0] == 'org':

                            net['description'] = str(t[3][0]).strip()

                        elif t[0] == 'adr':

                            net['address'] = str(t[1]['label']).strip()

                        elif t[0] == 'email':

                            net['misc_emails'] = str(t[3]).strip()

                elif en['roles'][0] == 'abuse':

                    temp = en['vcardArray'][1]

                    for t in temp:

                        if t[0] == 'email':

                            net['abuse_emails'] = str(t[3]).strip()

                elif en['roles'][0] == 'tech':

                    temp = en['vcardArray'][1]

                    for t in temp:

                        if t[0] == 'email':

                            net['tech_emails'] = str(t[3]).strip()

            except (KeyError, IndexError):

                pass

        return [net]

    def lookup_rws(self, inc_raw=False, retry_count=3):
        """
        The function for retrieving and parsing whois information for an IP
        address via HTTP (Whois-RWS).

        **This should be faster than IPWhois.lookup(), but may not be as
        reliable. AFRINIC does not have a Whois-RWS service yet. We have to
        rely on the Ripe RWS service, which does not contain all of the data
        we need. LACNIC RWS is in beta.**

        Args:
            inc_raw: Boolean for whether to include the raw whois results in
                the returned dictionary.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            Dictionary:

            :query: The IP address (String)
            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)
            :nets: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. (List)
            :raw: (Dictionary) - Whois results in Json format if the
                inc_raw parameter is True.
        """

        # Initialize the response.
        response = None

        # Attempt to resolve ASN info via Cymru. DNS is faster, try that first.
        try:

            asn_data = self.get_asn_dns()

        except (ASNLookupError, ASNRegistryError):

            try:

                asn_data = self.get_asn_whois(retry_count)

            except (ASNLookupError, ASNRegistryError):

                # Lets attempt to get the ASN registry information from ARIN.
                response = self.get_rws(
                    str(NIC_WHOIS['arin']['url']).format(self.address_str),
                    retry_count
                )

                asn_data = {
                    'asn_registry': None,
                    'asn': None,
                    'asn_cidr': None,
                    'asn_country_code': None,
                    'asn_date': None
                }

                try:

                    net_list = response['nets']['net']

                    if not isinstance(net_list, list):

                        net_list = [net_list]

                except KeyError:

                    net_list = []

                for n in net_list:

                    try:

                        if n['orgRef']['@handle'] in ('ARIN', 'VR-ARIN'):

                            asn_data['asn_registry'] = 'arin'

                        elif n['orgRef']['@handle'] == 'RIPE':

                            asn_data['asn_registry'] = 'ripencc'

                        else:

                            test = NIC_WHOIS[n['orgRef']['@handle'].lower()]
                            asn_data['asn_registry'] = (
                                n['orgRef']['@handle'].lower()
                            )

                    except KeyError:

                        raise ASNRegistryError('ASN registry lookup failed.')

                    break

        # Create the return dictionary.
        results = {
            'query': self.address_str,
            'nets': [],
            'raw': None
        }

        # Add the ASN information to the return dictionary.
        results.update(asn_data)

        # Only fetch the response if we haven't already.
        if response is None or results['asn_registry'] is not 'arin':

            # Retrieve the whois data.
            response = self.get_rws(
                str(NIC_WHOIS[results['asn_registry']]['url']).format(
                    self.address_str),
                retry_count
            )

        # If inc_raw parameter is True, add the response to return dictionary.
        if inc_raw:

            results['raw'] = response

        if results['asn_registry'] in ('ripencc', 'afrinic'):

            nets, persons = self._lookup_rws_ripe(response)

        elif results['asn_registry'] == 'arin':

            nets = self._lookup_rws_arin(response, retry_count)

        elif results['asn_registry'] == 'apnic':

            nets = self._lookup_rws_apnic(response)

        else:

            nets = self._lookup_rws_lacnic(response)

        # Add the networks to the return dictionary.
        results['nets'] = nets

        # Only add persons entry if there are entries.
        if persons:
            results['persons'] = persons

        return results
