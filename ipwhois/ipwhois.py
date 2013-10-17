# Copyright (c) 2013, Philip Hane
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import ipaddress, socket, dns.resolver, re, json
from .utils import ipv4_is_defined, ipv6_is_defined
from urllib import request
from time import sleep
from datetime import datetime

#Import the dnspython3 rdtypes to resolve the dynamic import problem when frozen to exe.
import dns.rdtypes.ANY.TXT

IETF_RFC_REFERENCES = {
                    #IPv4
                    'RFC 1122, Section 3.2.1.3': 'http://tools.ietf.org/html/rfc1122#section-3.2.1.3',
                    'RFC 1918': 'http://tools.ietf.org/html/rfc1918',
                    'RFC 3927': 'http://tools.ietf.org/html/rfc3927',
                    'RFC 5736': 'http://tools.ietf.org/html/rfc5736',
                    'RFC 5737': 'http://tools.ietf.org/html/rfc5737',
                    'RFC 3068': 'http://tools.ietf.org/html/rfc3068',
                    'RFC 2544': 'http://tools.ietf.org/html/rfc2544',
                    'RFC 3171': 'http://tools.ietf.org/html/rfc3171',
                    'RFC 919, Section 7': 'http://tools.ietf.org/html/rfc919#section-7',
                    #IPv6
                    'RFC 4291, Section 2.7': 'http://tools.ietf.org/html/rfc4291#section-2.7',
                    'RFC 4291': 'http://tools.ietf.org/html/rfc4291',
                    'RFC 4291, Section 2.5.2': 'http://tools.ietf.org/html/rfc4291#section-2.5.2',
                    'RFC 4291, Section 2.5.3': 'http://tools.ietf.org/html/rfc4291#section-2.5.3',
                    'RFC 4291, Section 2.5.6': 'http://tools.ietf.org/html/rfc4291#section-2.5.6',
                    'RFC 4291, Section 2.5.7': 'http://tools.ietf.org/html/rfc4291#section-2.5.7',
                    'RFC 4193': 'https://tools.ietf.org/html/rfc4193'
                     }
    
NIC_WHOIS = {
            'arin': {
                     'server': 'whois.arin.net',
                     'url': 'http://whois.arin.net/rest/nets;q={0}?showDetails=true&showARIN=true',
                     'fields': {
                                'name': '^(NetName):[^\S\n]+(?P<val>.+)$',
                                'description': '^(OrgName|CustName):[^\S\n]+(?P<val>.+)$',
                                'country': '^(Country):[^\S\n]+(?P<val>.+)$',
                                'state': '^(StateProv):[^\S\n]+(?P<val>.+)$',
                                'city': '^(City):[^\S\n]+(?P<val>.+)$',
                                'address': '^(Address):[^\S\n]+(?P<val>.+)$',
                                'postal_code': '^(PostalCode):[^\S\n]+(?P<val>.+)$',
                                'abuse_emails': '^(OrgAbuseEmail):[^\S\n]+(?P<val>.+)$',
                                'tech_emails': '^(OrgTechEmail):[^\S\n]+(?P<val>.+)$',
                                'created': '^(RegDate):[^\S\n]+(?P<val>.+)$',
                                'updated': '^(Updated):[^\S\n]+(?P<val>.+)$'
                                },
                     'dt_format': '%Y-%m-%d',
                     'dt_rws_format': '%Y-%m-%dT%H:%M:%S%z'
                     },
            'ripencc': {
                     'server': 'whois.ripe.net',
                     'url': 'http://apps.db.ripe.net/whois/grs-search?query-string={0}&source=ripe-grs', 
                     'fields': {
                                'name': '^(netname):[^\S\n]+(?P<val>.+)$',
                                'description': '^(descr):[^\S\n]+(?P<val>.+)$',
                                'country': '^(country):[^\S\n]+(?P<val>.+)$',
                                'address': '^(address):[^\S\n]+(?P<val>.+)$',
                                'abuse_emails': '^(abuse-mailbox:[^\S\n]+(?P<val>.+))|((?!abuse-mailbox).+?:.*[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*)$',
                                'misc_emails': '^(?!abuse-mailbox).+?:.*[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*$'
                                }
                     },
            'apnic': {
                     'server': 'whois.apnic.net',
                     'url': 'http://apps.db.ripe.net/whois/grs-search?query-string={0}&source=apnic-grs', 
                     'fields': {
                                'name': '^(netname):[^\S\n]+(?P<val>.+)$',
                                'description': '^(descr):[^\S\n]+(?P<val>.+)$',
                                'country': '^(country):[^\S\n]+(?P<val>.+)$',
                                'address': '^(address):[^\S\n]+(?P<val>.+)$',
                                'abuse_emails': '^(abuse-mailbox:[^\S\n]+(?P<val>.+))|((?!abuse-mailbox).+?:.*[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*)$',
                                'misc_emails': '^(?!abuse-mailbox).+?:.*[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*$',
                                'updated': '^(changed):[^\S\n]+.*?(?P<val>[0-9]{8})$'
                                },
                     'dt_format': '%Y%m%d'
                     },
            'lacnic': {
                     'server': 'whois.lacnic.net',
                     'url': 'http://apps.db.ripe.net/whois/grs-search?query-string={0}&source=lacnic-grs', 
                     'fields': {
                                'description': '^(owner):[^\S\n]+(?P<val>.+)$',
                                'country': '^(country):[^\S\n]+(?P<val>.+)$',
                                'abuse_emails': '^(abuse-mailbox:[^\S\n]+(?P<val>.+))|((?!abuse-mailbox).+?:.*[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*)$',
                                'misc_emails': '^(?!abuse-mailbox).+?:.*[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*$',
                                'created': '^(created):[^\S\n]+(?P<val>[0-9]{8}).*$',
                                'updated': '^(changed):[^\S\n]+(?P<val>[0-9]{8}).*$'
                                },
                     'dt_format': '%Y%m%d'
                     },
            'afrinic': {
                     'server': 'whois.afrinic.net',
                     'url': 'http://apps.db.ripe.net/whois/grs-search?query-string={0}&source=afrinic-grs', 
                     'fields': {
                                'name': '^(netname):[^\S\n]+(?P<val>.+)$',
                                'description': '^(descr):[^\S\n]+(?P<val>.+)$',
                                'country': '^(country):[^\S\n]+(?P<val>.+)$',
                                'address': '^(address):[^\S\n]+(?P<val>.+)$',
                                'abuse_emails': '^(abuse-mailbox:[^\S\n]+(?P<val>.+))|((?!abuse-mailbox).+?:.*[^\S\n]+(?P<val2>[\w\-\.]*abuse[\w\-\.]*@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*)$',
                                'misc_emails': '^(?!abuse-mailbox).+?:.*[^\S\n]+(?P<val>(?!abuse)[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)([^\S\n]+.*)*$'
                                }
                     }
            }
    
CYMRU_WHOIS = 'whois.cymru.com'

IPV4_DNS_ZONE = '{0}.origin.asn.cymru.com'

IPV6_DNS_ZONE = '{0}.origin6.asn.cymru.com'

class IPDefinedError(Exception):
    """
    An Exception for when the IP is defined (does not need to be resolved).
    """
    
class ASNLookupError(Exception):
    """
    An Exception for when the ASN lookup failed.
    """

class WhoisLookupError(Exception):
    """
    An Exception for when the Whois lookup failed.
    """
    
class HostLookupError(Exception):
    """
    An Exception for when the Host lookup failed.
    """
         
class IPWhois():
    """
    The class for performing ASN/whois lookups and parsing for IPv4 and IPv6 addresses.
    
    Args:
        address: An IPv4 or IPv6 address in string format.
        timeout: The default timeout for socket connections in seconds.
        proxy_opener: The urllib.request.OpenerDirector request for proxy support or None.
    """
    
    def __init__(self, address, timeout = 5, proxy_opener = None):
        
        #IPv4Address or IPv6Address, use ipaddress package exception handling.
        self.address = ipaddress.ip_address(address)
        
        #Default timeout for socket connections.
        self.timeout = timeout
        
        #Proxy opener.
        if isinstance(proxy_opener, request.OpenerDirector):
            
            self.opener = proxy_opener
            
        else:
            
            handler = request.ProxyHandler()
            self.opener = request.build_opener(handler)
            
        #IP address in string format for use in queries.
        self.address_str = self.address.__str__()
        
        #Determine the IP version, 4 or 6
        self.version = self.address.version
        
        if self.version == 4:
            
            #Check if no ASN/whois resolution needs to occur.
            is_defined = ipv4_is_defined(address)
            
            if is_defined[0]:
                
                raise IPDefinedError('IPv4 address %r is already defined as %r via %r.' % (self.address_str, is_defined[1], is_defined[2]))
                
            #Reverse the IPv4Address for the DNS ASN query.
            split = self.address_str.split('.')
            split.reverse()
            self.reversed = '.'.join(split)
            
            self.dns_zone = IPV4_DNS_ZONE.format(self.reversed)
        
        else:
            
            #Check if no ASN/whois resolution needs to occur.
            is_defined = ipv6_is_defined(address)
            
            if is_defined[0]:
                
                raise IPDefinedError('IPv6 address %r is already defined as %r via %r.' % (self.address_str, is_defined[1], is_defined[2]))
            
            #Explode the IPv6Address to fill in any missing 0's.
            exploded = self.address.exploded
            
            #Cymru seems to timeout when the IPv6 address has trailing '0000' groups. Remove these groups.
            groups = exploded.split(':')
            for index,value in reversed(list(enumerate(groups))):
                
                if value == '0000':
                    
                    del groups[index]
                    
                else:
                    
                    break
            
            exploded = ':'.join(groups)

            #Reverse the IPv6Address for the DNS ASN query.
            val = str(exploded).replace(':', '')
            val = val[::-1]
            self.reversed = '.'.join(val)
            
            self.dns_zone = IPV6_DNS_ZONE.format(self.reversed)
    
    def __repr__(self):
        
        return 'IPWhois(%r, %r, %r)' % (self.address_str, self.timeout, self.opener)
    
    def get_asn_dns(self):
        """
        The function for retrieving ASN information for an IP address from Cymru via port 53 (DNS).
        
        Returns:
            Dictionary: A dictionary containing the following keys:
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.
        """
        
        try:
            
            data = dns.resolver.query(self.dns_zone, 'TXT')
            
            #Parse out the ASN information.
            temp = str(data[0]).split('|')

            ret = {}
            
            ret['asn_registry'] = temp[3].strip(' \n')
            
            if ret['asn_registry'] not in NIC_WHOIS.keys():
                
                return None
            
            ret['asn'] = temp[0].strip(' "\n')
            ret['asn_cidr'] = temp[1].strip(' \n')
            ret['asn_country_code'] = temp[2].strip(' \n').upper()
            ret['asn_date'] = temp[4].strip(' "\n')
            
            return ret
        
        except:
            
            raise ASNLookupError('ASN lookup failed for %r.' % self.address_str) 
        
    def get_asn_whois(self, retry_count = 3):
        """
        The function for retrieving ASN information for an IP address from Cymru via port 43 (WHOIS).
        
        Args:
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            Dictionary: A dictionary containing the following keys:
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.
        """
        
        try:
            
            #Create the connection for the Cymru whois query.
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect((CYMRU_WHOIS, 43))
            
            #Query the Cymru whois server, and store the results.  
            conn.send((' -r -a -c -p -f -o %s%s' % (self.address_str, '\r\n')).encode())
            
            data = ''
            while True:
                
                d = conn.recv(4096).decode()
                data += d
                
                if not d:
                    
                    break
                
            conn.close()
            
            #Parse out the ASN information.
            temp = str(data).split('|')
            
            ret = {}
            
            ret['asn_registry'] = temp[4].strip(' \n')
            
            if ret['asn_registry'] not in NIC_WHOIS.keys():
                
                return None
            
            ret['asn'] = temp[0].strip(' \n')
            ret['asn_cidr'] = temp[2].strip(' \n')
            ret['asn_country_code'] = temp[3].strip(' \n').upper()
            ret['asn_date'] = temp[5].strip(' \n')
            
            return ret
        
        except (socket.timeout, socket.error):
            
            if retry_count > 0:
                
                return self.get_asn_whois(retry_count - 1)
            
            else:
                
                raise ASNLookupError('ASN lookup failed for %r.' % self.address_str) 
            
        except:

            raise ASNLookupError('ASN lookup failed for %r.' % self.address_str) 
        
    def get_whois(self, asn_registry = 'arin', retry_count = 3):
        """
        The function for retrieving whois information for an IP address via port 43 (WHOIS).
        
        Args:
            asn_registry: The NIC to run the query against.
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            String: The raw whois data.
        """
        
        try:
            
            #Create the connection for the whois query.
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(self.timeout)
            conn.connect((NIC_WHOIS[asn_registry]['server'], 43))
            
            #Prep the query.
            query = self.address_str + '\r\n'
            if asn_registry == 'arin':
                
                query = 'n + %s' % query
            
            #Query the whois server, and store the results.  
            conn.send((query).encode())
            
            response = ''
            while True:
                
                d = conn.recv(4096).decode('utf-8', 'ignore')
                    
                response += d
                
                if not d:
                    
                    break
                
            conn.close()
            
            if 'Query rate limit exceeded' in response:
                
                sleep(1)
                return self.get_whois(asn_registry, retry_count)
                
            return response
    
        except (socket.timeout, socket.error):
            
            if retry_count > 0:
                
                return self.get_whois(asn_registry, retry_count - 1)
            
            else:
                
                raise WhoisLookupError('Whois lookup failed for %r.' % self.address_str)
            
        except:

            raise WhoisLookupError('Whois lookup failed for %r.' % self.address_str)
        
    def get_rws(self, url = None, retry_count = 3):
        """
        The function for retrieving Whois-RWS information for an IP address via HTTP (Whois-RWS).
        
        Args:
            url: The URL to retrieve.
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            Dictionary: The whois data in Json format.
        """

        try:
            
            #Create the connection for the whois query.
            conn = request.Request(url, headers = {'Accept':'application/json'})
            data = self.opener.open(conn, timeout=self.timeout)
            d = json.loads(data.readall().decode())

            return d
    
        except (socket.timeout, socket.error):
            
            if retry_count > 0:
                
                return self.get_rws(url, retry_count - 1)
            
            else:
                
                raise WhoisLookupError('Whois RWS lookup failed for %r.' % url)
            
        except:

            raise WhoisLookupError('Whois RWS lookup failed for %r.' % url)
    
    def get_host(self, retry_count = 3):
        """
        The function for retrieving host information for an IP address.
        
        Args:
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            Tuple: hostname, aliaslist, ipaddrlist
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
                
                raise HostLookupError('Host lookup failed for %r.' % self.address_str)
            
        except:

            raise HostLookupError('Host lookup failed for %r.' % self.address_str)
        
    def lookup(self, inc_raw = False, retry_count = 3):
        """
        The function for retrieving and parsing whois information for an IP address via port 43 (WHOIS).
        
        Args:
            inc_raw: Boolean for whether to include the raw whois results in the returned dictionary.
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            Dictionary: A dictionary containing the following keys:
                    query (String) - The IP address.
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.
                    nets (List) - Dictionaries containing network information which consists of the fields 
                                listed in the NIC_WHOIS dictionary. Certain IPs have more granular network listings, 
                                hence the need for a list object.
                    raw (String) - Raw whois results if the inc_raw parameter is True.
        """
        
        #Attempt to resolve ASN info via Cymru. DNS is faster, so try that first.
        try:
            
            asn_data = self.get_asn_dns()
        
        except ASNLookupError:

            asn_data = self.get_asn_whois(retry_count)
        
        #Create the return dictionary.   
        results = {
                   'query': self.address_str,
                   'nets': [],
                   'raw': None
        }
        
        #Add the ASN information to the return dictionary.
        results.update(asn_data)
        
        #Retrieve the whois data.
        response = self.get_whois(results['asn_registry'], retry_count)
        
        #If the inc_raw parameter is True, add the response to the return dictionary.
        if inc_raw:
            
            results['raw'] = response
        
        #Create the network dictionary template. The start and end fields will be removed in the final returned dictionary.
        base_net = {
              'cidr': None,
              'name': None,
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
              'updated': None,
              'start': None,
              'end': None
              }
        
        nets = []
        
        if results['asn_registry'] == 'arin': 
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r'^CIDR:[^\S\n]+(.+?,[^\S\n].+|.+)$', response, re.MULTILINE):
                
                try:

                    net = base_net.copy()
                    net['cidr'] = ', '.join([ipaddress.ip_network(c.strip()).__str__() for c in match.group(1).split(', ')])
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)
                    
                except:
                    
                    pass
        
        elif results['asn_registry'] == 'lacnic':
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r'^(inetnum|inet6num):[^\S\n]+(.+?,[^\S\n].+|.+)$', response, re.MULTILINE):
                
                try:
                    
                    temp = []                    
                    for addr in match.group(2).strip().split(', '):
                        
                        count = addr.count('.')
                        if count is not 0 and count < 4:
                            
                            addr_split = addr.strip().split('/')
                            for i in range(count + 1, 4):
                                addr_split[0] += '.0'
                                
                            addr = '/'.join(addr_split)
                        
                        temp.append(ipaddress.ip_network(addr.strip()).__str__())
                        
                    net = base_net.copy()
                    net['cidr'] = ', '.join(temp)
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)
                    
                except:

                    pass

        else:
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r'^(inetnum|inet6num):[^\S\n]+((.+?)[^\S\n]-[^\S\n](.+)|.+)$', response, re.MULTILINE):
                
                try:
                    
                    if match.group(3) and match.group(4):
                        
                        addrs = []
                        addrs.extend(ipaddress.summarize_address_range(ipaddress.ip_address(match.group(3).strip()), ipaddress.ip_address(match.group(4).strip())))
                        
                        cidr = ', '.join([i.__str__() for i in ipaddress.collapse_addresses(addrs)])
                            
                    else:
                        
                        cidr = ipaddress.ip_network(match.group(2).strip()).__str__()
                        
                    net = base_net.copy()
                    net['cidr'] = cidr
                    net['start'] = match.start()
                    net['end'] = match.end()
                    nets.append(net)
                    
                except:
                    
                    pass
        
        #Iterate through all of the network sections and parse out the appropriate fields for each.
        for index, net in enumerate(nets):
                
            end = None
            if index + 1 < len(nets):
                
                end = nets[index + 1]['start']
            
            for field in NIC_WHOIS[results['asn_registry']]['fields']:

                pattern = re.compile(r'' + NIC_WHOIS[results['asn_registry']]['fields'][field], re.MULTILINE)
            
                if end:
                    
                    match = pattern.finditer(response, net['end'], end)
                    
                else:
                    
                    match = pattern.finditer(response, net['end'])
                
                values = []
                sub_end = None
                for m in match:
                    
                    if sub_end:

                        if field not in ('abuse_emails', 'tech_emails', 'misc_emails') and sub_end != (m.start()-1):
                            
                            break 
                        
                    try:
                        
                        values.append(m.group('val').strip())
                    
                    except:
                        
                        values.append(m.group('val2').strip())
                        
                    sub_end = m.end()
                    
                if len(values) > 0:
                    
                    try:
                        
                        if field == 'country':
                            
                            value = values[0].upper()
                            
                        elif field in ['created', 'updated']:

                            value = datetime.strptime(values[0], NIC_WHOIS[results['asn_registry']]['dt_format']).isoformat('T')
                            
                        else:
                            
                            values = list(set(values))
                            value = '\n'.join(values)
                            
                    except:
                        
                        value = None
                        pass
                        
                    net[field] = value
            
            #The start and end values are no longer needed.
            del net['start'], net['end']
        
        #Add the networks to the return dictionary.  
        results['nets'] = nets

        return results
    
    def lookup_rws(self, inc_raw = False, retry_count = 3):
        """
        The function for retrieving and parsing whois information for an IP address via HTTP (Whois-RWS).
        
        NOTE: This should be faster than IPWhois.lookup(), but may not be as reliable. APNIC, LACNIC, and AFRINIC
            do not have a Whois-RWS service yet. We have to rely on the Ripe RWS service, which does not contain all
            of the data we need.
            
        Args:
            inc_raw: Boolean for whether to include the raw whois results in the returned dictionary.
            retry_count: The number of times to retry in case socket errors, timeouts, connection resets, etc. are encountered.
    
        Returns:
            Dictionary: A dictionary containing the following keys:
                    query (String) - The IP address.
                    asn (String) - The Autonomous System Number.
                    asn_date (String) - The ASN Allocation date.
                    asn_registry (String) - The assigned ASN registry.
                    asn_cidr (String) - The assigned ASN CIDR.
                    asn_country_code (String) - The assigned ASN country code.
                    nets (List) - Dictionaries containing network information which consists of the fields 
                                listed in the NIC_WHOIS dictionary. Certain IPs have more granular network listings, 
                                hence the need for a list object.
                    raw (Dictionary) - Whois results in Json format if the inc_raw parameter is True.
        """
        
        #Attempt to resolve ASN info via Cymru. DNS is faster, so try that first.
        try:
            
            asn_data = self.get_asn_dns()
        
        except ASNLookupError:

            asn_data = self.get_asn_whois(retry_count)
        
        #Create the return dictionary.   
        results = {
                   'query': self.address_str,
                   'nets': [],
                   'raw': None
        }
        
        #Add the ASN information to the return dictionary.
        results.update(asn_data)
        
        #Retrieve the whois data.
        try:
            
            response = self.get_rws(NIC_WHOIS[results['asn_registry']]['url'].format(self.address_str), retry_count)
        
        #If the query failed, try the radb-grs source.
        except WhoisLookupError:
            
            response = self.get_rws('http://apps.db.ripe.net/whois/grs-search?query-string={0}&source=radb-grs'.format(self.address_str), retry_count)

        #If the inc_raw parameter is True, add the response to the return dictionary.
        if inc_raw:
            
            results['raw'] = response
        
        #Create the network dictionary template.
        base_net = {
              'cidr': None,
              'name': None,
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
        
        nets = []
        
        if results['asn_registry'] == 'arin': 
            
            try:
                
                net_list = response['nets']['net']
                
                if not isinstance(net_list, list):
                    
                    net_list = [net_list]
                                    
                for n in net_list:
                    
                    if 'orgRef' in n and n['orgRef']['@handle'] in ('ARIN', 'VR-ARIN'):
                        
                        continue
                            
                    addrs = []
                    addrs.extend(ipaddress.summarize_address_range(ipaddress.ip_address(n['startAddress']['$'].strip()), ipaddress.ip_address(n['endAddress']['$'].strip())))
                        
                    net = base_net.copy()
                    net['cidr'] = ', '.join([i.__str__() for i in ipaddress.collapse_addresses(addrs)])
                    
                    if 'registrationDate' in n:

                        net['created'] = n['registrationDate']['$'].strip()
                    
                    if 'updateDate' in n:
                        
                        net['updated'] = n['updateDate']['$'].strip()
                           
                    if 'name' in n:
                        
                        net['name'] = n['name']['$'].strip()
                    
                    ref = None
                    if 'customerRef' in n:
                        
                        ref = ['customerRef', 'customer']
                        
                    elif 'orgRef' in n:
                        
                        ref = ['orgRef', 'org']
                        
                    if ref is not None:
                        
                        net['description'] = n[ref[0]]['@name'].strip()
                        ref_url = n[ref[0]]['$'].strip() + '?showPocs=true'
                        
                        try:
                            
                            ref_response = self.get_rws(ref_url, retry_count)
                        
                        except WhoisLookupError:
                            
                            nets.append(net)
                            continue
                        
                        if 'streetAddress' in ref_response[ref[1]]:
                            
                            addr_list = ref_response[ref[1]]['streetAddress']['line']
            
                            if not isinstance(addr_list, list):
                                
                                addr_list = [addr_list]
                
                            net['address'] = '\n'.join([line['$'].strip() for line in addr_list])
                            
                        if 'postalCode' in ref_response[ref[1]]:
                            
                            net['postal_code'] = ref_response[ref[1]]['postalCode']['$']
                            
                        if 'city' in ref_response[ref[1]]:
                            
                            net['city'] = ref_response[ref[1]]['city']['$']
                            
                        if 'iso3166-1' in ref_response[ref[1]]:
                            
                            net['country'] = ref_response[ref[1]]['iso3166-1']['code2']['$']
                            
                        if 'iso3166-2' in ref_response[ref[1]]:
                            
                            net['state'] = ref_response[ref[1]]['iso3166-2']['$']
                            
                        if 'pocs' in ref_response[ref[1]]:
                            
                            for poc in ref_response[ref[1]]['pocs']['pocLinkRef']:
                            
                                if poc['@description'] in ('Abuse', 'Tech'):
                                    
                                    try:
                                        
                                        poc_url = poc['$']
                                        poc_response = self.get_rws(poc_url, retry_count)
                                        
                                        net['%s_emails' % poc['@description'].lower()] = poc_response['poc']['emails']['email']['$'].strip()

                                    except WhoisLookupError:
                                        
                                        pass
                                    
                    nets.append(net)
                    
            except:
                
                pass
            
        else:
            
            try:
                
                object_list = response['whois-resources']['objects']['object']
                
                if not isinstance(object_list, list):
                    
                    object_list = [object_list]
                
                ripe_abuse_emails = []
                ripe_misc_emails = []
                
                for n in object_list:

                    if n['type'] == 'organisation':
                        
                        for attr in n['attributes']['attribute']:
                            
                            if attr['name'] == 'abuse-mailbox':
                                
                                ripe_abuse_emails.append(attr['value'].strip())
                                
                            elif attr['name'] == 'e-mail':
                                
                                ripe_misc_emails.append(attr['value'].strip())
                            
                    if n['type'] in ('inetnum', 'inet6num', 'route', 'route6'):
                        
                        net = base_net.copy()
                        
                        for attr in n['attributes']['attribute']:
                            
                            if attr['name'] in ('inetnum', 'inet6num'):
                                
                                ipr = attr['value'].strip()
                                ip_range = ipr.split(' - ')
                                
                                try:
                                    
                                    if len(ip_range) > 1:
                                        
                                        addrs = []
                                        addrs.extend(ipaddress.summarize_address_range(ipaddress.ip_address(ip_range[0]), ipaddress.ip_address(ip_range[1])))
                                            
                                        cidr = ', '.join([i.__str__() for i in ipaddress.collapse_addresses(addrs)])
                                        
                                    else:
                                        
                                        cidr = ipaddress.ip_network(ip_range[0]).__str__()
                                    
                                    net['cidr'] = cidr
                                    
                                except:
                                    
                                    pass
                                
                            elif attr['name'] in ('route', 'route6'):
                                
                                ipr = attr['value'].strip()
                                ip_ranges = ipr.split(', ')
                                
                                try:

                                    net['cidr'] = ', '.join(ipaddress.ip_network(r).__str__() for r in ip_ranges)   
                                    
                                except:
                                    
                                    pass
                                
                            elif attr['name'] == 'netname':
                                
                                net['name'] = attr['value'].strip()
                            
                            elif attr['name'] == 'descr':
                                
                                if net['description']:
                                    
                                    net['description'] += '\n%s' % attr['value'].strip()
                                    
                                else:
                                    
                                    net['description'] = attr['value'].strip()
                                
                            elif attr['name'] == 'country':
                                
                                net['country'] = attr['value'].strip()
                                
                            elif attr['name'] == 'address':
                                
                                if net['address']:
                                    
                                    net['address'] += '\n%s' % attr['value'].strip()
                                    
                                else:
                                    
                                    net['address'] = attr['value'].strip()
                                
                        nets.append(net)
                
                #This is nasty. Since RIPE RWS doesn't provide a granular contact => network relationship, we apply to all networks.
                if len(ripe_abuse_emails) > 0 or len(ripe_misc_emails) > 0:
                    
                    abuse = '\n'.join(ripe_abuse_emails) if ripe_abuse_emails else None
                    misc = '\n'.join(ripe_misc_emails) if ripe_misc_emails else None
                    
                    for net in nets:
                        
                        net['abuse_emails'] = abuse
                        net['misc_emails'] = misc
                    
            except:
                
                pass
            
        #Add the networks to the return dictionary.  
        results['nets'] = nets

        return results