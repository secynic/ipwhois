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

__version__ = '0.1.2'

import ipaddress, socket, urllib.request, dns.resolver, re
from xml.dom.minidom import parseString
from os import path

IETF_RFC_REFERENCES = {
                    #IPv4
                    "RFC 1122, Section 3.2.1.3": "http://tools.ietf.org/html/rfc1122#section-3.2.1.3",
                    "RFC 1918": "http://tools.ietf.org/html/rfc1918",
                    "RFC 3927": "http://tools.ietf.org/html/rfc3927",
                    "RFC 5736": "http://tools.ietf.org/html/rfc5736",
                    "RFC 5737": "http://tools.ietf.org/html/rfc5737",
                    "RFC 3068": "http://tools.ietf.org/html/rfc3068",
                    "RFC 2544": "http://tools.ietf.org/html/rfc2544",
                    "RFC 3171": "http://tools.ietf.org/html/rfc3171",
                    "RFC 919, Section 7": "http://tools.ietf.org/html/rfc919#section-7",
                    #IPv6
                    "RFC 4291, Section 2.7": "http://tools.ietf.org/html/rfc4291#section-2.7",
                    "RFC 4291": "http://tools.ietf.org/html/rfc4291",
                    "RFC 4291, Section 2.5.2": "http://tools.ietf.org/html/rfc4291#section-2.5.2",
                    "RFC 4291, Section 2.5.3": "http://tools.ietf.org/html/rfc4291#section-2.5.3",
                    "RFC 4291, Section 2.5.6": "http://tools.ietf.org/html/rfc4291#section-2.5.6",
                    "RFC 4291, Section 2.5.7": "http://tools.ietf.org/html/rfc4291#section-2.5.7",
                    "RFC 4193": "https://tools.ietf.org/html/rfc4193"
                     }

NIC_URLS = {
            "arin": "http://whois.arin.net/rest/nets;q={0}?showDetails=true&showARIN=true",
            "ripencc": "http://apps.db.ripe.net/whois/grs-search.xml?query-string={0}&source=ripe-grs", 
            "apnic": "http://apps.db.ripe.net/whois/grs-search.xml?query-string={0}&source=apnic-grs",
            "lacnic": "http://apps.db.ripe.net/whois/grs-search.xml?query-string={0}&source=lacnic-grs",
            "afrinic": "http://apps.db.ripe.net/whois/grs-search.xml?query-string={0}&source=afrinic-grs"
            }
    
NIC_WHOIS = {
            "arin": {
                     "server": "whois.arin.net",
                     "fields": {
                                "name": "^(NetName):[^\S\n]+(.+)$",
                                "description": "^(OrgName|CustName):[^\S\n]+(.+)$",
                                "country": "^(Country):[^\S\n]+(.+)$",
                                "state": "^(StateProv):[^\S\n]+(.+)$",
                                "city": "^(City):[^\S\n]+(.+)$"
                                }
                     },
            "ripencc": {
                     "server": "whois.ripe.net",
                     "fields": {
                                "name": "^(netname):[^\S\n]+(.+)$",
                                "description": "^(descr):[^\S\n]+(.+)$",
                                "country": "^(country):[^\S\n]+(.+)$"
                                }
                     },
            "apnic": {
                     "server": "whois.apnic.net",
                     "fields": {
                                "name": "^(netname):[^\S\n]+(.+)$",
                                "description": "^(descr):[^\S\n]+(.+)$",
                                "country": "^(country):[^\S\n]+(.+)$"
                                }
                     },
            "lacnic": {
                     "server": "whois.lacnic.net",
                     "fields": {
                                "description": "^(owner):[^\S\n]+(.+)$",
                                "country": "^(country):[^\S\n]+(.+)$"
                                }
                     },
            "afrinic": {
                     "server": "whois.afrinic.net",
                     "fields": {
                                "name": "^(netname):[^\S\n]+(.+)$",
                                "description": "^(descr):[^\S\n]+(.+)$",
                                "country": "^(country):[^\S\n]+(.+)$"
                                }
                     }
            }
    
CYMRU_WHOIS = "whois.cymru.com"

IPV4_DNS_ZONE = "{0}.origin.asn.cymru.com"

IPV6_DNS_ZONE = "{0}.origin6.asn.cymru.com"
     
def get_countries():
    """
    The function to generate a dictionary containing ISO_3166-1 country codes to names.
    """

    #Initialize the countries dictionary.
    countries = {}
    
    try:
        
        #Create the country codes file object.
        f = open(str(path.dirname(__file__)) + "/iso_3166-1_list_en.xml", "r")
        
        #Read the file.
        data = f.read()
        
        #Check if there is data.
        if not data:
            
            return {}
            
        #Parse the data to get the DOM.
        dom = parseString(data)
        
        #Retrieve the country entries.
        entries = dom.getElementsByTagName('ISO_3166-1_Entry')
        
        #Iterate through the entries and add to the countries dictionary.
        for entry in entries:
            
            #Retrieve the country code and name from the DOM.
            code = entry.getElementsByTagName('ISO_3166-1_Alpha-2_Code_element')[0].firstChild.data
            name = entry.getElementsByTagName('ISO_3166-1_Country_name')[0].firstChild.data
            
            #Add to the countries dictionary.
            countries[code] = name.title()
        
        return countries
    
    except:
        
        return {}


def ipv4_is_defined(address):
    """
    The function for checking if an IPv4 address is defined (does not need to be resolved).
    
    Args:
        address: An IPv4 address in string format.

    Returns:
        Tuple: Boolean - True if the given address is defined, otherwise False
               String - IETF assignment name if the given address is defined, otherwise ""
               String - IETF assignment RFC if the given address is defined, otherwise ""
    """
        
    #Initialize the IP address object.
    query_ip = ipaddress.IPv4Address(str(address))
    
    #This Network
    if query_ip in ipaddress.IPv4Network("0.0.0.0/8"):
        
        return True, "This Network", "RFC 1122, Section 3.2.1.3"
    
    #Private-Use Networks
    elif query_ip.is_private:
        
        return True, "Private-Use Networks", "RFC 1918"
    
    #Loopback
    elif query_ip.is_loopback:
        
        return True, "Loopback", "RFC 1122, Section 3.2.1.3"
    
    #Link Local
    elif query_ip.is_link_local:
        
        return True, "Link Local", "RFC 3927"
    
    #IETF Protocol Assignments
    elif query_ip in ipaddress.IPv4Network("192.0.0.0/24"):
        
        return True, "IETF Protocol Assignments", "RFC 5736"
    
    #TEST-NET-1
    elif query_ip in ipaddress.IPv4Network("192.0.2.0/24"):
        
        return True, "TEST-NET-1", "RFC 5737"
    
    #6to4 Relay Anycast
    elif query_ip in ipaddress.IPv4Network("192.88.99.0/24"):
        
        return True, "6to4 Relay Anycast", "RFC 3068"
    
    #Network Interconnect Device Benchmark Testing
    elif query_ip in ipaddress.IPv4Network("198.18.0.0/15"):
        
        return True, "Network Interconnect Device Benchmark Testing", "RFC 2544"
    
    #TEST-NET-2
    elif query_ip in ipaddress.IPv4Network("198.51.100.0/24"):
        
        return True, "TEST-NET-2", "RFC 5737"
    
    #TEST-NET-3
    elif query_ip in ipaddress.IPv4Network("203.0.113.0/24"):
        
        return True, "TEST-NET-3", "RFC 5737"
    
    #Multicast
    elif query_ip.is_multicast:
        
        return True, "Multicast", "RFC 3171"
    
    #Limited Broadcast
    elif query_ip in ipaddress.IPv4Network("255.255.255.255/32"):
        
        return True, "Limited Broadcast", "RFC 919, Section 7"
        
    return False, "", ""


def ipv6_is_defined(address):
    """
    The function for checking if an IPv6 address is defined (does not need to be resolved).
    
    Args:
        address: An IPv6 address in string format.

    Returns:
        Tuple: Boolean - True if the given address is defined, otherwise False
               String - IETF assignment name if the given address is defined, otherwise ""
               String - IETF assignment RFC if the given address is defined, otherwise ""
    """
    
    #Initialize the IP address object.
    query_ip = ipaddress.IPv6Address(str(address))
    
    #Multicast
    if query_ip.is_multicast:
        
        return True, "Multicast", "RFC 4291, Section 2.7"
    
    #Reserved
    elif query_ip.is_reserved:
        
        return True, "Reserved", "RFC 4291"
    
    #Unspecified
    elif query_ip.is_unspecified:
        
        return True, "Unspecified", "RFC 4291, Section 2.5.2"
    
    #Loopback.
    elif query_ip.is_loopback:
        
        return True, "Loopback", "RFC 4291, Section 2.5.3"
    
    #Link-Local
    elif query_ip.is_link_local:
        
        return True, "Link-Local", "RFC 4291, Section 2.5.6"
    
    #Site-Local
    elif query_ip.is_site_local:
        
        return True, "Site-Local", "RFC 4291, Section 2.5.7"
    
    #Unique Local Unicast
    elif query_ip.is_private:
        
        return True, "Unique Local Unicast", "RFC 4193"
      
    return False, "", ""

class IPDefinedError(Exception):
    """
    An Exception for when the IP is defined (does not need to be resolved).
    """
    
class ASNLookupError(Exception):
    """
    An Exception for when the ASN lookup failed.
    """
    
class IPWhois():
    """
    The class for performing ASN/whois lookups and parsing for IPv4 and IPv6 addresses.
    
    Args:
        address: An IPv4 or IPv6 address in string format.
    """
    
    def __init__(self, address):
        
        #IPv4Address or IPv6Address, use ipaddress package exception handling.
        self.address = ipaddress.ip_address(address)
        
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
            split = self.address_str.split(".")
            split.reverse()
            self.reversed = ".".join(split)
            
            self.dns_zone = IPV4_DNS_ZONE.format(self.reversed)
        
        else:
            
            #Check if no ASN/whois resolution needs to occur.
            is_defined = ipv6_is_defined(address)
            
            if is_defined[0]:
                
                raise IPDefinedError('IPv6 address %r is already defined as %r via %r.' % (self.address_str, is_defined[1], is_defined[2]))
            
            #Explode the IPv6Address to fill in any missing 0's.
            exploded = self.address.exploded
            
            #Cymru seems to timeout when the IPv6 address has trailing '0000' groups. Remove these groups.
            groups = exploded.split(":")
            for index,value in reversed(list(enumerate(groups))):
                
                if value == "0000":
                    
                    del groups[index]
                    
                else:
                    
                    break
            
            exploded = ":".join(groups)

            #Reverse the IPv6Address for the DNS ASN query.
            val = str(exploded).replace(":", "")
            val = val[::-1]
            self.reversed = ".".join(val)
            
            self.dns_zone = IPV6_DNS_ZONE.format(self.reversed)
    
    def lookup(self, inc_raw = False):
        """
        The function for retrieving and parsing whois information for an IP address via port 43 (WHOIS).
        
        Args:
            inc_raw: Boolean for whether to include the raw whois results in the returned dictionary.
    
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
        
        #First attempt to resolve ASN info via Cymru DNS (Faster).  
        try:
            
            for rdata in dns.resolver.query(self.dns_zone, "TXT"):
                
                #Attempt to parse out the ASN information.
                split = str(rdata).split("|")
                
                asn = split[0].strip(' "\n')
                asn_cidr = split[1].strip(" \n")
                asn_country_code = split[2].strip(" \n")
                asn_registry = split[3].strip(" \n")
                asn_date = split[4].strip(' "\n')
                
                break
        
        #DNS ASN info resolution failed, try via Cymru whois.
        #except (dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        except:
               
            try:
                
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.connect((CYMRU_WHOIS, 43))
                
                conn.send((" -r -a -c -p -f -o " + self.address_str + "\r\n").encode())
                
                rdata = ''
                while True:
                    
                    d = conn.recv(4096).decode()
                    rdata += d
                    
                    if not d:
                        
                        break
                    
                conn.close()
                
                #Attempt to parse out the ASN information.
                split = str(rdata).split("|")
    
                asn = split[0].strip(" \n")
                asn_cidr = split[2].strip(" \n")
                asn_country_code = split[3].strip(" \n")
                asn_registry = split[4].strip(" \n")
                asn_date = split[5].strip(" \n")
    
            except:
                
                raise ASNLookupError('ASN lookup failed for %r.' % self.address_str) 
        
        #Create the return dictionary.   
        results = {
                   "query": self.address_str,
                   "asn": asn,
                   "asn_date": asn_date,
                   "asn_registry": asn_registry,
                   "asn_cidr": asn_cidr,
                   "asn_country_code": asn_country_code,
                   "nets": [],
                   "raw": None
        }
        
        #Create the connection for the whois query.
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((NIC_WHOIS[asn_registry]["server"], 43))
        
        #Prep the query.
        query = self.address_str + "\r\n"
        if asn_registry == "arin":
            
            query = "n + " + query
        
        #Query the whois server, and store the results.  
        conn.send((query).encode())
        
        response = ''
        while True:
            
            if asn_registry == "lacnic":
                
                d = conn.recv(4096).decode("latin-1")
                
            else:
                
                d = conn.recv(4096).decode()
                
            response += d
            
            if not d:
                
                break
            
        conn.close()
        
        #If the inc_raw parameter is True, add the response to the return dictionary.
        if inc_raw:
            
            results["raw"] = response
        
        #Create the network dictionary template. The start and end fields will be removed in the final returned dictionary.
        base_net = {
              "cidr": None,
              "name": None,
              "description": None,
              "country": None,
              "state": None,
              "city": None,
              "start": None,
              "end": None
              }
        
        nets = []
        
        if asn_registry == "arin": 
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r"^CIDR:[^\S\n]+(.+?,[^\S\n].+|.+)$", response, re.MULTILINE):
                
                try:
                    
                    if "," in match.group(1):
                        
                        cidrs = match.group(1).split(", ")
                        
                        for c in cidrs:
                            
                            ipaddress.ip_network(c.strip())
                            
                        cidr = match.group(1).strip()
                        
                    else:
                        
                        cidr = ipaddress.ip_network(match.group(1).strip()).__str__()
                        
                    net = base_net.copy()
                    net["cidr"] = cidr
                    net["start"] = match.start()
                    net["end"] = match.end()
                    nets.append(net)
                    
                except:
                    
                    pass
        
        #Future fix: LACNIC has to be special and shorten inetnum field (no validity testing done for these).
        elif asn_registry == "lacnic":
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r"^(inetnum|inet6num):[^\S\n]+(.+?,[^\S\n].+|.+)$", response, re.MULTILINE):
                
                try:
                    
                    cidr = match.group(2).strip()
                        
                    net = base_net.copy()
                    net["cidr"] = cidr
                    net["start"] = match.start()
                    net["end"] = match.end()
                    nets.append(net)
                    
                except:
                    
                    pass

        else:
            
            #Iterate through all of the networks found, storing the CIDR value and the start and end positions.
            for match in re.finditer(r"^(inetnum|inet6num):[^\S\n]+((.+?)[^\S\n]-[^\S\n](.+)|.+)$", response, re.MULTILINE):
                
                try:
                    
                    addrs = []
                    if match.group(3) and match.group(4):
                        
                        addrs.extend(ipaddress.summarize_address_range(ipaddress.ip_address(match.group(3).strip()), ipaddress.ip_address(match.group(4).strip())))
                        
                        temp = []
                        for i in ipaddress.collapse_addresses(addrs):
                            
                            temp.append(i.__str__())
                            
                        cidr = ", ".join(temp)
                            
                    else:
                        
                        cidr = ipaddress.ip_network(match.group(2).strip()).__str__()
                        
                    net = base_net.copy()
                    net["cidr"] = cidr
                    net["start"] = match.start()
                    net["end"] = match.end()
                    nets.append(net)
                    
                except:
                    
                    pass
        
        #Iterate through all of the network sections and parse out the appropriate fields for each.
        for index, net in enumerate(nets):
                
            end = None
            if index + 1 < len(nets):
                
                end = nets[index + 1]["start"]
            
            for field in NIC_WHOIS[asn_registry]["fields"]:

                pattern = re.compile(r"" + NIC_WHOIS[asn_registry]["fields"][field], re.MULTILINE)
            
                if end:
                    
                    match = pattern.finditer(response, net["end"], end)
                    
                else:
                    
                    match = pattern.finditer(response, net["end"])
                
                value = ""
                sub_end = None
                for m in match:
                    
                    if sub_end:

                        if sub_end != (m.start()-1):
                            
                            break 
                        
                    if value != "":
                        
                        value += "\n"
                        
                    value += m.group(2).strip()
                    
                    sub_end = m.end()
                    
                if value != "":
                    
                    net[field] = value
            
            #The start and end values are no longer needed.
            del net["start"], net["end"]
        
        #Add the networks to the return dictionary.  
        results["nets"] = nets

        return results