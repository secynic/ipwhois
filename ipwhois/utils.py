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

import ipaddress
from xml.dom.minidom import parseString
from os import path
                
def get_countries():
    """
    The function to generate a dictionary containing ISO_3166-1 country codes to names.
    
    Returns:
        Dictionary: A dictionary with the country codes as the keys and the country names as the values.
    """

    #Initialize the countries dictionary.
    countries = {}
    
    try:
        
        #Create the country codes file object.
        f = open(str(path.dirname(__file__)) + '/iso_3166-1_list_en.xml', 'r')
        
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
               String - IETF assignment name if the given address is defined, otherwise ''
               String - IETF assignment RFC if the given address is defined, otherwise ''
    """
        
    #Initialize the IP address object.
    query_ip = ipaddress.IPv4Address(str(address))
    
    #This Network
    if query_ip in ipaddress.IPv4Network('0.0.0.0/8'):
        
        return True, 'This Network', 'RFC 1122, Section 3.2.1.3'
    
    #Private-Use Networks
    elif query_ip.is_private:
        
        return True, 'Private-Use Networks', 'RFC 1918'
    
    #Loopback
    elif query_ip.is_loopback:
        
        return True, 'Loopback', 'RFC 1122, Section 3.2.1.3'
    
    #Link Local
    elif query_ip.is_link_local:
        
        return True, 'Link Local', 'RFC 3927'
    
    #IETF Protocol Assignments
    elif query_ip in ipaddress.IPv4Network('192.0.0.0/24'):
        
        return True, 'IETF Protocol Assignments', 'RFC 5736'
    
    #TEST-NET-1
    elif query_ip in ipaddress.IPv4Network('192.0.2.0/24'):
        
        return True, 'TEST-NET-1', 'RFC 5737'
    
    #6to4 Relay Anycast
    elif query_ip in ipaddress.IPv4Network('192.88.99.0/24'):
        
        return True, '6to4 Relay Anycast', 'RFC 3068'
    
    #Network Interconnect Device Benchmark Testing
    elif query_ip in ipaddress.IPv4Network('198.18.0.0/15'):
        
        return True, 'Network Interconnect Device Benchmark Testing', 'RFC 2544'
    
    #TEST-NET-2
    elif query_ip in ipaddress.IPv4Network('198.51.100.0/24'):
        
        return True, 'TEST-NET-2', 'RFC 5737'
    
    #TEST-NET-3
    elif query_ip in ipaddress.IPv4Network('203.0.113.0/24'):
        
        return True, 'TEST-NET-3', 'RFC 5737'
    
    #Multicast
    elif query_ip.is_multicast:
        
        return True, 'Multicast', 'RFC 3171'
    
    #Limited Broadcast
    elif query_ip in ipaddress.IPv4Network('255.255.255.255/32'):
        
        return True, 'Limited Broadcast', 'RFC 919, Section 7'
        
    return False, '', ''


def ipv6_is_defined(address):
    """
    The function for checking if an IPv6 address is defined (does not need to be resolved).
    
    Args:
        address: An IPv6 address in string format.

    Returns:
        Tuple: Boolean - True if the given address is defined, otherwise False
               String - IETF assignment name if the given address is defined, otherwise ''
               String - IETF assignment RFC if the given address is defined, otherwise ''
    """
    
    #Initialize the IP address object.
    query_ip = ipaddress.IPv6Address(str(address))
    
    #Multicast
    if query_ip.is_multicast:
        
        return True, 'Multicast', 'RFC 4291, Section 2.7'
    
    #Reserved
    elif query_ip.is_reserved:
        
        return True, 'Reserved', 'RFC 4291'
    
    #Unspecified
    elif query_ip.is_unspecified:
        
        return True, 'Unspecified', 'RFC 4291, Section 2.5.2'
    
    #Loopback.
    elif query_ip.is_loopback:
        
        return True, 'Loopback', 'RFC 4291, Section 2.5.3'
    
    #Link-Local
    elif query_ip.is_link_local:
        
        return True, 'Link-Local', 'RFC 4291, Section 2.5.6'
    
    #Site-Local
    elif query_ip.is_site_local:
        
        return True, 'Site-Local', 'RFC 4291, Section 2.5.7'
    
    #Unique Local Unicast
    elif query_ip.is_private:
        
        return True, 'Unique Local Unicast', 'RFC 4193'
      
    return False, '', ''