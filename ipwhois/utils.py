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
                           ip_network,
                           IPv4Address,
                           IPv4Network,
                           IPv6Address)
else:
    from ipaddr import (IPAddress as ip_address,
                        IPNetwork as ip_network,
                        IPv4Address,
                        IPv4Network,
                        IPv6Address)

from xml.dom.minidom import parseString
from os import path
import re
import copy
import io
import csv

try:
    from itertools import filterfalse

except ImportError:
    from itertools import ifilterfalse as filterfalse

IP_REGEX = (
    r'(?P<ip>'
    #IPv4
    '(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.)){3}'
    '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    #IPv6
    '|\[?(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:)'
    '{6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|'
    '2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]'
    '{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d'
    '\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|'
    '((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|'
    '2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]'
    '{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    '(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(('
    '(:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1'
    '\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(('
    '[0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4})'
    '{0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]'
    '?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:(('
    '25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})'
    ')|:)))(%.+)?))\]?'
    #Optional IPv4 Port
    '((:(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}'
    #Optional CIDR block
    '))|(\/(?:[012]\d?|3[012]?|[4-9])))?'
    ')'
)


def get_countries(is_legacy_xml=False):
    """
    The function to generate a dictionary containing ISO_3166-1 country codes
    to names.

    Args:
        is_legacy_xml: Boolean for whether to use the older country code
            list (iso_3166-1_list_en.xml).

    Returns:
        Dictionary: A dictionary with the country codes as the keys and the
            country names as the values.
    """

    #Initialize the countries dictionary.
    countries = {}

    #Set the data directory based on if the script is a frozen executable.
    if sys.platform == 'win32' and getattr(sys, 'frozen', False):

        data_dir = path.dirname(sys.executable)

    else:

        data_dir = path.dirname(__file__)

    if is_legacy_xml:

        #Create the country codes file object.
        f = io.open(str(data_dir) + '/data/iso_3166-1_list_en.xml', 'r',
                    encoding='ISO-8859-1')

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
            code = entry.getElementsByTagName(
                'ISO_3166-1_Alpha-2_Code_element')[0].firstChild.data
            name = entry.getElementsByTagName(
                'ISO_3166-1_Country_name')[0].firstChild.data

            #Add to the countries dictionary.
            countries[code] = name.title()

    else:

        #Create the country codes file object.
        f = io.open(str(data_dir) + '/data/iso_3166-1.csv', 'r',
                    encoding='utf-8')

        #Create csv reader object.
        csv_reader = csv.reader(f, delimiter=',', quotechar='"')

        #Iterate through the rows and add to the countries dictionary.
        for row in csv_reader:

            #Retrieve the country code and name columns.
            code = row[0]
            name = row[1]

            #Add to the countries dictionary.
            countries[code] = name

    return countries


def ipv4_is_defined(address):
    """
    The function for checking if an IPv4 address is defined (does not need to
    be resolved).

    Args:
        address: An IPv4 address in string format.

    Returns:
        Tuple:

        :Boolean: True if given address is defined, otherwise False
        :String: IETF assignment name if given address is defined, otherwise ''
        :String: IETF assignment RFC if given address is defined, otherwise ''
    """

    #Initialize the IP address object.
    query_ip = IPv4Address(str(address))

    #This Network
    if query_ip in IPv4Network('0.0.0.0/8'):

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
    elif query_ip in IPv4Network('192.0.0.0/24'):

        return True, 'IETF Protocol Assignments', 'RFC 5736'

    #TEST-NET-1
    elif query_ip in IPv4Network('192.0.2.0/24'):

        return True, 'TEST-NET-1', 'RFC 5737'

    #6to4 Relay Anycast
    elif query_ip in IPv4Network('192.88.99.0/24'):

        return True, '6to4 Relay Anycast', 'RFC 3068'

    #Network Interconnect Device Benchmark Testing
    elif query_ip in IPv4Network('198.18.0.0/15'):

        return (True,
                'Network Interconnect Device Benchmark Testing',
                'RFC 2544')

    #TEST-NET-2
    elif query_ip in IPv4Network('198.51.100.0/24'):

        return True, 'TEST-NET-2', 'RFC 5737'

    #TEST-NET-3
    elif query_ip in IPv4Network('203.0.113.0/24'):

        return True, 'TEST-NET-3', 'RFC 5737'

    #Multicast
    elif query_ip.is_multicast:

        return True, 'Multicast', 'RFC 3171'

    #Limited Broadcast
    elif query_ip in IPv4Network('255.255.255.255/32'):

        return True, 'Limited Broadcast', 'RFC 919, Section 7'

    return False, '', ''


def ipv6_is_defined(address):
    """
    The function for checking if an IPv6 address is defined (does not need to
    be resolved).

    Args:
        address: An IPv6 address in string format.

    Returns:
        Tuple:

        :Boolean: True if address is defined, otherwise False
        :String: IETF assignment name if address is defined, otherwise ''
        :String: IETF assignment RFC if address is defined, otherwise ''
    """

    #Initialize the IP address object.
    query_ip = IPv6Address(str(address))

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


def unique_everseen(iterable, key=None):
    """
    The generator to list unique elements, preserving the order. Remember all
    elements ever seen. This was taken from the itertools recipes.

    Args:
        iterable: An iterable to process.
        key: Optional function to run when checking elements (e.g., str.lower)

    Returns:
        Generator: Yields a generator object.
    """

    seen = set()
    seen_add = seen.add

    if key is None:

        for element in filterfalse(seen.__contains__, iterable):

            seen_add(element)
            yield element

    else:

        for element in iterable:

            k = key(element)

            if k not in seen:

                seen_add(k)
                yield element


def unique_addresses(data=None, file_path=None):
    """
    The function to search an input string and/or file, extracting and
    counting IPv4/IPv6 addresses/networks. Summarizes ports with sub-counts.
    If both a string and file_path are provided, it will process them both.

    Args:
        data: A string to process.
        file_path: An optional file path to process.

    Returns:
        Dictionary:

        :ip address/network: Each address or network found is a dictionary
            containing\:

            :count: Total number of times seen (Integer)
            :ports: Dictionary with port numbers as keys and the number of
                times seen for this ip as values (Dictionary)

    Raises:
        ValueError: Arguments provided are invalid.
    """

    if not data and not file_path:

        raise ValueError('No data or file path provided.')

    ret = {}
    base = {
        'count': 0,
        'ports': {}
    }

    file_data = None
    if file_path:

        f = open(str(file_path), 'r')

        #Read the file.
        file_data = f.read()

    pattern = re.compile(
        str(IP_REGEX),
        re.DOTALL
    )

    #Check if there is data.
    for input_data in [data, file_data]:

        if input_data:

            #Search for IPs.
            for match in pattern.finditer(input_data):

                is_net = False
                port = None
                try:

                    found = match.group('ip')

                    if '.' in found and ':' in found:

                        split = found.split(':')
                        ip_or_net = split[0]
                        port = split[1]

                    elif '[' in found:

                        split = found.split(']:')
                        ip_or_net = split[0][1:]
                        port = split[1]

                    elif '/' in found:

                        is_net = True
                        ip_or_net = found

                    else:

                        ip_or_net = found

                    if is_net:

                        ip_obj = ip_network(ip_or_net)

                    else:
                        ip_obj = ip_address(ip_or_net)

                    obj_str = ip_obj.__str__()

                    if obj_str not in ret.keys():

                        ret[obj_str] = copy.deepcopy(base)

                    ret[obj_str]['count'] += 1

                    if port:

                        try:

                            ret[obj_str]['ports'][str(port)] += 1

                        except KeyError:

                            ret[obj_str]['ports'][str(port)] = 1

                except (KeyError, ValueError):

                    continue

    return ret
