# Copyright (c) 2013, 2014 Philip Hane
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

try:
    from ipaddr import (IPAddress as ip_address,
                        IPNetwork as ip_network,
                        IPv4Address,
                        IPv4Network,
                        IPv6Address)

except ImportError:
    from ipaddress import (ip_address,
                           ip_network,
                           IPv4Address,
                           IPv4Network,
                           IPv6Address)

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

import socket
from .ipwhois import IPDefinedError
from .utils import ipv4_is_defined


class RepLookupError(Exception):
    """
    An Exception for when the IP reputation lookup failed.
    """


class IPRep():
    """
    The class for performing IPv4 address reputation lookups and parsing.

    Args:
        address: An IPv4 address in string format.
        timeout: The default timeout for socket connections in seconds.
        proxy_opener: The urllib.request.OpenerDirector request for proxy
            support or None.

    Raises:
        IPDefinedError: The address provided is defined (does not need to be
            resolved).
    """

    def __init__(self, address, timeout=5, proxy_opener=None):

        #IPv4Address, use ipaddress package exception handling.
        self.address = ip_address(address)

        #Default timeout for socket connections.
        self.timeout = timeout

        #Proxy opener.
        if isinstance(proxy_opener, OpenerDirector):

            self.opener = proxy_opener

        else:

            handler = ProxyHandler()
            self.opener = build_opener(handler)

        #IP address in string format for use in queries.
        self.address_str = self.address.__str__()

        #Check if address is defined, and no lookup is necessary.
        is_defined = ipv4_is_defined(address)

        if is_defined[0]:

            raise IPDefinedError(
                'IPv4 address %r is already defined as %r via '
                '%r.' % (
                    self.address_str, is_defined[1], is_defined[2]
                )
            )

    def get_ipvoid(self, retry_count=3):
        """
        The function to retrieve and parse ipvoid.com IP address reputation
        data.

        Args:
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.

        Returns:
            Dictionary: A dictionary with the reputation source as keys and the
                data as a dictionary of the following:
                    status: The reputation status.
                    url: The URL for reputation details.

        Raises:
            RepLookupError: The reputation lookup failed.
        """

        url = 'http://www.ipvoid.com/scan/{ip}'.format(ip=self.address_str)

        try:

            #Create the connection for the whois query.
            conn = Request(url)
            data = self.opener.open(conn, timeout=self.timeout)
            try:
                d = data.readall().decode()
            except AttributeError:
                d = data.read().decode('ascii', 'ignore')

            return d

        except (socket.timeout, socket.error):

            if retry_count > 0:

                return self.get_ipvoid(retry_count - 1)

            else:

                raise RepLookupError('IPVoid lookup failed for %r.' %
                                     self.address_str)

        except:

            raise RepLookupError('IPVoid lookup failed for %r.' %
                                 self.address_str)
