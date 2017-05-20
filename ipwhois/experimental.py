# Copyright (c) 2017 Philip Hane
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

import socket
import logging

from .exceptions import ASNLookupError
from .net import CYMRU_WHOIS

log = logging.getLogger(__name__)


def get_bulk_asn_whois(addresses=None, retry_count=3, timeout=120):
    """
    The function for retrieving ASN information for multiple IP addresses from
    Cymru via port 43/tcp (WHOIS).

    Args:
        addresses: List of IPv4 or IPv6 addresses in string format.
        retry_count: The number of times to retry in case socket errors,
            timeouts, connection resets, etc. are encountered.
        timeout: The default timeout for socket connections in seconds.

    Returns:
        String: The raw ASN bulk data, new line (\n) separated.

    Raises:
        ValueError: addresses argument must be a list of IPv4/v6 address 
            strings.
        ASNLookupError: The ASN bulk lookup failed.
    """

    if not isinstance(addresses, list):

        raise ValueError('addresses argument must be a list of IPv4/v6 '
                         'address strings.')

    try:

        # Create the connection for the Cymru whois query.
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        log.debug('ASN bulk query initiated.')
        conn.connect((CYMRU_WHOIS, 43))

        # Query the Cymru whois server, and store the results.
        conn.sendall((
            ' -r -a -c -p -f -o begin\n{0}\nend'.format(
                '\n'.join(addresses))
        ).encode())

        data = ''
        while True:

            d = conn.recv(4096).decode()
            data += d

            if not d:

                break

        conn.close()

        return str(data)

    except (socket.timeout, socket.error) as e:  # pragma: no cover

        log.debug('ASN bulk query socket error: {0}'.format(e))
        if retry_count > 0:

            log.debug('ASN bulk query retrying (count: {0})'.format(
                str(retry_count)))
            return get_bulk_asn_whois(addresses, retry_count - 1, timeout)

        else:

            raise ASNLookupError('ASN bulk lookup failed.')

    except:  # pragma: no cover

        raise ASNLookupError('ASN bulk lookup failed.')
