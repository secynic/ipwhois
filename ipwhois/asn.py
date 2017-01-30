# Copyright (c) 2013-2017 Philip Hane
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

import re
import copy
import logging
from . import (NetError)

log = logging.getLogger(__name__)

BASE_NET = {
    'cidr': None,
    'description': None,
    'maintainer': None,
    'updated': None,
    'source': None
}

ASN_WHOIS = {
    'radb': {
        'server': 'whois.radb.net',
        'fields': {
            'description': r'(descr):[^\S\n]+(?P<val>.+?)\n',
            'maintainer': r'(mnt-by):[^\S\n]+(?P<val>.+?)\n',
            'updated': r'(changed):[^\S\n]+(?P<val>.+?)\n',
            'source': r'(source):[^\S\n]+(?P<val>.+?)\n',
        }
    },
}

ASN_HTTP = {
    'radb': {
        'url': 'http://www.radb.net/query/{0}',
        'fields': {
            'description': r'(descr):[^\S\n]+(?P<val>.+?)\n',
            'maintainer': r'(mnt-by):[^\S\n]+(?P<val>.+?)\n',
            'updated': r'(changed):[^\S\n]+(?P<val>.+?)\n',
            'source': r'(source):[^\S\n]+(?P<val>.+?)\n',
        }
    },
}


class ASNOrigin:
    """
    The class for parsing ASN origin whois data

    Args:
        net: A ipwhois.net.Net object.

    Raises:
        NetError: The parameter provided is not an instance of
            ipwhois.net.Net
    """

    def __init__(self, net):

        from .net import Net

        # ipwhois.net.Net validation
        if isinstance(net, Net):

            self._net = net

        else:

            raise NetError('The provided net parameter is not an instance of '
                           'ipwhois.net.Net')

    def _parse_fields(self, response, fields_dict, net_start=None,
                      net_end=None, field_list=None):
        """
        The function for parsing ASN whois fields from a data input.

        Args:
            response: The response from the whois/rwhois server.
            fields_dict: The dictionary of fields -> regex search values.
            net_start: The starting point of the network (if parsing multiple
                networks).
            net_end: The ending point of the network (if parsing multiple
                networks).
            field_list: If provided, a list of fields to parse:
                ['description', 'maintainer', 'updated', 'source']

        Returns:
            Dictionary: A dictionary of fields provided in fields_dict.
        """

        ret = {}

        if not field_list:

            field_list = ['description', 'maintainer', 'updated', 'source']

        generate = ((field, pattern) for (field, pattern) in
                    fields_dict.items() if field in field_list)

        for field, pattern in generate:

            pattern = re.compile(
                str(pattern),
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

                    if sub_section_end != (m.start() - 1):
                        break

                try:

                    values.append(m.group('val').strip())

                except IndexError:  # pragma: no cover

                    pass

                sub_section_end = m.end()

            if len(values) > 0:

                value = None
                try:

                    value = values[0]

                except ValueError as e:  # pragma: no cover

                    log.debug('ASN origin Whois field parsing failed for {0}: '
                              '{1}'.format(field, e))
                    pass

                ret[field] = value

        return ret

    def _get_nets_radb(self, response):
        """
        The function for parsing network blocks from ASN origin whois data.

        Args:
            response: The response from the RADB whois server.

        Returns:
            List: A of dictionaries containing keys: cidr, start, end.
        """

        nets = []

        # Iterate through all of the networks found, storing the CIDR value
        # and the start and end positions.
        for match in re.finditer(
                r'^route:[^\S\n]+(?P<val>.+|.+)$',
                response,
                re.MULTILINE
        ):

            try:

                net = copy.deepcopy(BASE_NET)
                net['cidr'] = match.group(1).strip()
                net['start'] = match.start()
                net['end'] = match.end()
                nets.append(net)

            except ValueError:  # pragma: no cover

                pass

        return nets

    def lookup(self, asn=None, inc_raw=False, retry_count=3, response=None,
               field_list=None):
        """
        The function for retrieving and parsing ASN origin whois information
        via port 43/tcp (WHOIS).

        Args:
            asn: The ASN string (required).
            inc_raw: Boolean for whether to include the raw results in the
                returned dictionary.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.
            response: Optional response object, this bypasses the Whois lookup.
            field_list: If provided, a list of fields to parse:
                ['description', 'maintainer', 'updated', 'source']

        Returns:
            Dictionary:

            :query: The Autonomous System Number (String)
            :nets: Dictionaries containing network information which consists
                of the fields listed in the ASN_WHOIS dictionary. (List)
            :raw: Raw ASN origin whois results if the inc_raw parameter is
                True. (String)
        """

        if asn[0:2] != 'AS':

            asn = 'AS{0}'.format(asn)

        # Create the return dictionary.
        results = {
            'query': asn,
            'nets': [],
            'raw': None
        }

        # Only fetch the response if we haven't already.
        if response is None:

            log.debug('Response not given, perform ASN origin WHOIS lookup '
                      'for {0}'
                      .format(asn))

            # Retrieve the whois data.
            response = self._net.get_asn_origin_whois(
                asn=asn, retry_count=retry_count
            )

        # If inc_raw parameter is True, add the response to return dictionary.
        if inc_raw:

            results['raw'] = response

        nets = []
        nets_response = self._get_nets_radb(response)

        nets.extend(nets_response)

        # Iterate through all of the network sections and parse out the
        # appropriate fields for each.
        log.debug('Parsing ASN origin WHOIS data')
        for index, net in enumerate(nets):

            section_end = None
            if index + 1 < len(nets):

                section_end = nets[index + 1]['start']

            temp_net = self._parse_fields(
                response,
                ASN_WHOIS['radb']['fields'],
                section_end,
                net['end'],
                field_list
            )

            # Merge the net dictionaries.
            net.update(temp_net)

            # The start and end values are no longer needed.
            del net['start'], net['end']

        # Add the networks to the return dictionary.
        results['nets'] = nets

        return results
