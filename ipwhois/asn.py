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
from .exceptions import (NetError, ASNRegistryError, ASNParseError,
                         ASNLookupError, HTTPLookupError)

log = logging.getLogger(__name__)

BASE_NET = {
    'cidr': None,
    'description': None,
    'maintainer': None,
    'updated': None,
    'source': None
}

ASN_ORIGIN_WHOIS = {
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

ASN_ORIGIN_HTTP = {
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


class IPASN:
    """
    The class for parsing ASN data for an IP address.

    Args:
        net: A ipwhois.net.Net object.

    Raises:
        NetError: The parameter provided is not an instance of
            ipwhois.net.Net
    """

    def __init__(self, net):

        from .net import (Net, ORG_MAP)
        from .whois import RIR_WHOIS

        # ipwhois.net.Net validation
        if isinstance(net, Net):

            self._net = net

        else:

            raise NetError('The provided net parameter is not an instance of '
                           'ipwhois.net.Net')

        self.org_map = ORG_MAP
        self.rir_whois = RIR_WHOIS

    def _parse_fields_dns(self, response):
        """
        The function for parsing ASN fields from a dns response.

        Args:
            response: The response from the ASN dns server.

        Returns:
            Dictionary:

            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNParseError: ASN parsing failed.
        """

        try:

            temp = response.split('|')

            # Parse out the ASN information.
            ret = {'asn_registry': temp[3].strip(' \n')}

            if ret['asn_registry'] not in self.rir_whois.keys():

                raise ASNRegistryError(
                    'ASN registry {0} is not known.'.format(
                        ret['asn_registry'])
                )

            ret['asn'] = temp[0].strip(' "\n')
            ret['asn_cidr'] = temp[1].strip(' \n')
            ret['asn_country_code'] = temp[2].strip(' \n').upper()
            ret['asn_date'] = temp[4].strip(' "\n')

        except ASNRegistryError:

            raise

        except Exception as e:

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return ret

    def _parse_fields_whois(self, response):
        """
        The function for parsing ASN fields from a whois response.

        Args:
            response: The response from the ASN whois server.

        Returns:
            Dictionary:

            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNParseError: ASN parsing failed.
        """

        try:

            temp = response.split('|')

            # Parse out the ASN information.
            ret = {'asn_registry': temp[4].strip(' \n')}

            if ret['asn_registry'] not in self.rir_whois.keys():

                raise ASNRegistryError(
                    'ASN registry {0} is not known.'.format(
                        ret['asn_registry'])
                )

            ret['asn'] = temp[0].strip(' \n')
            ret['asn_cidr'] = temp[2].strip(' \n')
            ret['asn_country_code'] = temp[3].strip(' \n').upper()
            ret['asn_date'] = temp[5].strip(' \n')

        except ASNRegistryError:

            raise

        except Exception as e:

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return ret

    def _parse_fields_http(self, response, extra_org_map=None):
        """
        The function for parsing ASN fields from a http response.

        Args:
            response: The response from the ASN http server.
            extra_org_map: Dictionary mapping org handles to RIRs. This is for
                limited cases where ARIN REST (ASN fallback HTTP lookup) does
                not show an RIR as the org handle e.g., DNIC (which is now the
                built in ORG_MAP) e.g., {'DNIC': 'arin'}. Valid RIR values are
                (note the case-sensitive - this is meant to match the REST
                result): 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'

        Returns:
            Dictionary:

            :asn: None, can't retrieve with this method.
            :asn_date: None, can't retrieve with this method.
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: None, can't retrieve with this method.
            :asn_country_code: None, can't retrieve with this method.

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNParseError: ASN parsing failed.
        """

        # Set the org_map. Map the orgRef handle to an RIR.
        org_map = self.org_map.copy()
        try:

            org_map.update(extra_org_map)

        except (TypeError, ValueError, IndexError, KeyError):

            pass

        try:

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

            except (KeyError, TypeError):

                log.debug('No networks found')
                net_list = []

            for n in net_list:

                try:

                    asn_data['asn_registry'] = (
                        org_map[n['orgRef']['@handle'].upper()]
                    )

                except KeyError as e:

                    log.debug('Could not parse ASN registry via HTTP: '
                              '{0}'.format(str(e)))
                    raise ASNRegistryError('ASN registry lookup failed.')

                break

        except ASNRegistryError:

            raise

        except Exception as e:  # pragma: no cover

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return asn_data

    def lookup(self, inc_raw=False, retry_count=3, asn_alts=None,
               extra_org_map=None):
        """
        The wrapper function for retrieving and parsing ASN information for an
        IP address.

        Args:
            inc_raw: Boolean for whether to include the raw results in the
                returned dictionary.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.
            asn_alts: Array of additional lookup types to attempt if the
                ASN dns lookup fails. Allow permutations must be enabled.
                Defaults to all ['whois', 'http'].
            extra_org_map: Dictionary mapping org handles to RIRs. This is for
                limited cases where ARIN REST (ASN fallback HTTP lookup) does
                not show an RIR as the org handle e.g., DNIC (which is now the
                built in ORG_MAP) e.g., {'DNIC': 'arin'}. Valid RIR values are
                (note the case-sensitive - this is meant to match the REST
                result): 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'

        Returns:
            Dictionary:

            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)
            :raw: Raw ASN results if the inc_raw parameter is True. (String)

        Raises:
            ASNRegistryError: ASN registry does not match.
            HTTPLookupError: The HTTP lookup failed.
        """

        lookups = asn_alts if asn_alts is not None else ['whois', 'http']

        # Attempt to resolve ASN info via Cymru. DNS is faster, try that first.
        try:

            self._net.dns_resolver.lifetime = (
                self._net.dns_resolver.timeout * (
                    retry_count and retry_count or 1
                )
            )
            response = self._net.get_asn_dns()
            asn_data = self._parse_fields_dns(response)

        except (ASNLookupError, ASNRegistryError) as e:

            if not self._net.allow_permutations:

                raise ASNRegistryError('ASN registry lookup failed. '
                                       'Permutations not allowed.')

            try:
                if 'whois' in lookups:

                    log.debug('ASN DNS lookup failed, trying ASN WHOIS: '
                              '{0}'.format(e))
                    response = self._net.get_asn_whois(retry_count)
                    asn_data = self._parse_fields_whois(response)

                else:

                    raise ASNLookupError

            except (ASNLookupError, ASNRegistryError):  # pragma: no cover

                if 'http' in lookups:

                    # Lets attempt to get the ASN registry information from
                    # ARIN.
                    log.debug('ASN WHOIS lookup failed, trying ASN via HTTP')
                    try:

                        response = self._net.get_asn_http(
                            retry_count=retry_count
                        )
                        asn_data = self._parse_fields_http(response,
                                                           extra_org_map)

                    except ASNRegistryError:

                        raise ASNRegistryError('ASN registry lookup failed.')

                    except ASNLookupError:

                        raise HTTPLookupError('ASN HTTP lookup failed.')

                else:

                    raise ASNRegistryError('ASN registry lookup failed.')

        if inc_raw:

            asn_data['raw'] = response

        return asn_data


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
                of the fields listed in the ASN_ORIGIN_WHOIS dictionary. (List)
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
                ASN_ORIGIN_WHOIS['radb']['fields'],
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
