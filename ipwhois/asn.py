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
import sys
import copy
import logging

from .exceptions import (NetError, ASNRegistryError, ASNParseError,
                         ASNLookupError, HTTPLookupError, WhoisLookupError,
                         WhoisRateLimitError, ASNOriginLookupError)

if sys.version_info >= (3, 3):  # pragma: no cover
    from ipaddress import ip_network

else:  # pragma: no cover
    from ipaddr import IPNetwork as ip_network

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
        'url': 'http://www.radb.net/query/',
        'form_data_asn_field': 'keywords',
        'form_data': {
            'advanced_query': '1',
            'query': 'Query',
            '-T option': 'inet-rtr',
            'ip_option': '',
            '-i': '1',
            '-i option': 'origin'
        },
        'fields': {
            'description': r'(descr):[^\S\n]+(?P<val>.+?)\<br\>',
            'maintainer': r'(mnt-by):[^\S\n]+(?P<val>.+?)\<br\>',
            'updated': r'(changed):[^\S\n]+(?P<val>.+?)\<br\>',
            'source': r'(source):[^\S\n]+(?P<val>.+?)\<br\>',
        }
    },
}


class IPASN:
    """
    The class for parsing ASN data for an IP address.

    Args:
        net (:obj:`ipwhois.net.Net`): A ipwhois.net.Net object.

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

    def parse_fields_dns(self, response):
        """
        The function for parsing ASN fields from a dns response.

        Args:
            response (:obj:`str`): The response from the ASN dns server.

        Returns:
            dict: The ASN lookup results

            ::

                {
                    'asn' (str) - The Autonomous System Number
                    'asn_date' (str) - The ASN Allocation date
                    'asn_registry' (str) - The assigned ASN registry
                    'asn_cidr' (str) - The assigned ASN CIDR
                    'asn_country_code' (str) - The assigned ASN country code
                    'asn_description' (None) - Cannot retrieve with this
                        method.
                }

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
            ret['asn_description'] = None

        except ASNRegistryError:

            raise

        except Exception as e:

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return ret

    def _parse_fields_dns(self, *args, **kwargs):
        """
        Deprecated. This will be removed in a future release.
        """

        from warnings import warn
        warn('IPASN._parse_fields_dns() has been deprecated and will be '
             'removed. You should now use IPASN.parse_fields_dns().')
        return self.parse_fields_dns(*args, **kwargs)

    def parse_fields_verbose_dns(self, response):
        """
        The function for parsing ASN fields from a verbose dns response.

        Args:
            response (:obj:`str`): The response from the ASN dns server.

        Returns:
            dict: The ASN lookup results

            ::

                {
                    'asn' (str) - The Autonomous System Number
                    'asn_date' (str) - The ASN Allocation date
                    'asn_registry' (str) - The assigned ASN registry
                    'asn_cidr' (None) - Cannot retrieve with this method.
                    'asn_country_code' (str) - The assigned ASN country code
                    'asn_description' (str) - The ASN description
                }

        Raises:
            ASNRegistryError: The ASN registry is not known.
            ASNParseError: ASN parsing failed.
        """

        try:

            temp = response.split('|')

            # Parse out the ASN information.
            ret = {'asn_registry': temp[2].strip(' \n')}

            if ret['asn_registry'] not in self.rir_whois.keys():

                raise ASNRegistryError(
                    'ASN registry {0} is not known.'.format(
                        ret['asn_registry'])
                )

            ret['asn'] = temp[0].strip(' "\n')
            ret['asn_cidr'] = None
            ret['asn_country_code'] = temp[1].strip(' \n').upper()
            ret['asn_date'] = temp[3].strip(' \n')
            ret['asn_description'] = temp[4].strip(' "\n')

        except ASNRegistryError:

            raise

        except Exception as e:

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return ret

    def parse_fields_whois(self, response):
        """
        The function for parsing ASN fields from a whois response.

        Args:
            response (:obj:`str`): The response from the ASN whois server.

        Returns:
            dict: The ASN lookup results

            ::

                {
                    'asn' (str) - The Autonomous System Number
                    'asn_date' (str) - The ASN Allocation date
                    'asn_registry' (str) - The assigned ASN registry
                    'asn_cidr' (str) - The assigned ASN CIDR
                    'asn_country_code' (str) - The assigned ASN country code
                    'asn_description' (str) - The ASN description
                }

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
            ret['asn_description'] = temp[6].strip(' \n')

        except ASNRegistryError:

            raise

        except Exception as e:

            raise ASNParseError('Parsing failed for "{0}" with exception: {1}.'
                                ''.format(response, e)[:100])

        return ret

    def _parse_fields_whois(self, *args, **kwargs):
        """
        Deprecated. This will be removed in a future release.
        """

        from warnings import warn
        warn('IPASN._parse_fields_whois() has been deprecated and will be '
             'removed. You should now use IPASN.parse_fields_whois().')
        return self.parse_fields_whois(*args, **kwargs)

    def parse_fields_http(self, response, extra_org_map=None):
        """
        The function for parsing ASN fields from a http response.

        Args:
            response (:obj:`str`): The response from the ASN http server.
            extra_org_map (:obj:`dict`): Dictionary mapping org handles to
                RIRs. This is for limited cases where ARIN REST (ASN fallback
                HTTP lookup) does not show an RIR as the org handle e.g., DNIC
                (which is now the built in ORG_MAP) e.g., {'DNIC': 'arin'}.
                Valid RIR values are (note the case-sensitive - this is meant
                to match the REST result): 'ARIN', 'RIPE', 'apnic', 'lacnic',
                'afrinic'. Defaults to None.

        Returns:
            dict: The ASN lookup results

            ::

                {
                    'asn' (None) - Cannot retrieve with this method.
                    'asn_date' (None) - Cannot retrieve with this method.
                    'asn_registry' (str) - The assigned ASN registry
                    'asn_cidr' (None) - Cannot retrieve with this method.
                    'asn_country_code' (None) - Cannot retrieve with this
                        method.
                    'asn_description' (None) - Cannot retrieve with this
                        method.
                }

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
                'asn_date': None,
                'asn_description': None
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

    def _parse_fields_http(self, *args, **kwargs):
        """
        Deprecated. This will be removed in a future release.
        """

        from warnings import warn
        warn('IPASN._parse_fields_http() has been deprecated and will be '
             'removed. You should now use IPASN.parse_fields_http().')
        return self.parse_fields_http(*args, **kwargs)

    def lookup(self, inc_raw=False, retry_count=3, asn_alts=None,
               extra_org_map=None, asn_methods=None,
               get_asn_description=True):
        """
        The wrapper function for retrieving and parsing ASN information for an
        IP address.

        Args:
            inc_raw (:obj:`bool`): Whether to include the raw results in the
                returned dictionary. Defaults to False.
            retry_count (:obj:`int`): The number of times to retry in case
                socket errors, timeouts, connection resets, etc. are
                encountered. Defaults to 3.
            asn_alts (:obj:`list`): Additional lookup types to attempt if the
                ASN dns lookup fails. Allow permutations must be enabled.
                Defaults to all ['whois', 'http']. *WARNING* deprecated in
                favor of new argument asn_methods. Defaults to None.
            extra_org_map (:obj:`dict`): Mapping org handles to RIRs. This is
                for limited cases where ARIN REST (ASN fallback HTTP lookup)
                does not show an RIR as the org handle e.g., DNIC (which is
                now the built in ORG_MAP) e.g., {'DNIC': 'arin'}. Valid RIR
                values are (note the case-sensitive - this is meant to match
                the REST result): 'ARIN', 'RIPE', 'apnic', 'lacnic', 'afrinic'
                Defaults to None.
            asn_methods (:obj:`list`): ASN lookup types to attempt, in order.
                If None, defaults to all: ['dns', 'whois', 'http'].
            get_asn_description (:obj:`bool`): Whether to run an additional
                query when pulling ASN information via dns, in order to get
                the ASN description. Defaults to True.

        Returns:
            dict: The ASN lookup results

            ::

                {
                    'asn' (str) - The Autonomous System Number
                    'asn_date' (str) - The ASN Allocation date
                    'asn_registry' (str) - The assigned ASN registry
                    'asn_cidr' (str) - The assigned ASN CIDR
                    'asn_country_code' (str) - The assigned ASN country code
                    'asn_description' (str) - The ASN description
                    'raw' (str) - Raw ASN results if the inc_raw parameter is
                        True.
                }

        Raises:
            ValueError: methods argument requires one of dns, whois, http.
            ASNRegistryError: ASN registry does not match.
        """

        if asn_methods is None:

            if asn_alts is None:

                lookups = ['dns', 'whois', 'http']

            else:

                from warnings import warn
                warn('IPASN.lookup() asn_alts argument has been deprecated '
                     'and will be removed. You should now use the asn_methods '
                     'argument.')
                lookups = ['dns'] + asn_alts

        else:

            # Python 2.6 doesn't support set literal expressions, use explicit
            # set() instead.
            if set(['dns', 'whois', 'http']).isdisjoint(asn_methods):

                raise ValueError('methods argument requires at least one of '
                                 'dns, whois, http.')

            lookups = asn_methods

        response = None
        asn_data = None
        dns_success = False
        for index, lookup_method in enumerate(lookups):

            if index > 0 and not asn_methods and not (
                    self._net.allow_permutations):

                raise ASNRegistryError('ASN registry lookup failed. '
                                       'Permutations not allowed.')

            if lookup_method == 'dns':

                try:

                    self._net.dns_resolver.lifetime = (
                        self._net.dns_resolver.timeout * (
                            retry_count and retry_count or 1
                        )
                    )
                    response = self._net.get_asn_dns()
                    asn_data_list = []
                    for asn_entry in response:

                        asn_data_list.append(self._parse_fields_dns(
                            str(asn_entry)))

                    # Iterate through the parsed ASN results to find the
                    # smallest CIDR
                    asn_data = asn_data_list.pop(0)
                    try:

                        prefix_len = ip_network(asn_data['asn_cidr']).prefixlen
                        for asn_parsed in asn_data_list:
                            prefix_len_comp = ip_network(
                                asn_parsed['asn_cidr']).prefixlen
                            if prefix_len_comp > prefix_len:
                                asn_data = asn_parsed
                                prefix_len = prefix_len_comp

                    except (KeyError, ValueError):  # pragma: no cover

                        pass

                    dns_success = True
                    break

                except (ASNLookupError, ASNRegistryError) as e:

                    log.debug('ASN DNS lookup failed: {0}'.format(e))
                    pass

            elif lookup_method == 'whois':

                try:

                    response = self._net.get_asn_whois(retry_count)
                    asn_data = self._parse_fields_whois(
                        response)  # pragma: no cover
                    break

                except (ASNLookupError, ASNRegistryError) as e:

                    log.debug('ASN WHOIS lookup failed: {0}'.format(e))
                    pass

            elif lookup_method == 'http':

                try:

                    response = self._net.get_asn_http(
                        retry_count=retry_count
                    )
                    asn_data = self._parse_fields_http(response,
                                                       extra_org_map)
                    break

                except (ASNLookupError, ASNRegistryError) as e:

                    log.debug('ASN HTTP lookup failed: {0}'.format(e))
                    pass

        if asn_data is None:

            raise ASNRegistryError('ASN lookup failed with no more methods to '
                                   'try.')

        if get_asn_description and dns_success:

            try:

                response = self._net.get_asn_verbose_dns('AS{0}'.format(
                    asn_data['asn']))
                asn_verbose_data = self.parse_fields_verbose_dns(response)
                asn_data['asn_description'] = asn_verbose_data[
                    'asn_description']

            except (ASNLookupError, ASNRegistryError) as e:  # pragma: no cover

                log.debug('ASN DNS verbose lookup failed: {0}'.format(e))
                pass

        if inc_raw:

            asn_data['raw'] = response

        return asn_data


import ipwhois.ASNOrigin as _asnorigin

def ASNOrigin(*args):
    import warnings
    warnings.warn("asn.ASNOrigin() has been deprecated and will be removed. The timeout value stored in Net object is not in use!!! You should now use ASNOrigin module instead.")
    return _asnorigin
