# -*- coding: UTF-8 -*-
"""
Created on 8/5/17-1:17 PM

@author: Ling Wang<lingwangneuraleng@gmail.com>

Demonstrate we can re-orgnize the ipwhois packages. The ASNOrigin class is not necessary at all. Several related functions should be moved out from Net class also.
The query commands follow RIPE style as described in https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-database-query-reference-manual

-i origin AS16276 -T route -K will only return ipv4
-i origin AS16276 -T route6 -K will only return ipv6
without -K the object contain lots of additional info
without -T it will return both v4 and v6

"""
# Original work Copyright (c) 2013-2017 Philip Hane
# Modifed work Copyright (c) 2017 Ling Wang
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


import socket
import logging
from time import sleep

import re

import copy
from .exceptions import (IPDefinedError, ASNLookupError, BlacklistError, WhoisLookupError, HTTPLookupError,
                                HostLookupError, HTTPRateLimitError, WhoisRateLimitError, ASNOriginLookupError)
from .asn import ASN_ORIGIN_WHOIS, BASE_NET, ASN_ORIGIN_HTTP

from ipwhois.debugutils import DEBUGV

try:  # pragma: no cover
    from urllib.request import (OpenerDirector,
                                ProxyHandler,
                                build_opener,
                                Request,
                                URLError,
                                HTTPError)
    from urllib.parse import urlencode
except ImportError:  # pragma: no cover
    from urllib2 import (OpenerDirector,
                         ProxyHandler,
                         build_opener,
                         Request,
                         URLError,
                         HTTPError)
    from urllib import urlencode

log = logging.getLogger(__name__)


def get_asn_origin_whois(asn_registry='radb', asn=None,
                         retry_count=3, server=None, port=43,
                         timeout = 5,
                         add_query_params =''
                         ):
    """The function for retrieving CIDR info for an ASN via whois.

    Args:
        asn_registry (:obj:`str`): The source to run the query against
            (asn.ASN_ORIGIN_WHOIS).
        asn (:obj:`str`): The AS number (required).
        retry_count (:obj:`int`): The number of times to retry in case
            socket errors, timeouts, connection resets, etc. are
            encountered. Defaults to 3.
        server (:obj:`str`): An optional server to connect to.
        port (:obj:`int`): The network port to connect on. Defaults to 43.
        timeout (:obj:`int`): The default timeout for socket connections in
            seconds. Defaults to 5.
        add_query_params (:obj:`str`, optional): additional RIPE query flags from ASN lookup
    Returns:
        str: The raw ASN origin whois data.
    Raises:
        WhoisLookupError: The ASN origin whois lookup failed.
        WhoisRateLimitError: The ASN origin Whois request rate limited and
            retries were exhausted.
    """

    try:

        if server is None:
            server = ASN_ORIGIN_WHOIS[asn_registry]['server']

        # Create the connection for the whois query.
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        log.debug('ASN origin WHOIS query for {0} at {1}:{2}, timeout = {3}'.format(
            asn, server, port, timeout))
        conn.connect((server, port))

        # Prep the query.
        query = ' {1} -i origin {0} {2}'.format(asn,
                                                add_query_params,
                                                '\r\n')

        log.debug('ANS query line: '+ query)
        # Query the whois server, and store the results.
        conn.send(query.encode())

        response = ''
        while True:

            d = conn.recv(4096).decode()

            response += d

            if not d:
                break

        conn.close()

        # TODO: this was taken from get_whois(). Need to test rate limiting
        if 'Query rate limit exceeded' in response:  # pragma: no cover

            if retry_count > 0:

                log.debug('ASN origin WHOIS query rate limit exceeded. '
                          'Waiting...')
                sleep(1)
                return get_asn_origin_whois(
                    asn_registry=asn_registry, asn=asn,
                    retry_count=retry_count - 1,
                    server=server, port=port,
                    timeout=timeout,
                    add_query_params=add_query_params
                )

            else:

                raise WhoisRateLimitError(
                    'ASN origin Whois lookup failed for {0}. Rate limit '
                    'exceeded, wait and try again (possibly a '
                    'temporary block).'.format(asn))

        elif ('error 501' in response or 'error 230' in response
              ):  # pragma: no cover

            log.debug('ASN origin WHOIS query error: {0}'.format(response))
            raise ValueError

        return str(response)

    except (socket.timeout, socket.error) as e:

        log.debug('ASN origin WHOIS query socket error: {0}'.format(e))
        if retry_count > 0:

            log.debug('ASN origin WHOIS query retrying (count: {0})'
                      ''.format(str(retry_count)))
            return get_asn_origin_whois(
                    asn_registry=asn_registry, asn=asn,
                    retry_count=retry_count - 1,
                    server=server, port=port,
                    timeout=timeout,
                    add_query_params=add_query_params
                )

        else:
            log.debug('0 retry')
            raise WhoisLookupError(
                'ASN origin WHOIS lookup failed for {0}.'.format(asn)
            )

    except WhoisRateLimitError:  # pragma: no cover

        raise

    except:  # pragma: no cover

        raise WhoisLookupError(
            'ASN origin WHOIS lookup failed for {0}.'.format(asn)
        )


def get_http_raw(url=None, retry_count=3, headers=None,
                 request_type='GET', form_data=None,
                 timeout = 5,
                 proxy_opener=None):
    """
    The function for retrieving a raw HTML result via HTTP.
    Args:
        url (:obj:`str`): The URL to retrieve (required).
        retry_count (:obj:`int`): The number of times to retry in case
            socket errors, timeouts, connection resets, etc. are
            encountered. Defaults to 3.
        headers (:obj:`dict`): The HTTP headers. The Accept header
            defaults to 'text/html'.
        request_type (:obj:`str`): Request type 'GET' or 'POST'. Defaults
            to 'GET'.
        form_data (:obj:`dict`): Optional form POST data.
        timeout (:obj:`int`): The default timeout for socket connections in
            seconds. Defaults to 5.
        proxy_opener (:obj:`OpenerDirector`): default to None and will create a new one inside the function.
    Returns:
        str: The raw data.
    Raises:
        HTTPLookupError: The HTTP lookup failed.
    """
    # Proxy opener.
    if isinstance(proxy_opener, OpenerDirector):

        opener = proxy_opener
    else:
        handler = ProxyHandler()
        opener = build_opener(handler)

    if headers is None:
        headers = {'Accept': 'text/html'}

    enc_form_data = None
    if form_data:
        enc_form_data = urlencode(form_data)
        try:
            # Py 2 inspection will alert on the encoding arg, no harm done.
            enc_form_data = bytes(enc_form_data, encoding='ascii')
        except TypeError as e:  # pragma: no cover
            log.debug(e, exc_info = True)

    try:

        # Create the connection for the HTTP query.
        log.debug('HTTP query at {}'.format(url))
        try:
            # Py 2 inspection alert bypassed by using kwargs dict.
            conn = Request(url=url, data=enc_form_data, headers=headers,
                           **{'method': request_type})
        except TypeError:  # pragma: no cover
            conn = Request(url=url, data=enc_form_data, headers=headers)
        data = opener.open(conn, timeout=timeout)

        try:
            d = data.readall().decode('ascii', 'ignore')
        except AttributeError:  # pragma: no cover
            d = data.read().decode('ascii', 'ignore')

        return str(d)

    except (URLError, socket.timeout, socket.error) as e:

        # Check needed for Python 2.6, also why URLError is caught.
        try:  # pragma: no cover
            if not isinstance(e.reason, (socket.timeout, socket.error)):
                raise HTTPLookupError('HTTP lookup failed for {0}.'
                                      ''.format(url))
        except AttributeError:  # pragma: no cover

            pass

        log.debug('HTTP query socket error: {0}'.format(e))
        if retry_count > 0:

            log.debug('HTTP query retrying (count: {0})'.format(
                str(retry_count)))

            return get_http_raw(
                url=url, retry_count=retry_count - 1, headers=headers,
                request_type=request_type, form_data=form_data,
                timeout=timeout,
                proxy_opener=opener
            )

        else:

            raise HTTPLookupError('HTTP lookup failed for {0}.'.format(
                url))

    except HTTPLookupError as e:  # pragma: no cover

        raise e

    except Exception:  # pragma: no cover


        raise HTTPLookupError('HTTP lookup failed for {0}.'.format(url))


def parse_fields(response, fields_dict, net_start=None,
                 net_end=None, field_list=None):
    """
    The function for parsing ASN whois fields from a data input.
    Args:
        response (:obj:`str`): The response from the whois/rwhois server.
        fields_dict (:obj:`dict`): Mapping of fields->regex search values.
        net_start (:obj:`int`): The starting point of the network (if
            parsing multiple networks). Defaults to None.
        net_end (:obj:`int`): The ending point of the network (if parsing
            multiple networks). Defaults to None.
        field_list (:obj:`list`): If provided, a list of fields to parse:
            ['description', 'maintainer', 'updated', 'source']
            If None, defaults to all fields.
    Returns:
        dict: A dictionary of fields provided in fields_dict.
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


def _parse_fields(*args, **kwargs):
    """
    Deprecated. This will be removed in a future release.
    """

    from warnings import warn
    warn('ASNOrigin._parse_fields() has been deprecated and will be '
         'removed. You should now use ASNOrigin.parse_fields().')
    return parse_fields(*args, **kwargs)

def get_nets_radb(response, is_http=False):
    """
    The function for parsing network blocks from ASN origin data.
    Args:
        response (:obj:`str`): The response from the RADB whois/http
            server.
        is_http (:obj:`bool`): If the query is RADB HTTP instead of whois,
            set to True. Defaults to False.
    Returns:
        list: A list of network block dictionaries
        ::
            [{
                'cidr' (str) - The assigned CIDR
                'start' (int) - The index for the start of the parsed
                    network block
                'end' (int) - The index for the end of the parsed network
                    block
            }]
    """
    log.debugv("response = \r\n '{}'".format(response))
    nets = []

    if is_http:
        regex = r'route(?:6)?:[^\S\n]+(?P<val>.+?)<br>'
    else:
        regex = r'^route(?:6)?:[^\S\n]+(?P<val>.+|.+)$'

    # Iterate through all of the networks found, storing the CIDR value
    # and the start and end positions.
    for match in re.finditer(
            regex,
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


def _get_nets_radb(*args, **kwargs):
    """
    Deprecated. This will be removed in a future release.
    """

    from warnings import warn
    warn('ASNOrigin._get_nets_radb() has been deprecated and will be '
         'removed. You should now use ASNOrigin.get_nets_radb().')
    return get_nets_radb(*args, **kwargs)


def lookup(asn=None, inc_raw=False, retry_count=3, response=None,
           field_list=None, asn_alts=None, asn_methods=None,
           asn_stop_after_success = True,
           timeout = 5,
           add_query_params='',
           proxy_opener = None
           ):
    """
    The function for retrieving and parsing ASN origin whois information
    via port 43/tcp (WHOIS).
    Args:
        asn (:obj:`str`): The ASN (required).
        inc_raw (:obj:`bool`): Whether to include the raw results in the
            returned dictionary. Defaults to False.
        retry_count (:obj:`int`): The number of times to retry in case
            socket errors, timeouts, connection resets, etc. are
            encountered. Defaults to 3.
        response (:obj:`str`): Optional response object, this bypasses the
            Whois lookup. Defaults to None.
        field_list (:obj:`list`): If provided, fields to parse:
            ['description', 'maintainer', 'updated', 'source']
            If None, defaults to all.
        asn_alts (:obj:`list`): Additional lookup types to attempt if the
            ASN whois lookup fails. If None, defaults to all ['http'].
            *WARNING* deprecated in favor of new argument asn_methods.
        asn_methods (:obj:`list`): ASN lookup types to attempt, in order.
            If None, defaults to all ['whois', 'http'].
        add_query_params (:obj:`str`, optional): additional RIPE query flags from ASN lookup
        proxy_opener (:obj:`OpenerDirector`): default to None and will create a new one inside the function.
    Returns:
        dict: The ASN origin lookup results
        ::
            {
                'query' (str) - The Autonomous System Number
                'nets' (list) - Dictionaries containing network
                    information which consists of the fields listed in the
                    ASN_ORIGIN_WHOIS dictionary.
                'raw' (str) - Raw ASN origin whois results if the inc_raw
                    parameter is True.
            }
    Raises:
        ValueError: methods argument requires one of whois, http.
        ASNOriginLookupError: ASN origin lookup failed.
    """

    if asn[0:2] != 'AS':

        asn = 'AS{0}'.format(asn)

    if asn_methods is None:

        if asn_alts is None:

            lookups = ['whois', 'http']

        else:

            from warnings import warn
            warn('ASNOrigin.lookup() asn_alts argument has been deprecated'
                 ' and will be removed. You should now use the asn_methods'
                 ' argument.')
            lookups = ['whois'] + asn_alts

    else:

        # Python 2.6 doesn't support set literal expressions, use explicit
        # set() instead.
        if set(['whois', 'http']).isdisjoint(asn_methods):

            raise ValueError('methods argument requires at least one of '
                             'whois, http.')

        lookups = asn_methods

    # Create the return dictionary.
    results = {
        'query': asn,
        'nets': [],
        'raw': None
    }

    is_http = False

    # Only fetch the response if we haven't already.
    if response is None:

        # for index, lookup_method in enumerate(lookups): index are not used at all
        for lookup_method in lookups:

            if lookup_method == 'whois':

                try:

                    log.debug('Response not given, perform ASN origin '
                              'WHOIS lookup for {0}'.format(asn))

                    # Retrieve the whois data.
                    response = get_asn_origin_whois(
                        asn=asn,
                        retry_count=retry_count,
                        timeout=timeout,
                        add_query_params=add_query_params
                    )

                except (WhoisLookupError, WhoisRateLimitError) as e:

                    log.debug('ASN origin WHOIS lookup failed: {0}'
                              ''.format(e))
                    pass

            elif lookup_method == 'http':

                try:

                    log.debug('Response not given, perform ASN origin '
                              'HTTP lookup for: {0}'.format(asn))

                    tmp = ASN_ORIGIN_HTTP['radb']['form_data']
                    tmp[str(ASN_ORIGIN_HTTP['radb']['form_data_asn_field']
                            )] = asn
                    response = get_http_raw(
                        url=ASN_ORIGIN_HTTP['radb']['url'],
                        retry_count=retry_count,
                        request_type='POST',
                        form_data=tmp,
                        timeout=timeout,
                        proxy_opener=proxy_opener
                    )
                    is_http = True   # pragma: no cover

                except HTTPLookupError as e:

                    log.debug('ASN origin HTTP lookup failed: {0}'
                              ''.format(e), exc_info = True)
                    pass

            if (not response is None) and asn_stop_after_success:
                # there is a valid response we should not try next asn method then
                break

        if response is None:

            raise ASNOriginLookupError('ASN origin lookup failed with no '
                                       'more methods to try.')

    # If inc_raw parameter is True, add the response to return dictionary.
    if inc_raw:

        results['raw'] = response

    nets = []
    nets_response = get_nets_radb(response, is_http)

    nets.extend(nets_response)

    if is_http:   # pragma: no cover
        fields = ASN_ORIGIN_HTTP
    else:
        fields = ASN_ORIGIN_WHOIS

    # Iterate through all of the network sections and parse out the
    # appropriate fields for each.
    log.debug('Parsing ASN origin data: len(nets) = {}'.format(len(nets)))

    for index, net in enumerate(nets):

        section_end = None
        if index + 1 < len(nets):

            section_end = nets[index + 1]['start']

        temp_net = parse_fields(
            response,
            fields['radb']['fields'],
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
