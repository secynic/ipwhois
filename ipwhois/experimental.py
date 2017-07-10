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
import time

from .exceptions import (ASNLookupError, HTTPLookupError, HTTPRateLimitError,
                         ASNRegistryError)
from .asn import IPASN
from .net import (CYMRU_WHOIS, Net)
from .rdap import RDAP
from .utils import unique_everseen

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
        String: The raw ASN bulk data, new line separated.

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
            ' -r -a -c -p -f begin\n{0}\nend'.format(
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


def bulk_lookup_rdap(addresses=None, inc_raw=False, retry_count=3, depth=0,
                     excluded_entities=None, rate_limit_timeout=60,
                     socket_timeout=10, asn_timeout=240):
    """
    The function for bulk retrieving and parsing whois information for a list
    of IP addresses via HTTP (RDAP). This bulk lookup method uses bulk
    ASN Whois lookups first to retrieve the ASN for each IP. It then optimizes
    RDAP queries to achieve the fastest overall time, accounting for
    rate-limiting RIRs.

    Args:
        addresses: A list of IP addresse strings to lookup.
        inc_raw: Boolean for whether to include the raw whois results in
            the returned dictionary.
        retry_count: The number of times to retry in case socket errors,
            timeouts, connection resets, etc. are encountered.
        depth: How many levels deep to run queries when additional
            referenced objects are found.
        excluded_entities: A list of entity handles to not perform lookups.
        rate_limit_timeout: The number of seconds to wait before retrying
            when a rate limit notice is returned via rdap+json.
        socket_timeout: The default timeout for socket connections in seconds.
        asn_timeout: The default timeout for bulk ASN lookups in seconds.

    Returns:
        Tuple:

        :Dictionary: A dictionary of the IP addresses as keys with the values
            as dictionaries returned by IPWhois.lookup_rdap().
        :List: A list of IP addresses that failed to lookup.
        :List: A list of IP addresses that were rate-limited at least once.
        :Integer: The number of IP addresses that lookups were originally
            requested for (addresses), excluding duplicates.
        :Integer: The number of IP addresses that lookups were attempted for,
            excluding any that failed ASN registry checks.
        :Dictionary: A dictionary of RIR keys to the number of addresses
            looked up for each, determined as a result of ASN lookups.

    Raises:
        ASNLookupError: The ASN bulk lookup failed, cannot proceed with bulk
            RDAP lookup.
    """

    if not isinstance(addresses, list):

        raise ValueError('addresses must be a list of IP address strings')

    # Initialize the dicts/lists
    results = {}
    failed_lookups_dict = {}
    rated_lookups = []
    rir_stats = {
        'lacnic': 0,
        'ripencc': 0,
        'apnic': 0,
        'afrinic': 0,
        'arin': 0
    }
    asn_parsed_results = {}

    # Make sure addresses is unique
    unique_ip_list = list(unique_everseen(addresses))

    # Get the unique count to return
    ip_unique_total = len(unique_ip_list)

    # This is needed for iteration order
    rir_keys_ordered = ['lacnic', 'ripencc', 'apnic', 'afrinic', 'arin']

    # First query the ASN data for all IPs, can raise ASNLookupError, no catch
    bulk_asn = get_bulk_asn_whois(unique_ip_list, timeout=asn_timeout)

    # ASN results are returned as string, parse lines to list and remove first
    asn_result_list = bulk_asn.split('\n')
    del asn_result_list[0]

    # We need to instantiate IPASN, which currently needs a Net object,
    # IP doesn't matter here
    net = Net('1.2.3.4')
    ipasn = IPASN(net)

    # Iterate each IP ASN result, and add valid RIR results to
    # asn_parsed_results for RDAP lookups
    for asn_result in asn_result_list:

        temp = asn_result.split('|')

        # Not a valid entry, move on to next
        if len(temp) == 1:

            continue

        ip = temp[1].strip()

        # We need this since ASN bulk lookup is returning duplicates
        # This is an issue on the Cymru end
        if ip in asn_parsed_results.keys():  # pragma: no cover

            continue

        try:

            results = ipasn._parse_fields_whois(asn_result)

        except ASNRegistryError:  # pragma: no cover

            continue

        # Add valid IP ASN result to asn_parsed_results for RDAP lookup
        asn_parsed_results[ip] = results
        rir_stats[results['asn_registry']] += 1

    # Set the total lookup count after unique IP and ASN result filtering
    ip_lookup_total = len(asn_parsed_results)

    # Track the total number of LACNIC queries left. This is tracked in order
    # to ensure the 9 priority LACNIC queries/min don't go into infinite loop
    lacnic_total_left = rir_stats['lacnic']

    # Initialize the LACNIC query count for tracking number of LACNIC queries
    # since the last rate limit time reset via old_time
    lacnic_count = 0

    # Set the start time, this value is updated when the rate limit is reset
    old_time = time.time()

    # TODO: Rate limit tracking dict for all RIRs
    rate_tracker = {
        'lacnic': {'time': old_time, 'count': 0},
        'ripencc': {'time': old_time, 'count': 0},
        'apnic': {'time': old_time, 'count': 0},
        'afrinic': {'time': old_time, 'count': 0},
        'arin': {'time': old_time, 'count': 0}
    }

    # Iterate all of the IPs to perform RDAP lookups until none are left
    while len(asn_parsed_results) > 0:

        # Sequentially run through each RIR to minimize lookups in a row to
        # the same RIR.
        for rir in rir_keys_ordered:

            # If there are still LACNIC IPs left to lookup and the rate limit
            # hasn't been reached, skip to find a LACNIC IP to lookup
            if (
                rir != 'lacnic' and lacnic_total_left > 0 and
                (lacnic_count != 9 or
                    (time.time() - old_time) >= rate_limit_timeout
                 )
               ):  # pragma: no cover

                continue

            # If this IP is LACNIC, run some checks
            if rir == 'lacnic' and lacnic_total_left > 0:

                # If the LACNIC rate limit has been reached and hasn't expired,
                # move on to the next non-LACNIC IP
                if (
                    lacnic_count == 9 and (
                        (time.time() - old_time) < rate_limit_timeout)
                   ):  # pragma: no cover

                    continue

                # If the LACNIC rate limit has expired, reset the count/timer
                # and perform the lookup
                elif ((time.time() - old_time) >= rate_limit_timeout
                      ):  # pragma: no cover

                    lacnic_count = 0
                    old_time = time.time()

            # Create a copy of the lookup IP dict so we can modify on
            # successful/failed queries. Loop each IP until it matches the
            # correct RIR in the parent loop, and attempt lookup
            tmp_dict = asn_parsed_results.copy()

            for ip, asn_data in tmp_dict.items():

                # Check to see if IP matches parent loop RIR for lookup
                if asn_data['asn_registry'] == rir:

                    log.debug('Starting lookup for IP: {0} '
                              'RIR: {1}'.format(ip, rir))

                    # LACNIC IP found, add to count for rate-limit tracking
                    if rir == 'lacnic':

                        lacnic_count += 1

                    # Instantiate the objects needed for the RDAP lookup
                    net = Net(ip, timeout=socket_timeout)
                    rdap = RDAP(net)

                    try:

                        # Perform the RDAP lookup
                        results = rdap.lookup(
                            inc_raw=inc_raw, retry_count=0, asn_data=asn_data,
                            depth=depth, excluded_entities=excluded_entities
                        )

                        log.debug('Successful lookup for IP: {0} '
                                  'RIR: {1}'.format(ip, rir))

                        # Lookup was successful, add to result. Set the nir
                        # key to None as this is not supported
                        # (yet - requires more queries)
                        results[ip] = results
                        results[ip]['nir'] = None

                        # Remove the IP from the lookup queue
                        del asn_parsed_results[ip]

                        # If this was LACNIC IP, reduce the total left count
                        if rir == 'lacnic':

                            lacnic_total_left -= 1

                        log.debug(
                            '{0} total lookups left, {1} LACNIC lookups left'
                            ''.format(str(len(asn_parsed_results)),
                                      str(lacnic_total_left))
                        )

                        # If this IP failed previously, remove it from the
                        # failed return dict
                        if (
                            ip in failed_lookups_dict.keys()
                        ):  # pragma: no cover

                            del failed_lookups_dict[ip]

                        # Break out of the IP list loop, we need to change to
                        # the next RIR
                        break

                    except HTTPLookupError:  # pragma: no cover

                        log.debug('Failed lookup for IP: {0} '
                                  'RIR: {1}'.format(ip, rir))

                        # Add the IP to the failed lookups dict if not there
                        if ip not in failed_lookups_dict.keys():

                            failed_lookups_dict[ip] = 1

                        # This IP has already failed at least once, increment
                        # the failure count until retry_count reached, then
                        # stop trying
                        else:

                            failed_lookups_dict[ip] += 1

                            if failed_lookups_dict[ip] == retry_count:

                                del asn_parsed_results[ip]

                                if rir == 'lacnic':

                                    lacnic_total_left -= 1

                        # Since this IP failed, we don't break to move to next
                        # RIR, we check the next IP for this RIR
                        continue

                    except HTTPRateLimitError:  # pragma: no cover

                        # Add the IP to the rate-limited lookups dict if not
                        # there
                        if ip not in rated_lookups:

                            rated_lookups.append(ip)

                        log.debug('Rate limiting triggered for IP: {0} '
                                  'RIR: {1}'.format(ip, rir))

                        # Since rate-limit was reached, reset the timer and
                        # max out the count
                        if rir == 'lacnic':

                            old_time = time.time()
                            lacnic_count = 9

                        # Break out of the IP list loop, we need to change to
                        # the next RIR
                        break

    # Failed lookup counts will always be == retry_count, so make this a list
    failed_lookups = list(failed_lookups_dict.keys())

    return (results, failed_lookups, rated_lookups, ip_lookup_total, 
            ip_unique_total, rir_stats)
