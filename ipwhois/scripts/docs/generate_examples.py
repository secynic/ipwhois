# Copyright (c) 2013-2019 Philip Hane
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

# CLI python script interface for generating the docs usage examples output.

import argparse
import json
import logging
import re
from ipwhois import IPWhois
from ipwhois.experimental import (get_bulk_asn_whois, bulk_lookup_rdap)
from ipwhois.net import Net
from ipwhois.asn import (ASNOrigin, IPASN)
from ipwhois.utils import unique_everseen

# CLI ANSI rendering
ANSI = {
    'end': '\033[0m',
    'b': '\033[1m',
    'ul': '\033[4m',
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'cyan': '\033[36m'
}

# Setup the arg parser.
parser = argparse.ArgumentParser(
    description='ipwhois documentation usage examples generator'
)

parser.add_argument(
    '--docs',
    type=str,
    metavar='"RDAP.rst,WHOIS.rst,NIR.rst,ASN.rst..."',
    nargs=1,
    help='Comma separated list of RST document names to process. Omitting '
         'this argmuent will default to all supported.'
)

# Output options
group = parser.add_argument_group('Output options')

group.add_argument(
    '--progress',
    action='store_true',
    help='If set, provides output for this script\'s progress.'
)

group.add_argument(
    '--debug',
    action='store_true',
    help='If set, provides debug logging output.'
)

# Get the args
script_args = parser.parse_args()

RST_FILES = {
    'ASN.rst': {
        'OUTPUT_IP_ASN_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois.net import Net\n'
                '    >>>> from ipwhois.asn import IPASN\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> net = Net(\'2001:43f8:7b0::\')\n'
                '    >>>> obj = IPASN(net)\n'
                '    >>>> results = obj.lookup()\n'
                '    >>>> pprint(results)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: IPASN(Net('2001:43f8:7b0::')).lookup(),
            }
        },
        'OUTPUT_ASN_ORIGIN_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois.net import Net\n'
                '    >>>> from ipwhois.asn import ASNOrigin\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> net = Net(\'2001:43f8:7b0::\')\n'
                '    >>>> obj = ASNOrigin(net)\n'
                '    >>>> results = obj.lookup(asn=\'AS37578\')\n'
                '    >>>> pprint(results)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: ASNOrigin(Net('2001:43f8:7b0::')).lookup(
                    asn='AS37578'
                ),
            }
        }
    },
    'EXPERIMENTAL.rst': {
        'GET_BULK_ASN_WHOIS_OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois.experimental import get_bulk_asn_whois'
                '\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> ip_list = [\'74.125.225.229\', '
                '\'2001:4860:4860::8888\', \'62.239.237.1\', '
                '\'2a00:2381:ffff::1\', \'210.107.73.73\', '
                '\'2001:240:10c:1::ca20:9d1d\', \'200.57.141.161\', '
                '\'2801:10:c000::\', \'196.11.240.215\', \'2001:43f8:7b0::\', '
                '\'133.1.2.5\', \'115.1.2.3\']\n'
                '    >>>> results = get_bulk_asn_whois(addresses=ip_list)\n'
                '    >>>> pprint(results.split(\'\\\\n\'))\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: get_bulk_asn_whois([
                    '74.125.225.229',  # ARIN
                    '2001:4860:4860::8888',
                    '62.239.237.1',  # RIPE
                    '2a00:2381:ffff::1',
                    '210.107.73.73',  # APNIC
                    '2001:240:10c:1::ca20:9d1d',
                    '200.57.141.161',  # LACNIC
                    '2801:10:c000::',
                    '196.11.240.215',  # AFRINIC
                    '2001:43f8:7b0::',
                    '133.1.2.5',  # JPNIC
                    '115.1.2.3'  # KRNIC
                ]).split('\n'),
            }
        },
        'BULK_LOOKUP_RDAP_OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois.experimental import bulk_lookup_rdap\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> ip_list = [\'74.125.225.229\', '
                '\'2001:4860:4860::8888\', \'62.239.237.1\', '
                '\'2a00:2381:ffff::1\', \'210.107.73.73\', '
                '\'2001:240:10c:1::ca20:9d1d\', \'200.57.141.161\', '
                '\'2801:10:c000::\', \'196.11.240.215\', \'2001:43f8:7b0::\', '
                '\'133.1.2.5\', \'115.1.2.3\']\n'
                '    >>>> results, stats = bulk_lookup_rdap(addresses=ip_list)'
                '\n'
                '    >>>> pprint(stats)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: bulk_lookup_rdap(addresses=[
                    '74.125.225.229',  # ARIN
                    '2001:4860:4860::8888',
                    '62.239.237.1',  # RIPE
                    '2a00:2381:ffff::1',
                    '210.107.73.73',  # APNIC
                    '2001:240:10c:1::ca20:9d1d',
                    '200.57.141.161',  # LACNIC
                    '2801:10:c000::',
                    '196.11.240.215',  # AFRINIC
                    '2001:43f8:7b0::',
                    '133.1.2.5',  # JPNIC
                    '115.1.2.3'  # KRNIC
                ])[1],
            }
        }
    },
    'NIR.rst': {
        'OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois import IPWhois\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> obj = IPWhois(\'133.1.2.5\')\n'
                '    >>>> results = obj.lookup_whois(inc_nir=True)\n'
                '    >>>> pprint(results)\n\n'                
                '    {0}\n\n'
                '    >>>> results = obj.lookup_rdap(depth=1, inc_nir=True)\n'
                '    >>>> pprint(results)\n\n'
                '    {1}'
            ),
            'queries': {
                '0': lambda: IPWhois('133.1.2.5', timeout=15).lookup_whois(
                    inc_nir=True, retry_count=10
                ),
                '1': lambda: IPWhois('133.1.2.5', timeout=15).lookup_rdap(
                    depth=1, inc_nir=True, retry_count=10
                ),
            }
        }
    },
    'RDAP.rst': {
        'OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois import IPWhois\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> obj = IPWhois(\'74.125.225.229\')\n'
                '    >>>> results = obj.lookup_rdap(depth=1)\n'
                '    >>>> pprint(results)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: IPWhois('74.125.225.229', timeout=15).lookup_rdap(
                    depth=1, retry_count=10
                ),
            }
        }
    },
    'WHOIS.rst': {
        'OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois import IPWhois\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> obj = IPWhois(\'74.125.225.229\')\n'
                '    >>>> results = obj.lookup_whois()\n'
                '    >>>> pprint(results)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: IPWhois('74.125.225.229',
                                     timeout=15).lookup_whois(
                    retry_count=10
                ),
            }
        },
        'OUTPUT_MULTI_REF': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois import IPWhois\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> obj = IPWhois(\'38.113.198.252\')\n'
                '    >>>> results = obj.lookup_whois(get_referral=True)\n'
                '    >>>> pprint(results)\n\n'
                '    {0}'
            ),
            'queries': {
                '0': lambda: IPWhois('38.113.198.252',
                                     timeout=15).lookup_whois(
                    get_referral=True, retry_count=10
                ),
            }
        }
    }
}

if script_args.debug:

    LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
                  '[%(funcName)s()] %(message)s')
    logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
    log = logging.getLogger(__name__)

if script_args.docs:

    rst_files_keys = list(unique_everseen(script_args.docs[0].split(',')))

    try:

        for v in rst_files_keys:

            keytest = RST_FILES[v]

    except KeyError as e:

        print('{0}--docs key error{1}: {2}'.format(
            ANSI['red'], ANSI['end'], str(e)
        ))
        exit(0)

else:

    rst_files_keys = RST_FILES.keys()

x = 1
for filename, sections in (
         x for x in RST_FILES.items() if x[0] in rst_files_keys
):

    if script_args.progress:

        print('{0}Processing file{1}: {2} ({3}/{4})'.format(
            ANSI['b'], ANSI['end'], str(filename), str(x),
            str(len(rst_files_keys))
        ))

    filepath = '../../../{0}'.format(filename)
    s = open(filepath).read()

    for section_key, section_config in sections.items():

        tmp_query_results = {}
        for query_key, query in section_config['queries'].items():

            result = query()
            new_str = json.dumps(
                result, indent=4, sort_keys=True
            ).replace(': null', ': None')

            new_str = re.sub(
                r'(\\r\\n)(?=.+?")',
                r'\\\\r\\\\n',
                new_str,
                flags=re.DOTALL
            )

            new_str = re.sub(
                r'(\\\\n)',
                r'\\n',
                new_str,
                flags=re.DOTALL
            )

            tmp_query_results[query_key] = re.sub(
                r'(?<!\\\\r\\)(\\n)(?=.+?")',
                r'\\\\n',
                new_str,
                flags=re.DOTALL
            )[:-1] + '    {0}'.format(
                '}' if isinstance(result, dict) else ']'
            )

        output_str = section_config['content'].format(
            *tmp_query_results.values()
        )

        start = '{0} START'.format(section_key)
        end = '{0} END'.format(section_key)
        s = re.sub(
            '..\\s{0}.*?..\\s{1}'.format(
                start, end
            ),
            '.. {0}\n\n{1}\n\n.. {2}'.format(start, output_str, end),
            s,
            flags=re.DOTALL
        )

    if script_args.progress:

        print('{0}Writing updates to file{1}: {2} ({3}/{4})'.format(
            ANSI['b'], ANSI['end'], str(filename), str(x),
            str(len(rst_files_keys))
        ))

    f = open(filepath, 'w')
    f.write(s)
    f.close()

    if script_args.progress:

        print('{0}Updates completed for file{1}: {2} ({3}/{4})'.format(
            ANSI['b'], ANSI['end'], str(filename), str(x),
            str(len(rst_files_keys))
        ))

    x += 1
