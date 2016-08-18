# Copyright (c) 2013, 2014, 2015, 2016 Philip Hane
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

from ipwhois import IPWhois
import re
import json

RST_FILES = {
    'NIR.rst': {
        'OUTPUT_BASIC': {
            'content': (
                '::\n\n'
                '    >>>> from ipwhois import IPWhois\n'
                '    >>>> from pprint import pprint\n\n'
                '    >>>> obj = IPWhois(\'133.1.2.5\')\n'
                '    >>>> results = obj.lookup_whois(inc_nir=True)\n\n'
                '    {0}\n\n'
                '    >>>> results = obj.lookup_rdap(depth=1, inc_nir=True)\n\n'
                '    {1}'
            ),
            'queries': {
                '0': lambda: IPWhois('133.1.2.5').lookup_whois(
                    inc_nir=True
                ),
                '1': lambda: IPWhois('133.1.2.5').lookup_rdap(
                    depth=1, inc_nir=True
                ),
            }
        }
    }
}

for filename, sections in RST_FILES.items():

    filepath = '../../../{0}'.format(filename)
    s = open(filepath).read()

    for section_key, section_config in sections.items():

        tmp_query_results = {}
        for query_key, query in section_config['queries'].items():

            new_str = json.dumps(
                query(), indent=4, sort_keys=True
            ).replace(', "', ',\n    "')

            tmp_query_results[query_key] = re.sub(
                r'(\\n)(?=.+?")',
                r', ',
                new_str,
                flags=re.DOTALL
            )[:-1] + '    }'

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

    f = open(filepath, 'w')
    f.write(s)
    f.close()
