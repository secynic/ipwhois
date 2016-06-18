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

# CLI python script interface for ipwhois.utils lookups.

import argparse
import json
from ipwhois.utils import (ipv4_lstrip_zeros, calculate_cidr, get_countries,
                           ipv4_is_defined, ipv6_is_defined, unique_everseen,
                           unique_addresses)

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

# Color definitions for sub lines
COLOR_DEPTH = {
    '0': ANSI['green'],
    '1': ANSI['yellow'],
    '2': ANSI['red'],
    '3': ANSI['cyan']
}

# Line formatting, keys ending in C are colorized versions.
LINES = {
    '1': '>> ',
    '2': '>> >>> ',
    '3': '>> >>> >>>> ',
    '4': '>> >>> >>>> >>>>> ',
    '1C': '{0}>>{1} '.format(COLOR_DEPTH['0'], ANSI['end']),
    '2C': '{0}>>{1} >>>{2} '.format(
        COLOR_DEPTH['0'], COLOR_DEPTH['1'], ANSI['end']
    ),
    '3C': '{0}>>{1} >>>{2} >>>>{3} '.format(
        COLOR_DEPTH['0'], COLOR_DEPTH['1'], COLOR_DEPTH['2'], ANSI['end']
    ),
    '4C': '{0}>>{1} >>>{2} >>>>{3} >>>>>{4} '.format(
        COLOR_DEPTH['0'], COLOR_DEPTH['1'], COLOR_DEPTH['2'], COLOR_DEPTH['3'],
        ANSI['end']
    ),
}

# Setup the arg parser.
parser = argparse.ArgumentParser(
    description='ipwhois utilities CLI interface'
)
parser.add_argument(
    '--ipv4_lstrip_zeros',
    type=str,
    nargs=1,
    metavar='"IP ADDRESS"',
    help='Strip leading zeros in each octet of an IPv4 address.'
)
parser.add_argument(
    '--calculate_cidr',
    type=str,
    nargs=2,
    metavar='"IP ADDRESS"',
    help='Calculate a CIDR range(s) from a start and end IP address.'
)
parser.add_argument(
    '--get_countries',
    action='store_true',
    help='Output a dictionary containing ISO_3166-1 country codes to names.'
)
parser.add_argument(
    '--ipv4_is_defined',
    type=str,
    nargs=1,
    metavar='"IP ADDRESS"',
    help='Check if an IPv4 address is defined (in a reserved address range).'
)
parser.add_argument(
    '--ipv6_is_defined',
    type=str,
    nargs=1,
    metavar='"IP ADDRESS"',
    help='Check if an IPv6 address is defined (in a reserved address range).'
)
parser.add_argument(
    '--unique_everseen',
    type=json.loads,
    nargs=1,
    metavar='"ITERABLE"',
    help='List unique elements from input iterable, preserving the order.'
)
parser.add_argument(
    '--unique_addresses',
    type=str,
    nargs=1,
    metavar='"FILE PATH"',
    help='Search an input file, extracting, counting, and summarizing '
         'IPv4/IPv6 addresses/networks.'
)

# Get the args
script_args = parser.parse_args()

if script_args.ipv4_lstrip_zeros:

    print(ipv4_lstrip_zeros(address=script_args.ipv4_lstrip_zeros[0]))

elif script_args.calculate_cidr:

    print(calculate_cidr(start_address=script_args.calculate_cidr[0],
                         end_address=script_args.calculate_cidr[1]))

elif script_args.get_countries:

    print(get_countries())

elif script_args.ipv4_is_defined:

    print(ipv4_is_defined(address=script_args.ipv4_is_defined[0]))

elif script_args.ipv6_is_defined:

    print(ipv6_is_defined(address=script_args.ipv6_is_defined[0]))

elif script_args.unique_everseen:

    print(list(unique_everseen(iterable=script_args.unique_everseen[0])))

elif script_args.unique_addresses:

    print(unique_addresses(file_path=script_args.unique_addresses[0]))
