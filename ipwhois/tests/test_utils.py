import unittest
import sys
from os import path
import logging
from ipwhois.utils import (ipv4_lstrip_zeros,
                           calculate_cidr,
                           get_countries,
                           ipv4_is_defined,
                           ipv6_is_defined,
                           unique_everseen,
                           unique_addresses)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)


class TestFunctions(unittest.TestCase):

    maxDiff = None

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))

    def test_ipv4_lstrip_zeros(self):
        if sys.version_info >= (3, 3):
            from ipaddress import ip_address
        else:
            from ipaddr import IPAddress as ip_address

        self.assertIsInstance(ipv4_lstrip_zeros('074.125.000.000'), str)
        tmp = ip_address(ipv4_lstrip_zeros('074.125.000.000')).__str__()

    def test_calculate_cidr(self):

        start_addr = '74.125.0.0'
        end_addr = '74.125.255.255'
        self.assertIsInstance(calculate_cidr(start_addr, end_addr), list)

        start_addr_6 = '2001:240::'
        end_addr_6 = '2001:240:ffff:ffff:ffff:ffff:ffff:ffff'
        self.assertIsInstance(calculate_cidr(start_addr_6, end_addr_6), list)

    def test_get_countries(self):

        # Legacy
        countries = get_countries(is_legacy_xml=True)
        self.assertIsInstance(countries, dict)
        self.assertEqual(countries['US'], 'United States')

        # CSV
        countries = get_countries(is_legacy_xml=False)
        self.assertIsInstance(countries, dict)
        self.assertEqual(countries['US'], 'United States')

    def test_ipv4_is_defined(self):
        if sys.version_info >= (3, 3):
            from ipaddress import AddressValueError
        else:
            from ipaddr import AddressValueError

        self.assertRaises(ValueError, ipv4_is_defined, '192.168.0.256')
        self.assertRaises(AddressValueError, ipv4_is_defined, 1234)

        self.assertEquals(ipv4_is_defined('74.125.225.229'), (False, '', ''))

        self.assertEquals(ipv4_is_defined('0.0.0.0'),
                          (True, 'This Network', 'RFC 1122, Section 3.2.1.3'))
        self.assertEquals(ipv4_is_defined('127.0.0.0'),
                          (True, 'Loopback', 'RFC 1122, Section 3.2.1.3'))
        self.assertEquals(ipv4_is_defined('169.254.0.0'),
                          (True, 'Link Local', 'RFC 3927'))
        self.assertEquals(ipv4_is_defined('192.0.0.0'),
                          (True, 'IETF Protocol Assignments', 'RFC 5736'))
        self.assertEquals(ipv4_is_defined('192.0.2.0'),
                          (True, 'TEST-NET-1', 'RFC 5737'))
        self.assertEquals(ipv4_is_defined('192.88.99.0'),
                          (True, '6to4 Relay Anycast', 'RFC 3068'))
        self.assertEquals(ipv4_is_defined('198.18.0.0'),
                          (True,
                           'Network Interconnect Device Benchmark Testing',
                           'RFC 2544'))
        self.assertEquals(ipv4_is_defined('198.51.100.0'),
                          (True, 'TEST-NET-2', 'RFC 5737'))
        self.assertEquals(ipv4_is_defined('203.0.113.0'),
                          (True, 'TEST-NET-3', 'RFC 5737'))
        self.assertEquals(ipv4_is_defined('224.0.0.0'),
                          (True, 'Multicast', 'RFC 3171'))
        self.assertEquals(ipv4_is_defined('255.255.255.255'),
                          (True, 'Limited Broadcast', 'RFC 919, Section 7'))
        self.assertEquals(ipv4_is_defined('192.168.0.1'),
                          (True, 'Private-Use Networks', 'RFC 1918'))

    def test_ipv6_is_defined(self):
        if sys.version_info >= (3, 3):
            from ipaddress import AddressValueError
        else:
            from ipaddr import AddressValueError

        self.assertRaises(ValueError, ipv6_is_defined,
                          '2001:4860:4860::8888::1234')
        self.assertRaises(AddressValueError, ipv6_is_defined, 1234)

        self.assertEquals(ipv6_is_defined('2001:4860:4860::8888'),
                          (False, '', ''))

        self.assertEquals(ipv6_is_defined('ff00::'),
                          (True, 'Multicast', 'RFC 4291, Section 2.7'))
        self.assertEquals(ipv6_is_defined('0:0:0:0:0:0:0:0'),
                          (True, 'Unspecified', 'RFC 4291, Section 2.5.2'))
        self.assertEquals(ipv6_is_defined('0:0:0:0:0:0:0:1'),
                          (True, 'Loopback', 'RFC 4291, Section 2.5.3'))
        self.assertEquals(ipv6_is_defined('100::'),
                          (True, 'Reserved', 'RFC 4291'))
        self.assertEquals(ipv6_is_defined('fe80::'),
                          (True, 'Link-Local', 'RFC 4291, Section 2.5.6'))
        self.assertEquals(ipv6_is_defined('fec0::'),
                          (True, 'Site-Local', 'RFC 4291, Section 2.5.7'))
        self.assertEquals(ipv6_is_defined('fc00::'),
                          (True, 'Unique Local Unicast', 'RFC 4193'))

    def test_unique_everseen(self):

        input_list = ['b', 'a', 'c', 'a', 'b', 'x', 'a']
        self.assertEquals(list(unique_everseen(input_list)),
                          ['b', 'a', 'c', 'x'])

        self.assertEquals(list(unique_everseen(input_list, str.lower)),
                          ['b', 'a', 'c', 'x'])

    def test_unique_addresses(self):

        self.assertRaises(ValueError, unique_addresses)

        input_data = (
            'You can have IPs like 74.125.225.229, or 2001:4860:4860::8888'
            'Put a port on the end 74.125.225.229:80 or for IPv6: '
            '[2001:4860:4860::8888]:443 or even networks like '
            '74.125.0.0/16 and 2001:4860::/32.'
        )

        expected_result = {
            '74.125.225.229': {'count': 2, 'ports': {'80': 1}},
            '2001:4860::/32': {'count': 1, 'ports': {}},
            '74.125.0.0/16': {'count': 1, 'ports': {}},
            '2001:4860:4860::8888': {'count': 2, 'ports': {'443': 1}}
        }

        self.assertEquals(unique_addresses(input_data), expected_result)

        data_dir = path.dirname(__file__)
        fp = str(data_dir) + '/rdap.json'

        fp_expected_result = {
            '74.125.225.0/24': {'count': 1, 'ports': {}},
            '62.239.0.0/16': {'count': 1, 'ports': {}},
            '2001:43f8:7b0:ffff:ffff:ffff:ffff:ffff':
                {'count': 1, 'ports': {}},
            '210.0.0.0': {'count': 1, 'ports': {}},
            '196.11.240.0/23': {'count': 1, 'ports': {}},
            '2001:240:10c:1::ca20:9d1d': {'count': 2, 'ports': {}},
            '196.11.240.215': {'count': 2, 'ports': {}},
            '62.239.237.0/32': {'count': 1, 'ports': {}},
            '210.107.0.0/17': {'count': 6, 'ports': {}},
            '2001:4860::/32': {'count': 1, 'ports': {}},
            '210.107.73.73': {'count': 2, 'ports': {}},
            '210.107.0.0': {'count': 2, 'ports': {}},
            '2001:200::/23': {'count': 2, 'ports': {}},
            '2001:240:ffff:ffff:ffff:ffff:ffff:ffff':
                {'count': 1, 'ports': {}},
            '210.255.255.255': {'count': 1, 'ports': {}},
            '2001:43f8:7b0::': {'count': 3, 'ports': {}},
            '196.255.255.255': {'count': 1, 'ports': {}},
            '2001:240::/32': {'count': 6, 'ports': {}},
            '196.0.0.0': {'count': 1, 'ports': {}},
            '2001:240::': {'count': 1, 'ports': {}},
            '196.11.246.255': {'count': 2, 'ports': {}},
            '196.11.239.0': {'count': 2, 'ports': {}},
            '2001:4200::/23': {'count': 1, 'ports': {}},
            '2a00:2380::/25': {'count': 1, 'ports': {}},
            '200.57.128.0/20': {'count': 1, 'ports': {}},
            '62.239.237.255': {'count': 1, 'ports': {}},
            '2001:4860:4860::8888': {'count': 10, 'ports': {}},
            '2001:4860::': {'count': 2, 'ports': {}},
            '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff':
                {'count': 1, 'ports': {}},
            '74.125.225.229': {'count': 8, 'ports': {}},
            '210.107.127.255': {'count': 2, 'ports': {}},
            '200.57.141.161': {'count': 7, 'ports': {}},
            '62.239.237.255/32': {'count': 1, 'ports': {}},
            '2801:10:c000::': {'count': 7, 'ports': {}},
            '2a00:2381:ffff::1': {'count': 4, 'ports': {}},
            '62.239.237.0': {'count': 1, 'ports': {}},
            '62.239.237.1': {'count': 4, 'ports': {}},
            '210.0.0.0/8': {'count': 1, 'ports': {}}
        }

        self.assertEquals(unique_addresses(file_path=fp), fp_expected_result)
