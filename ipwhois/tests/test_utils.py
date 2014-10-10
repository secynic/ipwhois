import unittest
from ipwhois.utils import (get_countries,
                           ipv4_is_defined,
                           ipv6_is_defined,
                           unique_addresses)


class TestFunctions(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))

    def test_get_countries(self):
        countries = get_countries()
        self.assertIsInstance(countries, dict)
        self.assertEqual(countries['US'], 'United States')

    def test_ipv4_is_defined(self):
        try:
            from ipaddr import AddressValueError
        except ImportError:
            from ipaddress import AddressValueError

        self.assertRaises(ValueError, ipv4_is_defined, '192.168.0.256')
        self.assertRaises(AddressValueError, ipv4_is_defined, 1234)
        self.assertEquals(ipv4_is_defined('192.168.0.1'),
                          (True, 'Private-Use Networks', 'RFC 1918'))
        self.assertEquals(ipv4_is_defined('74.125.225.229'), (False, '', ''))

    def test_ipv6_is_defined(self):
        try:
            from ipaddr import AddressValueError
        except ImportError:
            from ipaddress import AddressValueError

        self.assertRaises(ValueError, ipv6_is_defined,
                          '2001:4860:4860::8888::1234')
        self.assertRaises(AddressValueError, ipv6_is_defined, 1234)
        self.assertEquals(ipv6_is_defined('fe80::'),
                          (True, 'Link-Local', 'RFC 4291, Section 2.5.6'))
        self.assertEquals(ipv6_is_defined('2001:4860:4860::8888'),
                          (False, '', ''))

    def test_unique_addresses(self):
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
