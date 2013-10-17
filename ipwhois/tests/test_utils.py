import unittest
from ipwhois.utils import get_countries, ipv4_is_defined, ipv6_is_defined

class TestFunctions(unittest.TestCase):
    
    def test_get_countries(self):
        countries = get_countries()
        self.assertIsInstance(countries, dict)
        self.assertEqual(countries['US'], 'United States')
        
    def test_ipv4_is_defined(self):
        from ipaddress import AddressValueError
        self.assertRaises(ValueError, ipv4_is_defined, '192.168.0.256')
        self.assertRaises(AddressValueError, ipv4_is_defined, 1234)
        self.assertEquals(ipv4_is_defined('192.168.0.1'), (True, 'Private-Use Networks', 'RFC 1918'))
        self.assertEquals(ipv4_is_defined('74.125.225.229'), (False, '', ''))
        
    def test_ipv6_is_defined(self):
        from ipaddress import AddressValueError
        self.assertRaises(ValueError, ipv6_is_defined, '2001:4860:4860::8888::1234')
        self.assertRaises(AddressValueError, ipv6_is_defined, 1234)
        self.assertEquals(ipv6_is_defined('fe80::'), (True, 'Link-Local', 'RFC 4291, Section 2.5.6'))
        self.assertEquals(ipv6_is_defined('2001:4860:4860::8888'), (False, '', ''))