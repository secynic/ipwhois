import sys
import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (IPDefinedError, ASNLookupError,
                                ASNRegistryError, WhoisLookupError,
                                HTTPLookupError, HostLookupError)
from ipwhois.net import Net

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)


class TestNet(TestCommon):

    def test_ip_invalid(self):
        self.assertRaises(ValueError, Net, '192.168.0.256')
        self.assertRaises(ValueError, Net, 'fe::80::')

    def test_ip_defined(self):
        if sys.version_info >= (3, 3):
            from ipaddress import (IPv4Address, IPv6Address)
        else:
            from ipaddr import (IPv4Address, IPv6Address)

        self.assertRaises(IPDefinedError, Net, '192.168.0.1')
        self.assertRaises(IPDefinedError, Net, 'fe80::')
        self.assertRaises(IPDefinedError, Net, IPv4Address('192.168.0.1'))
        self.assertRaises(IPDefinedError, Net, IPv6Address('fe80::'))

    def test_ip_version(self):
        result = Net('74.125.225.229')
        self.assertEqual(result.version, 4)
        result = Net('2001:4860:4860::8888')
        self.assertEqual(result.version, 6)

    def test_timeout(self):
        result = Net('74.125.225.229')
        self.assertIsInstance(result.timeout, int)

    def test_proxy_opener(self):
        try:
            from urllib.request import (OpenerDirector,
                                        ProxyHandler,
                                        build_opener)
        except ImportError:
            from urllib2 import (OpenerDirector,
                                 ProxyHandler,
                                 build_opener)

        result = Net('74.125.225.229')
        self.assertIsInstance(result.opener, OpenerDirector)

        handler = ProxyHandler()
        opener = build_opener(handler)
        result = Net(address='74.125.225.229', proxy_opener=opener)
        self.assertIsInstance(result.opener, OpenerDirector)
