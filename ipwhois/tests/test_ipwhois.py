import unittest
from ipwhois import (IPWhois, IPDefinedError, ASNLookupError, WhoisLookupError,
                     HostLookupError)


class TestIPWhois(unittest.TestCase):

    def test_ip_invalid(self):
        from ipaddress import AddressValueError
        self.assertRaises(ValueError, IPWhois, '192.168.0.256')
        self.assertRaises(AddressValueError, IPWhois, 1234)

    def test_ip_defined(self):
        self.assertRaises(IPDefinedError, IPWhois, '192.168.0.1')
        self.assertRaises(IPDefinedError, IPWhois, 'fe80::')

    def test_ip_version(self):
        result = IPWhois('74.125.225.229')
        self.assertEqual(result.version, 4)
        result = IPWhois('2001:4860:4860::8888')
        self.assertEqual(result.version, 6)

    def test_timeout(self):
        result = IPWhois('74.125.225.229')
        self.assertIsInstance(result.timeout, int)

    def test_proxy_opener(self):
        from urllib.request import OpenerDirector
        result = IPWhois('74.125.225.229')
        self.assertIsInstance(result.opener, OpenerDirector)

    def test_get_asn_dns(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_dns(), dict)
        except ASNLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_asn_whois(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_whois(), dict)
        except ASNLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_whois(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_whois(), str)
        except WhoisLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_rws(self):
        from ipwhois.ipwhois import NIC_WHOIS
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_rws(
                NIC_WHOIS['arin']['url'].format('74.125.225.229')), dict)
        except WhoisLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_host(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_host(), tuple)
        except HostLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_lookup(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.lookup(), dict)
        except (ASNLookupError, WhoisLookupError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_lookup_rws(self):
        from urllib import request
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.lookup_rws(), dict)
        except (ASNLookupError, WhoisLookupError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)
        handler = request.ProxyHandler({'http': 'http://0.0.0.0:80/'})
        opener = request.build_opener(handler)
        result = IPWhois('74.125.225.229', 0, opener)
        self.assertRaises(WhoisLookupError, result.lookup_rws)
