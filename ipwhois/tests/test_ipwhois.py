import unittest
from ipwhois import (IPWhois, IPDefinedError, ASNLookupError, ASNRegistryError,
                     WhoisLookupError, HostLookupError)


class TestIPWhois(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))

    def test_ip_invalid(self):
        try:
            from ipaddress import AddressValueError
        except ImportError:
            from ipaddr import AddressValueError

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
        try:
            from urllib.request import OpenerDirector
        except ImportError:
            from urllib2 import OpenerDirector

        result = IPWhois('74.125.225.229')
        self.assertIsInstance(result.opener, OpenerDirector)

    def test_get_asn_dns(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_dns(), dict)
        except (ASNLookupError, ASNRegistryError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_asn_whois(self):
        result = IPWhois('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_whois(), dict)
        except (ASNLookupError, ASNRegistryError):
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

        ips = [
            '74.125.225.229',  # ARIN
            '2001:4860:4860::8888',
            '62.239.237.1',  # RIPE
            '2a00:2381:ffff::1',
            '210.107.73.73',  # APNIC
            '2001:240:10c:1::ca20:9d1d',
            '200.57.141.161',  # LACNIC
            '2801:10:c000::',
            '196.11.240.215',  # AFRINIC
            '2001:43f8:7b0::'
        ]

        for ip in ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup(), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

    def test_lookup_rws(self):
        try:
            from urllib.request import ProxyHandler, build_opener
        except ImportError:
            from urllib2 import ProxyHandler, build_opener

        ips = [
            '74.125.225.229',  # ARIN
            '2001:4860:4860::8888',
            '62.239.237.1',  # RIPE
            '2a00:2381:ffff::1',
            '210.107.73.73',  # APNIC
            '2001:240:10c:1::ca20:9d1d',
            '200.57.141.161',  # LACNIC
            '2801:10:c000::',
            '196.11.240.215',  # AFRINIC
            '2001:43f8:7b0::'
        ]

        for ip in ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup_rws(), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

        handler = ProxyHandler({'http': 'http://0.0.0.0:80/'})
        opener = build_opener(handler)
        result = IPWhois('74.125.225.229', 0, opener)
        self.assertRaises(WhoisLookupError, result.lookup_rws)
