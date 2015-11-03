import unittest
import logging
from ipwhois import (IPWhois, ASNLookupError, ASNRegistryError,
                     WhoisLookupError, HTTPLookupError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestCommon(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))


class TestIPWhois(TestCommon):

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

            log.debug('Testing: {0}'.format(ip))
            result = IPWhois(ip)

            try:
                self.assertIsInstance(result.lookup(), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

        rwhois_ips = [
            '38.113.116.218'  # COGNETCO
        ]

        for ip in rwhois_ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup(get_referral=True), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

    def test_lookup_rdap(self):
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

            log.debug('Testing: {0}'.format(ip))
            result = IPWhois(ip)

            try:
                self.assertIsInstance(result.lookup_rdap(), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError,
                    HTTPLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

        handler = ProxyHandler({'http': 'http://0.0.0.0:80/'})
        opener = build_opener(handler)
        result = IPWhois('74.125.225.229', 0, opener)
        self.assertRaises(HTTPLookupError, result.lookup_rdap)
