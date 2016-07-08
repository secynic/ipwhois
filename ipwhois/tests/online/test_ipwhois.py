import logging
from ipwhois.tests import TestCommon
from ipwhois import (IPWhois, ASNLookupError, ASNRegistryError,
                     WhoisLookupError, HTTPLookupError, BlacklistError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


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
                self.fail('Unexpected exception raised: {0}'.format(e))

        rwhois_ips = [
            '38.113.116.218'  # COGNETCO
        ]

        for ip in rwhois_ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup(
                    get_referral=True,
                    ignore_referral_errors=True,
                    inc_raw=True), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: {0}'.format(e))

        for ip in rwhois_ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup(
                    get_referral=True,
                    ignore_referral_errors=True,
                    inc_raw=True,
                    extra_blacklist=['rwhois.cogentco.com']), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: {0}'.format(e))

            try:
                self.assertIsInstance(result.lookup(
                    get_referral=True,
                    ignore_referral_errors=False,
                    inc_raw=True,
                    extra_blacklist=['rwhois.cogentco.com']), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError,
                    BlacklistError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: {0}'.format(e))

            break

        for ip in rwhois_ips:

            result = IPWhois(ip)
            try:
                self.assertIsInstance(result.lookup(
                    get_referral=True,
                    ignore_referral_errors=False,
                    inc_raw=False), dict)
            except (ASNLookupError, ASNRegistryError, WhoisLookupError):
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: {0}'.format(e))

            break

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
                self.fail('Unexpected exception raised: {0}'.format(e))

        handler = ProxyHandler({'http': 'http://0.0.0.0:80/'})
        opener = build_opener(handler)
        result = IPWhois(address='74.125.225.229', timeout=0,
                         proxy_opener=opener)
        self.assertRaises(HTTPLookupError, result.lookup_rdap)

        log.debug('Testing allow_permutations')
        result = IPWhois(address='74.125.225.229', timeout=0,
                         allow_permutations=False)
        self.assertRaises(ASNRegistryError, result.lookup_rdap)
