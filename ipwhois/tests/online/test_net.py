import unittest
import logging
from ipwhois import (Net, ASNLookupError, ASNRegistryError, BlacklistError,
                     WhoisLookupError, HTTPLookupError, HostLookupError,
                     HTTPRateLimitError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)


class TestCommon(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))


class TestNet(TestCommon):

    def test_get_asn_dns(self):
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_dns(), dict)
        except (ASNLookupError, ASNRegistryError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

    def test_get_asn_whois(self):
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.get_asn_whois(), dict)
        except (ASNLookupError, ASNRegistryError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

        result = Net('74.125.225.229')
        self.assertRaises(ASNLookupError, result.get_asn_whois, 3, 'a')

    def test_get_whois(self):
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.get_whois(), str)
        except WhoisLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

        self.assertRaises(WhoisLookupError, result.get_whois, **dict(
            retry_count=0, server='arin.net'))

        self.assertRaises(BlacklistError, result.get_whois, **dict(
            server='whois.arin.net', extra_blacklist=['whois.arin.net']))

        result = Net('74.125.225.229', 0)
        self.assertRaises(WhoisLookupError, result.get_whois, **dict(
            retry_count=1))

    def test_get_http_json(self):
        from ipwhois.rdap import RIR_RDAP
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.get_http_json(
                RIR_RDAP['arin']['ip_url'].format('74.125.225.229')), dict)
        except HTTPLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

        self.assertRaises(HTTPLookupError, result.get_http_json, **dict(
            url='http://255.255.255.255', retry_count=0))

        result = Net('74.125.225.229', 0)
        url = RIR_RDAP['arin']['ip_url'].format('74.125.225.229')
        self.assertRaises(HTTPLookupError, result.get_http_json, **dict(
            url=url, retry_count=0))

        # Uncommenting below will result in a flood of up to 20 requests
        # to test rate limiting.
        '''
        url = RIR_RDAP['lacnic']['ip_url'].format('200.57.141.161')
        result = Net('200.57.141.161')
        count = 20
        while count > 0:
            count -= 1
            try:
                self.assertRaises(HTTPRateLimitError, result.get_http_json,
                                  **dict(url=url, retry_count=0))
                break

            except AssertionError as e:
                if count == 0:
                    raise e
                else:
                    pass
        '''

    def test_get_host(self):
        ips = [
            '74.125.225.229',  # ARIN
            '2001:4860:4860::8888'
        ]

        for ip in ips:
            result = Net(ip)
            try:
                self.assertIsInstance(result.get_host(0), tuple)
            except HostLookupError:
                pass
            except AssertionError as e:
                raise e
            except Exception as e:
                self.fail('Unexpected exception raised: %r' % e)

        result = Net('74.125.225.229', 0)
        self.assertRaises(HostLookupError, result.get_host, **dict(
            retry_count=1))

    def test_lookup_asn(self):
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.lookup_asn(), tuple)
        except (HTTPLookupError, ASNRegistryError):
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)

        result = Net('74.125.225.229', timeout=0, allow_permutations=False)
        self.assertRaises(ASNRegistryError, result.lookup_asn)
