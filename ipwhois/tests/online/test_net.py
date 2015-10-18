import unittest
from ipwhois import (Net, ASNLookupError, ASNRegistryError,
                     WhoisLookupError, HTTPLookupError, HostLookupError)


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

    def test_get_host(self):
        result = Net('74.125.225.229')
        try:
            self.assertIsInstance(result.get_host(), tuple)
        except HostLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: %r' % e)
