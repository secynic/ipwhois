import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (ASNLookupError)
from ipwhois.experimental import (get_bulk_asn_whois, bulk_lookup_rdap)
from ipwhois.utils import (ipv4_generate_random, ipv6_generate_random)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestExperimental(TestCommon):

    def test_get_bulk_asn_whois(self):

        ips = (list(ipv4_generate_random(500)) +
               list(ipv6_generate_random(500)))
        try:
            self.assertIsInstance(get_bulk_asn_whois(addresses=ips), str)
        except ASNLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

    def test_bulk_lookup_rdap(self):

        ips = (list(ipv4_generate_random(250)) +
               list(ipv6_generate_random(250)))
        try:
            self.assertIsInstance(bulk_lookup_rdap(addresses=ips), tuple)
        except ASNLookupError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))
