import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (ASNLookupError)
from ipwhois.experimental import (get_bulk_asn_whois, bulk_lookup_rdap)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestExperimental(TestCommon):

    def test_get_bulk_asn_whois(self):

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
            '2001:43f8:7b0::',
            '133.1.2.5',  # JPNIC
            '115.1.2.3'  # KRNIC
        ]

        try:
            self.assertIsInstance(get_bulk_asn_whois(addresses=ips), str)
        except ASNLookupError:
            pass
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

    def test_bulk_lookup_rdap(self):

        try:
            from urllib.request import (OpenerDirector,
                                        ProxyHandler,
                                        build_opener)
        except ImportError:
            from urllib2 import (OpenerDirector,
                                 ProxyHandler,
                                 build_opener)

        handler = ProxyHandler()
        opener = build_opener(handler)
        bulk_lookup_rdap(addresses=['74.125.225.229'], proxy_openers=[opener])

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
            '2001:43f8:7b0::',
            '133.1.2.5',  # JPNIC
            '115.1.2.3'  # KRNIC
        ]

        expected_stats = {'ip_input_total': 12, 'ip_unique_total': 12,
                          'ip_lookup_total': 12, 'ip_failed_total': 0,
                          'lacnic': {'failed': [], 'rate_limited': [], 'total': 2},
                          'ripencc': {'failed': [], 'rate_limited': [], 'total': 2},
                          'apnic': {'failed': [], 'rate_limited': [], 'total': 4},
                          'afrinic': {'failed': [], 'rate_limited': [], 'total': 2},
                          'arin': {'failed': [], 'rate_limited': [], 'total': 2},
                          'unallocated_addresses': []}

        try:
            result = bulk_lookup_rdap(addresses=ips)
            self.assertIsInstance(result, tuple)

            results, stats = result
            self.assertEqual(stats, expected_stats)
            self.assertEqual(len(results), 12)

        except ASNLookupError:
            pass
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))
