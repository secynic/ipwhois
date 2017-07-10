import logging
from ipwhois.tests import TestCommon
from ipwhois.experimental import (get_bulk_asn_whois, bulk_lookup_rdap)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestExperimental(TestCommon):

    def test_get_bulk_asn_whois(self):

        self.assertRaises(ValueError, get_bulk_asn_whois, **dict(
            addresses='1.2.3.4'
        ))

    def test_get_bulk_lookup_rdap(self):

        self.assertRaises(ValueError, bulk_lookup_rdap, **dict(
            addresses='1.2.3.4'
        ))
