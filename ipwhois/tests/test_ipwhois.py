import logging
from ipwhois.tests import TestCommon
from ipwhois import IPWhois

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestIPWhois(TestCommon):

    def test_repr(self):

        # basic str test
        log.debug('Basic str test: {0}'.format('74.125.225.229'))
        obj = IPWhois('74.125.225.229')
        self.assertIsInstance(repr(obj), str)

        # add more specific tests
