import unittest
import logging
from ipwhois import IPWhois

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
                    '{0} is not an instance of {1}'.format(obj, cls)
                ))


class TestIPWhois(TestCommon):

    def test_repr(self):

        # basic str test
        log.debug('Basic str test: {0}'.format('74.125.225.229'))
        obj = IPWhois('74.125.225.229')
        self.assertIsInstance(repr(obj), str)

        # add more specific tests
