import unittest
import json
import io
from os import path
import logging
from ipwhois.exceptions import WhoisLookupError
from ipwhois.net import Net
from ipwhois.whois import Whois

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


class TestWhois(TestCommon):

    def test__WhoisLookup(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/whois.json', 'r') as data_file:
            data = json.load(data_file)

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = Whois(net)

            try:

                self.assertIsInstance(obj.lookup(asn_data=val['asn_data']),
                                      dict)

            except WhoisLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: %r' % e)
