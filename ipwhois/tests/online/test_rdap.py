import unittest
import json
import io
from os import path
from ipwhois.exceptions import HTTPLookupError
from ipwhois.rdap import (RDAP, Net)


class TestCommon(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '%s is not an instance of %r' % (repr(obj), cls)
                ))


class TestRDAP(TestCommon):

    def test__RDAPLookup(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/rdap.json', 'r') as data_file:
            data = json.load(data_file)

        for key, val in data.items():

            net = Net(key)
            obj = RDAP(net)

            try:

                self.assertIsInstance(obj.lookup(asn_data=val['asn_data'],
                                                 depth=0), dict)

            except HTTPLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: %r' % e)