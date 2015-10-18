import unittest
import json
import io
from ipwhois.rdap import (RDAP, _RDAPEntity, InvalidEntityObject,
                          InvalidEntityContactObject, Net)


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

        with io.open('rdap.json') as data_file:
            data = json.load(data_file)

        for key, val in data.items():

            net = Net(key)
            obj = RDAP(net)

            try:

                self.assertIsInstance(obj.lookup(response=val['response'],
                                                 asn_data=val['asn_data'],
                                                 depth=0), dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: %r' % e)


class TestRDAPEntity(TestCommon):

    def test__RDAPEntity(self):

        self.assertRaises(InvalidEntityObject, _RDAPEntity, 'abc')

        ent = _RDAPEntity({'abc': 'def'})
        self.assertRaises(InvalidEntityObject, ent.parse)

        with io.open('entity.json') as data_file:
            data = json.load(data_file)

        ent = _RDAPEntity(data)
        ent.parse()
