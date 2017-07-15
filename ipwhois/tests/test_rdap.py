import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.rdap import (RDAP, _RDAPEntity, _RDAPContact, _RDAPNetwork, Net,
                          InvalidEntityObject, InvalidEntityContactObject,
                          InvalidNetworkObject, NetError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestRDAP(TestCommon):

    def test_RDAP(self):

        self.assertRaises(NetError, RDAP, 'a')

    def test_lookup(self):

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/rdap.json', 'r') as data_file:
            data = json.load(data_file)

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = RDAP(net)

            try:

                self.assertIsInstance(obj.lookup(response=val['response'],
                                                 asn_data=val['asn_data'],
                                                 depth=0), dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

            self.assertRaises(NetError, RDAP, 'a')

        for key, val in data.items():

            log.debug('Testing bootstrap and raw: {0}'.format(key))
            net = Net(key)
            obj = RDAP(net)

            try:

                self.assertIsInstance(obj.lookup(response=val['response'],
                                                 asn_data=val['asn_data'],
                                                 depth=0,
                                                 bootstrap=True,
                                                 inc_raw=True), dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

            break

        log.debug('Testing rdap.lookup response checks')
        net = Net('74.125.225.229')
        obj = RDAP(net)
        self.assertIsInstance(obj.lookup(response={
                                             'handle': 'test',
                                             'ipVersion': 'v4',
                                             'startAddress': '74.125.225.229',
                                             'endAddress': '74.125.225.229'
                                         },
                                         asn_data=val['asn_data'],
                                         depth=0), dict)

        log.debug('Testing rdap.lookup entitiy checks')
        net = Net('74.125.225.229')
        obj = RDAP(net)
        entity = [{'handle': 'test', 'roles': [
            'administrative', 'technical'], 'entities': [
            {'handle': 'GOGL', 'roles': ['administrative', 'technical']}]}]

        self.assertIsInstance(obj.lookup(response={
                                             'handle': 'test',
                                             'ipVersion': 'v4',
                                             'startAddress': '74.125.225.229',
                                             'endAddress': '74.125.225.229',
                                             'entities': entity
                                         },
                                         asn_data=val['asn_data'],
                                         depth=1), dict)

        self.assertIsInstance(obj.lookup(response={
                                             'handle': 'test',
                                             'ipVersion': 'v4',
                                             'startAddress': '74.125.225.229',
                                             'endAddress': '74.125.225.229',
                                             'entities': entity
                                         },
                                         asn_data=val['asn_data'],
                                         depth=1,
                                         bootstrap=True,
                                         inc_raw=True), dict)

        # No sub entities. This is for coverage, but won't error out.
        entity = [{'handle': 'test', 'roles': [
            'administrative', 'technical']}]

        self.assertIsInstance(obj.lookup(response={
            'handle': 'test',
            'ipVersion': 'v4',
            'startAddress': '74.125.225.229',
            'endAddress': '74.125.225.229',
            'entities': entity
        },
            asn_data=val['asn_data'],
            depth=1), dict)


class TestRDAPContact(TestCommon):

    def test__RDAPContact(self):

        self.assertRaises(InvalidEntityContactObject, _RDAPContact, 'a')

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/entity.json', 'r') as data_file:
            data = json.load(data_file)

        contact = _RDAPContact(data['vcardArray'][1])
        contact.parse()

        self.assertRaises(IndexError, contact._parse_phone, [])
        self.assertRaises(IndexError, contact._parse_role, [])
        self.assertRaises(IndexError, contact._parse_title, [])


class TestRDAPNetwork(TestCommon):

    def test__RDAPNetwork(self):

        self.assertRaises(InvalidNetworkObject, _RDAPNetwork, 'a')

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/rdap.json', 'r') as data_file:
            data = json.load(data_file)

        for key, val in data.items():
            network = _RDAPNetwork(val['response'])
            network.parse()

            tmp = val['response']
            del tmp['startAddress']
            network = _RDAPNetwork(tmp)
            self.assertRaises(InvalidNetworkObject, network.parse)

            network = _RDAPNetwork({})
            self.assertRaises(InvalidNetworkObject, network.parse)

            break


class TestRDAPEntity(TestCommon):

    def test__RDAPEntity(self):

        self.assertRaises(InvalidEntityObject, _RDAPEntity, 'abc')

        ent = _RDAPEntity({'abc': 'def'})
        self.assertRaises(InvalidEntityObject, ent.parse)

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/entity.json', 'r') as data_file:
            data = json.load(data_file)

        ent = _RDAPEntity(data)
        ent.parse()

        tmp = data
        del tmp['vcardArray']
        ent = _RDAPEntity(tmp)
        ent.parse()

        tmp = data
        del tmp['notices'][0]['description']
        ent = _RDAPEntity(tmp)
        ent.parse()
