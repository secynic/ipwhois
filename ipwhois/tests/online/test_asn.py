import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (ASNOriginLookupError, ASNRegistryError)
from ipwhois.net import Net
from ipwhois.asn import IPASN
from ipwhois.asn import ASNOrigin as ASNOriginOld
import ipwhois.ASNOrigin as ASNOrigin

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestIPASN(TestCommon):

    def test_lookup(self):

        net = Net('74.125.225.229')
        ipasn = IPASN(net)

        try:
            self.assertIsInstance(ipasn.lookup(inc_raw=True), dict)
        except ASNRegistryError:
            pass
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        self.assertRaises(ValueError, ipasn.lookup, **dict(
            asn_methods=['asd']))

        ipasn.lookup(asn_methods=['dns', 'whois', 'http'])
        ipasn.lookup(asn_methods=['http'])

        net = Net(address='74.125.225.229', timeout=0,
                  allow_permutations=False)
        ipasn = IPASN(net)
        self.assertRaises(ASNRegistryError, ipasn.lookup)

        net = Net(address='74.125.225.229', timeout=0,
                  allow_permutations=True)
        ipasn = IPASN(net)
        self.assertRaises(ASNRegistryError, ipasn.lookup, **dict(
            asn_alts=['http']))


class TestASNOrigin(TestCommon):

    def test_lookup(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/asn.json', 'r') as \
                data_file:
            data = json.load(data_file)

        # IP doesn't matter here
        net = Net('74.125.225.229')

        for key, val in data.items():

            log.debug('Testing: {0} - {1}'.format(key, val['asn']))

            obj = ASNOriginOld(net)
            try:

                self.assertIsInstance(
                    obj.lookup(
                        asn=val['asn']
                    ),
                    dict
                )

            except ASNOriginLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

        net = Net(address='74.125.225.229', timeout=0,
                  allow_permutations=True)
        asnorigin = ASNOriginOld(net)

        try:
            self.assertRaises(ASNOriginLookupError, asnorigin.lookup, **dict(
                asn='15169',
                asn_alts=['http']))
        except AssertionError as e:
            raise self.failureException('{}; This is supposed to fail after remove ASNOrigin class.'.format(e))

        try:

            self.assertRaises(ValueError, asnorigin.lookup, **dict(
                asn='15169',
                asn_methods=['asd']))
        except AssertionError as e:
            raise self.failureException('{}; This is supposed to fail after remove ASNOrigin class.'.format(e))

        net = Net(address='74.125.225.229')
        asnorigin = ASNOriginOld(net)
        asnorigin.lookup(asn='15169', asn_methods=['whois', 'http'])

    def test_lookup_new(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/asn.json', 'r') as \
                data_file:
            data = json.load(data_file)

        for key, val in data.items():

            log.debug('Testing: {0} - {1}'.format(key, val['asn']))

            try:

                self.assertIsInstance(
                    ASNOrigin.lookup(
                        asn=val['asn']
                    ),
                    dict
                )

            except ASNOriginLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

        self.assertRaises(ASNOriginLookupError, ASNOrigin.lookup, **dict(
            asn='15169',
            asn_alts=['http'],
            timeout=0))

        self.assertRaises(ValueError, ASNOrigin.lookup, **dict(
            asn='15169',
            asn_methods=['asd'],
            timeout=0))

        ASNOrigin.lookup(asn='15169', asn_methods=['whois', 'http'])