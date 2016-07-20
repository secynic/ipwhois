import json
import io
from os import path
import logging
from ipwhois.exceptions import NetError
from ipwhois.tests import TestCommon
from ipwhois.net import Net
from ipwhois.nir import (NIR_WHOIS, NIRWhois)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestNIR(TestCommon):

    def test__NIRWhoisLookup(self):

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/jpnic.json', 'r') as data_jpnic:
            data = json.load(data_jpnic)

        with io.open(str(data_dir) + '/krnic.json', 'r') as data_krnic:
            data.update(json.load(data_krnic))

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = NIRWhois(net)

            self.assertRaises(KeyError, obj.lookup,
                              **dict(nir=val['nir'], response=None,
                                     is_offline=True)
                              )

            try:

                self.assertIsInstance(obj.lookup(
                                                nir=val['nir'],
                                                response=val['response'],
                                                is_offline=True,
                                                inc_raw=True),
                                      dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

        self.assertRaises(NetError, NIRWhois, 'a')
        self.assertRaises(KeyError, obj.lookup)
        self.assertRaises(KeyError, obj.lookup, **dict(nir='a'))

    def test__parse_fields(self):

        net = Net('133.1.2.5')
        obj = NIRWhois(net)

        # No exception raised, but should provide code coverage for if regex
        # groups are messed up.
        tmp_dict = NIR_WHOIS['jpnic']['fields']
        tmp_dict['name'] = r'(NetName):[^\S\n]+(?P<val1>.+?)\n'
        obj._parse_fields(
            response="\nNetName:        TEST\n",
            fields_dict=tmp_dict,
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

        obj._parse_fields(
            response="\nUpdated:        2012-02-24\n",
            fields_dict=NIR_WHOIS['jpnic']['fields'],
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

        log.debug(
            'Testing field parse error. This should be followed by a '
            'debug log.')
        obj._parse_fields(
            response="\nUpdated:        2012-02-244\n",
            fields_dict=NIR_WHOIS['jpnic']['fields'],
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

    def test__get_nets_jpnic(self):
        # TODO: this
        return

    def test__get_nets_krnic(self):
        # TODO: this
        return

    def test__get_contact(self):
        # TODO: this
        return
