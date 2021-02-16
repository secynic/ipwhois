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


class TestNIRWhois(TestCommon):

    def test_lookup(self):

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

                self.assertIsInstance(obj.lookup(
                    nir=val['nir'],
                    response=val['response']),
                    dict)

            except AssertionError as e:

                raise e

        self.assertRaises(NetError, NIRWhois, 'a')
        self.assertRaises(KeyError, obj.lookup)
        self.assertRaises(KeyError, obj.lookup, **dict(nir='a'))

    def test_parse_fields(self):

        net = Net('133.1.2.5')
        obj = NIRWhois(net)

        # No exception raised, but should provide code coverage for if regex
        # groups are messed up.
        tmp_dict = NIR_WHOIS['jpnic']['fields']
        tmp_dict['name'] = r'(NetName):[^\S\n]+(?P<val1>.+?)\n'
        obj.parse_fields(
            response='\nNetName:        TEST\n',
            fields_dict=tmp_dict,
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

        obj.parse_fields(
            response='\nUpdated:        2012-02-24\n',
            fields_dict=NIR_WHOIS['jpnic']['fields'],
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

        log.debug(
            'Testing field parse error. This should be followed by a '
            'debug log.')
        obj.parse_fields(
            response='\nUpdated:        2012-02-244\n',
            fields_dict=NIR_WHOIS['jpnic']['fields'],
            dt_format=NIR_WHOIS['jpnic']['dt_format']
        )

    def test_get_nets_jpnic(self):

        net = Net('133.1.2.5')
        obj = NIRWhois(net)

        # No exception raised, but should provide code coverage for multiple
        # network scenarios and CIDR invalid IP ValueError.
        multi_net_response = (
            'a. [Network Number] asd>133.1.0.0/16</A>'
            'a. [Network Number] asd>133.1.0.0/24</A>'
        )
        obj.get_nets_jpnic(multi_net_response)

        self.assertFalse(obj.get_nets_jpnic(
            'a. [Network Number] asd>asd/16</A>'
        ))

    def test__get_nets_krnic(self):

        net = Net('115.1.2.3')
        obj = NIRWhois(net)

        # No exception raised, but should provide code coverage for multiple
        # network scenarios and CIDR invalid IP ValueError.
        multi_net_response = (
            'IPv4 Address       : 115.0.0.0 - 115.23.255.255 (/12+/13)'
            'IPv4 Address       : 115.1.2.0 - 115.1.2.63 (/26)'
        )
        obj.get_nets_krnic(multi_net_response)

        # ip_network ValueError
        self.assertFalse(obj.get_nets_krnic(
            'IPv4 Address       : asd - asd (/12+/13)'
        ))

        # Expected IP range regex not found, but some value found
        self.assertFalse(obj.get_nets_krnic(
            'IPv4 Address       : asd'
        ))

    def test_get_contact(self):

        net = Net('115.1.2.3')
        obj = NIRWhois(net)

        contact_response = (
            'Name               : IP Manager'
            'Phone              : +82-2-500-6630'
            'E-Mail             : kornet_ip@kt.com'
        )

        # No exception raised.
        obj.get_contact(
            response=contact_response,
            handle=None,
            nir='krnic',
            dt_format=NIR_WHOIS['krnic']['dt_format']
        )
