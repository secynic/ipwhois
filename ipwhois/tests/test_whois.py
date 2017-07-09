import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.net import Net
from ipwhois.whois import (Whois, RIR_WHOIS, NetError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestWhois(TestCommon):

    def test_Whois(self):

        self.assertRaises(NetError, Whois, 'a')

    def test_lookup(self):

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/whois.json', 'r') as data_file:
            data = json.load(data_file)

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = Whois(net)

            try:

                self.assertIsInstance(obj.lookup(response=val['response'],
                                                 asn_data=val['asn_data'],
                                                 is_offline=True,
                                                 inc_raw=True),
                                      dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

    def test__parse_fields(self):

        net = Net('74.125.225.229')
        obj = Whois(net)

        # No exception raised, but should provide code coverage for if regex
        # groups are messed up.
        tmp_dict = RIR_WHOIS['arin']['fields']
        tmp_dict['name'] = r'(NetName):[^\S\n]+(?P<val1>.+?)\n'
        obj._parse_fields(
            response="\nNetName:        TEST\n",
            fields_dict=tmp_dict,
            dt_format=RIR_WHOIS['arin']['dt_format']
        )

        obj._parse_fields(
            response="\nUpdated:        2012-02-24\n",
            fields_dict=RIR_WHOIS['arin']['fields'],
            dt_format=RIR_WHOIS['arin']['dt_format']
        )

        log.debug('Testing field parse error. This should be followed by a '
                  'debug log.')
        obj._parse_fields(
            response='\nUpdated:        2012-02-244\n',
            fields_dict=RIR_WHOIS['arin']['fields'],
            dt_format=RIR_WHOIS['arin']['dt_format']
        )

    def test__get_nets_arin(self):

        net = Net('74.125.225.229')
        obj = Whois(net)

        # No exception raised, but should provide code coverage for multiple
        # network scenarios and CIDR invalid IP ValueError.
        multi_net_response = (
            '\n#\n\nNetRange:       74.125.0.0 - 74.125.255.255'
            '\nCIDR:           74.125.0.0/16\nNetName:        TEST'
            '\nCIDR:           74.125.1.256/24\nNetName:        TEST2'
            '\nNetRange:       74.125.1.0 - 74.125.1.0'
            '\n'
        )
        obj._get_nets_arin(multi_net_response)

    def test__get_nets_lacnic(self):

        net = Net('200.57.141.161')
        obj = Whois(net)

        # No exception raised, but should provide code coverage for inetnum
        # invalid IP ValueError.
        multi_net_response = (
            '\ninetnum:     200.57.256/19\r\n'
            '\n'
        )
        obj._get_nets_lacnic(multi_net_response)

    def test__get_nets_other(self):

        net = Net('210.107.73.73')
        obj = Whois(net)

        # No exception raised, but should provide code coverage for inetnum
        # invalid IP ValueError.
        multi_net_response = (
            '\ninetnum:        210.107.0.0 - 210.107.127.256\n'
            '\n'
        )
        obj._get_nets_other(multi_net_response)
