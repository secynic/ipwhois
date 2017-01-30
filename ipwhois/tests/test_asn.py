import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.net import Net
from ipwhois.asn import (ASNOrigin, ASN_WHOIS, ASN_HTTP, NetError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestASNOrigin(TestCommon):

    def test__ASNOrigin(self):

        self.assertRaises(NetError, ASNOrigin, 'a')

    def test__ASNOriginLookup(self):

        data_dir = path.dirname(__file__)

        with io.open(str(data_dir) + '/asn.json', 'r') as \
                data_file:
            data = json.load(data_file)

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = ASNOrigin(net)

            try:

                self.assertIsInstance(obj.lookup(asn=val['asn'],
                                                 inc_raw=True,
                                                 response=val['response']),
                                      dict)

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))

    def test__parse_fields(self):

        net = Net('74.125.225.229')
        obj = ASNOrigin(net)

        # No exception raised, but should provide code coverage for if regex
        # groups are messed up.
        tmp_dict = ASN_WHOIS['radb']['fields']
        tmp_dict['route'] = r'(route):[^\S\n]+(?P<val1>.+?)\n'
        obj._parse_fields(
            response="\nroute:        66.249.64.0/20\n",
            fields_dict=tmp_dict
        )

        obj._parse_fields(
            response="\nchanged:        noc@google.com 20110301\n",
            fields_dict=ASN_WHOIS['radb']['fields']
        )

        multi_net_response = (
            '\n\nroute:      66.249.64.0/20'
            '\ndescr:      Google'
            '\norigin:     AS15169'
            '\nnotify:     noc@google.com'
            '\nmnt-by:     MAINT-AS15169'
            '\nchanged:    noc@google.com 20110301'
            '\nsource:     RADB'
            '\n\nroute:      66.249.80.0/20'
            '\ndescr:      Google'
            '\norigin:     AS15169'
            '\nnotify:     noc@google.com'
            '\nmnt-by:     MAINT-AS15169'
            '\nchanged:    noc@google.com 20110301'
            '\nsource:     RADB'
            '\n\n'
        )
        obj._parse_fields(
            response=multi_net_response,
            fields_dict=ASN_WHOIS['radb']['fields']
        )

    def test__get_nets_radb(self):

        net = Net('74.125.225.229')
        obj = ASNOrigin(net)

        # No exception raised, but should provide code coverage for multiple
        # network scenarios and CIDR invalid IP ValueError.
        multi_net_response = (
            '\n\nroute:      66.249.64.0/20'
            '\ndescr:      Google'
            '\norigin:     AS15169'
            '\nnotify:     noc@google.com'
            '\nmnt-by:     MAINT-AS15169'
            '\nchanged:    noc@google.com 20110301'
            '\nsource:     RADB'
            '\n\nroute:      66.249.80.0/20'
            '\ndescr:      Google'
            '\norigin:     AS15169'
            '\nnotify:     noc@google.com'
            '\nmnt-by:     MAINT-AS15169'
            '\nchanged:    noc@google.com 20110301'
            '\nsource:     RADB'
            '\n\n'
        )
        obj._get_nets_radb(multi_net_response)
