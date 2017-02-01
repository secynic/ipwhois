import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (ASNRegistryError, ASNLookupError,
                                ASNParseError)
from ipwhois.net import Net
from ipwhois.asn import (IPASN, ASNOrigin, ASN_ORIGIN_WHOIS, ASN_ORIGIN_HTTP,
                         NetError)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestIPASN(TestCommon):

    def test__IPASN(self):

        self.assertRaises(NetError, IPASN, 'a')

    def test__parse_fields_dns(self):

        data = '"15169 | 74.125.225.0/24 | US | arin | 2007-03-13"'
        net = Net('74.125.225.229')
        ipasn = IPASN(net)
        try:
            self.assertIsInstance(ipasn._parse_fields_dns(data), dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data = '"15169 | 74.125.225.0/24 | US | random | 2007-03-13"'
        self.assertRaises(ASNRegistryError, ipasn._parse_fields_dns, data)

        data = ''
        self.assertRaises(ASNParseError, ipasn._parse_fields_dns, data)

    def test__parse_fields_whois(self):

        data = ('15169   | 74.125.225.229   | 74.125.225.0/24     | US | arin'
                '     | 2007-03-13')
        net = Net('74.125.225.229')
        ipasn = IPASN(net)
        try:
            self.assertIsInstance(ipasn._parse_fields_whois(data), dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data = ('15169   | 74.125.225.229   | 74.125.225.0/24     | US | rdm'
                '     | 2007-03-13')
        self.assertRaises(ASNRegistryError, ipasn._parse_fields_whois, data)

        data = '15169   | 74.125.225.229   | 74.125.225.0/24     | US'
        self.assertRaises(ASNParseError, ipasn._parse_fields_whois, data)

    def test__parse_fields_http(self):

        data = {
            'nets': {
                'net': {
                    'orgRef': {
                        '@handle': 'APNIC'
                    }
                }
            }
        }
        net = Net('1.2.3.4')
        ipasn = IPASN(net)
        try:
            self.assertIsInstance(ipasn._parse_fields_http(response=data),
                                  dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data['nets']['net']['orgRef']['@handle'] = 'RIPE'
        try:
            self.assertIsInstance(ipasn._parse_fields_http(response=data),
                                  dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data['nets']['net']['orgRef']['@handle'] = 'DNIC'
        try:
            self.assertIsInstance(ipasn._parse_fields_http(response=data),
                                  dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data['nets']['net']['orgRef']['@handle'] = 'INVALID'
        try:
            self.assertRaises(ASNRegistryError, ipasn._parse_fields_http,
                              response=data)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

        data = ''
        try:
            self.assertIsInstance(ipasn._parse_fields_http(response=data), dict)
        except AssertionError as e:
            raise e
        except Exception as e:
            self.fail('Unexpected exception raised: {0}'.format(e))

    def test__IPASNLookup(self):
        # TODO: need to modify asn.json for this.
        return NotImplemented


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
        tmp_dict = ASN_ORIGIN_WHOIS['radb']['fields']
        tmp_dict['route'] = r'(route):[^\S\n]+(?P<val1>.+?)\n'
        obj._parse_fields(
            response="\nroute:        66.249.64.0/20\n",
            fields_dict=tmp_dict
        )

        obj._parse_fields(
            response="\nchanged:        noc@google.com 20110301\n",
            fields_dict=ASN_ORIGIN_WHOIS['radb']['fields']
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
            fields_dict=ASN_ORIGIN_WHOIS['radb']['fields']
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
