import json
import io
from os import path
import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import WhoisLookupError
from ipwhois.net import Net
from ipwhois.asn import ASNOrigin

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestASNWhois(TestCommon):

    def test__TestASNOriginLookup(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/asn.json', 'r') as \
                data_file:
            data = json.load(data_file)

        # IP doesn't matter here
        net = Net('74.125.225.229')

        for key, val in data.items():

            log.debug('Testing: {0} - {1}'.format(key, val['asn']))

            obj = ASNOrigin(net)
            try:

                self.assertIsInstance(
                    obj.lookup(
                        asn=val['asn']
                    ),
                    dict
                )

            except WhoisLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))
