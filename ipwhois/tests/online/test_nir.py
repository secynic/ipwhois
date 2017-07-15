import json
import io
from os import path
import logging
from ipwhois.exceptions import HTTPLookupError
from ipwhois.tests import TestCommon
from ipwhois.net import Net
from ipwhois.nir import NIRWhois

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestNIRWhois(TestCommon):

    def test_lookup(self):

        data_dir = path.abspath(path.join(path.dirname(__file__), '..'))

        with io.open(str(data_dir) + '/jpnic.json', 'r') as data_jpnic:
            data = json.load(data_jpnic)

        with io.open(str(data_dir) + '/krnic.json', 'r') as data_krnic:
            data.update(json.load(data_krnic))

        for key, val in data.items():

            log.debug('Testing: {0}'.format(key))
            net = Net(key)
            obj = NIRWhois(net)

            try:

                self.assertIsInstance(
                    obj.lookup(
                        nir=val['nir'],
                    ),
                    dict
                )

            except HTTPLookupError:

                pass

            except AssertionError as e:

                raise e

            except Exception as e:

                self.fail('Unexpected exception raised: {0}'.format(e))
