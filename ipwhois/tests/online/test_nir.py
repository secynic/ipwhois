import logging
from ipwhois.tests import TestCommon
from ipwhois.net import (Net)
from ipwhois.nir import (NIRWhois)

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestNIR(TestCommon):

    def test__NIRWhoisLookup(self):

        net = Net('133.1.2.5')
        obj = NIRWhois(net)

        # TODO: replace with assertion test
        log.debug(obj.lookup('jpnic'))

        net = Net('115.1.2.3')
        obj = NIRWhois(net)

        # TODO: replace with assertion test
        log.debug(obj.lookup('krnic'))
