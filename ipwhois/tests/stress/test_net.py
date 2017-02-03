import logging
from ipwhois.tests import TestCommon
from ipwhois.exceptions import (HTTPLookupError, HTTPRateLimitError)
from ipwhois.net import Net

LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
              '[%(funcName)s()] %(message)s')
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class TestNet(TestCommon):

    def test_get_http_json(self):
        from ipwhois.rdap import RIR_RDAP

        # Test for HTTPRateLimitError for up to 20 requests. Exits when raised.
        url = RIR_RDAP['lacnic']['ip_url'].format('200.57.141.161')
        result = Net('200.57.141.161')
        count = 20
        http_lookup_errors = 0
        while count > 0:
            log.debug('Attempts left: {0}'.format(str(count)))
            count -= 1
            try:
                self.assertRaises(HTTPRateLimitError, result.get_http_json,
                                  **dict(url=url, retry_count=0))
                break

            except AssertionError as e:
                if count == 0:
                    raise e
                else:
                    pass

            except HTTPLookupError as e:
                http_lookup_errors += 1
                if http_lookup_errors == 5:
                    raise Exception('HTTPLookupError has been raised 5 times. '
                                    'Likely cause is socket connection '
                                    'timeouts. Quitting test to avoid an '
                                    'endless loop.')
                continue
