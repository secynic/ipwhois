import unittest
import logging
import os
import simplejson

from ipwhois import (IPWhois, ripe)

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)



class TestRipe(unittest.TestCase):
    """ Test for various providers.
    """
    def setUp(self):
        # The following ip is just given to
        #  create the IPWhois object.
        #  We are only interested to run the
        #  _lookup_rws_ripe method.
        self.iw = IPWhois('62.239.237.1')

    def test_lookup_rws_bt(self):
        # Informations are taken from the whois response.
        self.lookup_rws_ripe("ripe-bt.json", expected={
            'abuse_emails': 'protect@bt.com',
            'handle': 'BCER1-RIPE',
            'address': 'British Telecommunications\n81 Newgate Street\nLondon GB\nBritish Telecommunications\n81 Newgate Street\nLondon GB',
        })

    def test_lookup_rws_ti(self):
        # Informations are taken from:
        #   - the whois response;
        #   - further admin-c, abuse-c requests.
        self.lookup_rws_ripe("ripe-ti.json", expected={
            'abuse_emails': 'abuse-ripe@telecomitalia.it',
            'handle': 'CM2687-RIPE'
        })

    def lookup_rws_ripe(self, fpath, expected=None):
        """Test the ripe parser without actually contacting
            the internet.
        """
        assert expected, "Specify the expected fields!"
        with open(os.path.join('tests', fpath)) as fh:
            ripe_data = simplejson.load(fh)

        ret = self.iw._lookup_rws_ripe(ripe_data)[0]
        assert ret
        log.debug("Returned entry: %r", ret)
        for k, v in expected.items():
            assert ret[k] == v

    def test_get_role(self):
        fpath = 'ripe-ti.role.json'
        with open(os.path.join('tests', fpath)) as fh:
            ripe_data = simplejson.load(fh)

        abuse_mailbox = ripe.get_attribute(ripe_data, 'abuse-mailbox')
        assert abuse_mailbox == "abuse-ripe@telecomitalia.it"