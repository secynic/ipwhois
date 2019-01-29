import unittest


class TestCommon(unittest.TestCase):
    longMessage = False

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '{0} is not an instance of {1}'.format(obj, cls)
                ))
