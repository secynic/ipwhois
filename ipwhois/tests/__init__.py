import unittest


class TestCommon(unittest.TestCase):
    longMessage = False

    # Python 2.6 doesn't have unittest._formatMessage or
    # unittest.util.safe_repr
    # Borrowed and modified both functions from Python 2.7.
    if not hasattr(unittest.TestCase, '_formatMessage'):
        def safe_repr(self, obj, short=False):
            try:
                result = repr(obj)
            except Exception:
                result = object.__repr__(obj)
            if not short or len(result) < 80:
                return result
            return result[:80] + ' [truncated]...'

        def _formatMessage(self, msg, standardMsg):
            if not self.longMessage:
                return msg or standardMsg
            if msg is None:
                return standardMsg
            try:
                return '{0} : {0}'.format(standardMsg, msg)
            except UnicodeDecodeError:
                return '{0} : {0}'.format(self.safe_repr(standardMsg),
                                          self.safe_repr(msg))

    if not hasattr(unittest.TestCase, 'assertIsInstance'):
        def assertIsInstance(self, obj, cls, msg=None):
            if not isinstance(obj, cls):
                self.fail(self._formatMessage(
                    msg,
                    '{0} is not an instance of {1}'.format(obj, cls)
                ))
