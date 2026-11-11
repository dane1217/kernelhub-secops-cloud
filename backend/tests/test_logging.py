import logging
import unittest
from secops.safe_logging import SafeFormatter


class LogRedaction(unittest.TestCase):
    def test_exception_and_message_secrets_are_not_rendered(self):
        exc = ValueError("password=secret-123")
        record = logging.LogRecord("secops",logging.ERROR,"test",1,"Authorization: secret-123",(),(ValueError,exc,None))
        record.error_id = "safe-error-id"
        value = SafeFormatter().format(record)
        self.assertNotIn("secret-123",value)
        self.assertIn("ValueError",value)
        self.assertIn("safe-error-id",value)
