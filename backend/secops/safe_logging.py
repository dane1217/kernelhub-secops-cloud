"""Structured operational metadata; never log exception text or request content."""
import json
import logging
from datetime import datetime, timezone


class SafeFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({"time": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
            "logger": record.name, "module": record.module, "function": record.funcName,
            "event": getattr(record, "event_code", "runtime_log"),
            "error_id": getattr(record, "error_id", None),
            "exception_type": record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None})


def configure():
    handler = logging.StreamHandler()
    handler.setFormatter(SafeFormatter())
    logging.basicConfig(level=logging.WARNING, handlers=[handler], force=True)
