import json
import logging
from datetime import datetime
from typing import Any


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def safe_json_load(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def parse_timestamp(value: str) -> str | None:
    for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"]:
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            continue
    return None
