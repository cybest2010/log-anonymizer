import json
import logging
from typing import Optional
from pygrok import Grok
from .models import LogModel

logger = logging.getLogger(__name__)

# Ordered list of patterns to try, most specific first
_GROK_PATTERNS = [
    # Standard: 2024-01-01 12:00:00 [INFO] [service] - message
    r"%{TIMESTAMP_ISO8601:time}\s+\[?%{LOGLEVEL:level}\]?\s+\[%{DATA:service}\]\s+-\s+%{GREEDYDATA:msg}",
    # Spring Boot: 2024-01-01 12:00:00.000  INFO 12345 --- [thread] service : message
    r"%{TIMESTAMP_ISO8601:time}\s+%{LOGLEVEL:level}\s+%{NUMBER}\s+---\s+\[%{DATA}\]\s+%{DATA:service}\s*:\s*%{GREEDYDATA:msg}",
    # Logback default: 12:00:00.000 [thread] INFO  service - message
    r"%{TIME:time}\s+\[%{DATA}\]\s+%{LOGLEVEL:level}\s+%{DATA:service}\s+-\s+%{GREEDYDATA:msg}",
    # Nginx/Apache: [01/Jan/2024:12:00:00 +0000] "GET /path HTTP/1.1" 200
    r'\[%{HTTPDATE:time}\]\s+"%{WORD} %{URIPATHPARAM:msg} HTTP/%{NUMBER}"\s+%{NUMBER:level}',
    # Syslog: Jan  1 12:00:00 hostname service[pid]: message
    r"%{SYSLOGTIMESTAMP:time}\s+%{HOSTNAME}\s+%{DATA:service}\[%{NUMBER}\]:\s+%{GREEDYDATA:msg}",
    # Simple: LEVEL message (no timestamp)
    r"%{LOGLEVEL:level}\s+%{GREEDYDATA:msg}",
]

_compiled: list[Grok] = []


def _get_compiled_patterns() -> list[Grok]:
    global _compiled
    if not _compiled:
        _compiled = [Grok(p) for p in _GROK_PATTERNS]
    return _compiled


def parse_line(line: str) -> dict:
    """Parse a single log line. Returns a dict with at least a 'msg' key.

    The returned dict includes a '_parse_method' key: 'json' | 'grok' | 'fallback'.
    """
    line = line.strip()
    if not line:
        return {}

    # Try JSON first
    if line.startswith("{"):
        try:
            raw = json.loads(line)
            result = LogModel.model_validate(raw).model_dump()
            result["_parse_method"] = "json"
            return result
        except (json.JSONDecodeError, ValueError) as exc:
            logger.debug("JSON parse failed: %s", exc)

    # Try Grok patterns in order
    for pattern in _get_compiled_patterns():
        try:
            match = pattern.match(line)
        except Exception as exc:
            logger.debug("Grok match error: %s", exc)
            continue
        if match:
            raw = {k: v for k, v in match.items() if v is not None}
            result = LogModel.model_validate(raw).model_dump()
            result["_parse_method"] = "grok"
            return result

    # Fallback: treat entire line as message
    result = LogModel.model_validate({"msg": line}).model_dump()
    result["_parse_method"] = "fallback"
    return result


def parse_lines(lines: list[str]) -> list[dict]:
    """Parse multiple log lines, skipping empty ones."""
    results = []
    for line in lines:
        parsed = parse_line(line)
        if parsed:
            results.append(parsed)
    return results
