import pytest
from src.log_anonymizer.parser import parse_line, parse_lines


def test_json_log():
    line = '{"time": "2024-01-01 12:00:00", "service": "auth", "msg": "user login"}'
    result = parse_line(line)
    assert result["service"] == "auth"
    assert result["msg"] == "user login"


def test_json_log_alternate_keys():
    line = '{"@timestamp": "2024-01-01T12:00:00Z", "app": "payment", "message": "charge ok"}'
    result = parse_line(line)
    assert result["service"] == "payment"
    assert result["msg"] == "charge ok"


def test_standard_grok():
    line = "2024-01-01T12:00:00 [INFO] [order-service] - Order placed successfully"
    result = parse_line(line)
    assert result["service"] == "order-service"
    assert "Order placed" in result["msg"]
    assert result["level"] in ("INFO", "UNKNOWN")


def test_fallback_plain_text():
    line = "something went wrong"
    result = parse_line(line)
    assert result["msg"] == "something went wrong"


def test_empty_line():
    result = parse_line("   ")
    assert result == {}


def test_parse_lines_skips_empty():
    lines = ["", "  ", '{"msg": "hello"}', ""]
    results = parse_lines(lines)
    assert len(results) == 1
    assert results[0]["msg"] == "hello"
