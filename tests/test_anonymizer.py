import re
import pytest
from src.log_anonymizer.anonymizer import LogAnonymizer


@pytest.fixture(scope="module")
def anon():
    return LogAnonymizer(entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "CHINESE_ID_NUMBER"])


def test_chinese_phone_masked(anon):
    text = "请联系 13812345678 了解详情"
    result, detected = anon.anonymize(text)
    assert "13812345678" not in result
    assert "PHONE_NUMBER" in detected


def test_email_masked(anon):
    text = "发送报告至 alice@example.com 邮箱"
    result, detected = anon.anonymize(text)
    assert "alice@example.com" not in result
    assert "EMAIL_ADDRESS" in detected


def test_chinese_id_masked(anon):
    text = "身份证号码: 110101199003077814"
    result, detected = anon.anonymize(text)
    assert "110101199003077814" not in result
    assert "CHINESE_ID_NUMBER" in detected


def test_clean_text_unchanged(anon):
    text = "系统启动完成，所有服务运行正常"
    result, detected = anon.anonymize(text)
    assert result == text
    assert detected == []


def test_empty_text(anon):
    result, detected = anon.anonymize("")
    assert result == ""
    assert detected == []


def test_stats_accumulate(anon):
    anon.reset_stats()
    anon.anonymize("联系 13900001234")
    anon.anonymize("系统正常")
    anon.anonymize("邮件 bob@test.com")
    assert anon.stats.total_lines == 3
    assert anon.stats.redacted_lines == 2
