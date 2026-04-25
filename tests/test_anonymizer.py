import pytest
from src.log_anonymizer.anonymizer import (
    AnonymizationConfig,
    AnonymizationMode,
    CustomEntityConfig,
    EntityConfig,
    LogAnonymizer,
    default_entity_configs,
)


def _make(entity_overrides: dict = None, custom: list = None, secret: str = "test-secret") -> LogAnonymizer:
    entities = default_entity_configs()
    if entity_overrides:
        for entity, cfg in entity_overrides.items():
            entities[entity] = cfg
    return LogAnonymizer(AnonymizationConfig(
        secret_key=secret,
        entities=entities,
        custom_entities=custom or [],
    ))


# ── replace mode ──────────────────────────────────────────────────────────────

def test_phone_replace():
    anon = _make({"PHONE_NUMBER": EntityConfig(mode=AnonymizationMode.REPLACE, label="<手机>")})
    result, detected = anon.anonymize("联系 13812345678 了解详情")
    assert "13812345678" not in result
    assert result == "联系 <手机> 了解详情"
    assert "PHONE_NUMBER" in detected


def test_email_replace():
    anon = _make({"EMAIL_ADDRESS": EntityConfig(mode=AnonymizationMode.REPLACE, label="<邮箱>")})
    result, _ = anon.anonymize("发送至 alice@example.com")
    assert "alice@example.com" not in result
    assert "<邮箱>" in result


def test_chinese_id_replace():
    anon = _make({"CHINESE_ID_NUMBER": EntityConfig(mode=AnonymizationMode.REPLACE, label="<证件>")})
    result, detected = anon.anonymize("证件: 110101199003077814")
    assert "110101199003077814" not in result
    assert "CHINESE_ID_NUMBER" in detected


def test_ip_replace():
    anon = _make({"IP_ADDRESS": EntityConfig(mode=AnonymizationMode.REPLACE, label="<IP>")})
    result, _ = anon.anonymize("来源 IP: 192.168.1.100")
    assert "192.168.1.100" not in result
    assert "<IP>" in result


# ── mask mode ─────────────────────────────────────────────────────────────────

def test_phone_mask_keeps_head_tail():
    anon = _make({"PHONE_NUMBER": EntityConfig(
        mode=AnonymizationMode.MASK, keep_head=3, keep_tail=4, mask_char="*"
    )})
    result, _ = anon.anonymize("手机 13812345678")
    assert result == "手机 138****5678"


def test_id_mask_keeps_head_tail():
    anon = _make({"CHINESE_ID_NUMBER": EntityConfig(
        mode=AnonymizationMode.MASK, keep_head=6, keep_tail=4, mask_char="*"
    )})
    result, _ = anon.anonymize("身份证: 110101199003077814")
    assert result == "身份证: 110101********14"


def test_credit_card_mask():
    anon = _make({"CREDIT_CARD": EntityConfig(
        mode=AnonymizationMode.MASK, keep_head=0, keep_tail=4, mask_char="*"
    )})
    result, _ = anon.anonymize("卡号 4111111111111111")
    assert result.endswith("1111")
    assert "4111111111111111" not in result


# ── pseudonymize mode ─────────────────────────────────────────────────────────

def test_pseudo_consistent():
    anon = _make({"PHONE_NUMBER": EntityConfig(
        mode=AnonymizationMode.PSEUDONYMIZE, token_prefix="TEL"
    )}, secret="fixed-key")
    r1, _ = anon.anonymize("电话 13812345678")
    r2, _ = anon.anonymize("再次联系 13812345678")
    # Both should produce the same token for the same phone number
    token1 = r1.split("电话 ")[1].strip()
    token2 = r2.split("再次联系 ")[1].strip()
    assert token1 == token2
    assert token1.startswith("[TEL_")


def test_pseudo_different_values_differ():
    anon = _make({"PHONE_NUMBER": EntityConfig(
        mode=AnonymizationMode.PSEUDONYMIZE, token_prefix="TEL"
    )}, secret="fixed-key")
    r1, _ = anon.anonymize("13800000001")
    r2, _ = anon.anonymize("13800000002")
    assert r1 != r2


def test_pseudo_different_keys_differ():
    cfg_a = EntityConfig(mode=AnonymizationMode.PSEUDONYMIZE, token_prefix="TEL")
    cfg_b = EntityConfig(mode=AnonymizationMode.PSEUDONYMIZE, token_prefix="TEL")
    anon_a = _make({"PHONE_NUMBER": cfg_a}, secret="key-a")
    anon_b = _make({"PHONE_NUMBER": cfg_b}, secret="key-b")
    r_a, _ = anon_a.anonymize("13812345678")
    r_b, _ = anon_b.anonymize("13812345678")
    assert r_a != r_b


# ── redact mode ───────────────────────────────────────────────────────────────

def test_redact():
    anon = _make({"EMAIL_ADDRESS": EntityConfig(mode=AnonymizationMode.REDACT)})
    result, _ = anon.anonymize("邮件 bob@test.com 已发送")
    assert "bob@test.com" not in result
    assert "[REDACTED]" in result


# ── disabled entity ───────────────────────────────────────────────────────────

def test_disabled_entity_not_touched():
    anon = _make({"EMAIL_ADDRESS": EntityConfig(enabled=False)})
    text = "邮件 keep@example.com 原样保留"
    result, detected = anon.anonymize(text)
    assert result == text
    assert "EMAIL_ADDRESS" not in detected


# ── custom entity ─────────────────────────────────────────────────────────────

def test_custom_entity_replace():
    custom = [CustomEntityConfig(
        name="员工工号",
        pattern=r"EMP\d{6}",
        config=EntityConfig(mode=AnonymizationMode.REPLACE, label="<工号>"),
    )]
    anon = _make(custom=custom)
    result, detected = anon.anonymize("操作员 EMP001234 执行了删除")
    assert "EMP001234" not in result
    assert "<工号>" in result
    assert "员工工号" in detected


def test_custom_entity_pseudo():
    custom = [CustomEntityConfig(
        name="订单号",
        pattern=r"ORD-\d{8}",
        config=EntityConfig(mode=AnonymizationMode.PSEUDONYMIZE, token_prefix="ORD"),
    )]
    anon = _make(custom=custom, secret="s3cr3t")
    r1, _ = anon.anonymize("订单 ORD-20240101")
    r2, _ = anon.anonymize("退款 ORD-20240101")
    assert "ORD-20240101" not in r1
    assert r1.split("订单 ")[1] == r2.split("退款 ")[1]  # same order → same token


def test_invalid_custom_pattern_skipped():
    """Malformed regex should not crash the anonymizer."""
    custom = [CustomEntityConfig(name="bad", pattern="[invalid(")]
    anon = _make(custom=custom)
    result, _ = anon.anonymize("some text")
    assert result == "some text"


# ── stats ─────────────────────────────────────────────────────────────────────

def test_stats():
    anon = _make()
    anon.reset_stats()
    anon.anonymize("联系 13900001234")
    anon.anonymize("系统正常启动")
    anon.anonymize("邮件 bob@test.com 已发送")
    assert anon.stats.total_lines == 3
    assert anon.stats.redacted_lines == 2
    assert anon.stats.entity_counts.get("PHONE_NUMBER", 0) == 1
    assert anon.stats.entity_counts.get("EMAIL_ADDRESS", 0) == 1


# ── clean text ────────────────────────────────────────────────────────────────

def test_clean_text_unchanged():
    anon = _make()
    text = "系统启动完成，所有服务运行正常"
    result, detected = anon.anonymize(text)
    assert result == text
    assert detected == []


def test_empty_text():
    anon = _make()
    result, detected = anon.anonymize("")
    assert result == ""
    assert detected == []
