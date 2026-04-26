"""
Three-layer PII anonymization engine.

  Layer 1 — Regex pre-filter   : phone, email, IP, credit card, Chinese ID
                                  High confidence, zero NLP cost.
  Layer 2 — NER model          : person names  (HanLP > spaCy fallback)
  Layer 3 — Custom entities    : user-defined regex patterns

Anonymization modes (per entity):
  replace      — fixed label,   e.g.  <手机>
  mask         — partial hide,  e.g.  138****5678
  pseudonymize — HMAC token,    e.g.  [TEL_a3f2b1c0]  (consistent, key-bound)
  redact       — full hide,     e.g.  [REDACTED]
"""

import re
import hmac
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ── Modes ─────────────────────────────────────────────────────────────────────

class AnonymizationMode(str, Enum):
    REPLACE      = "replace"
    MASK         = "mask"
    PSEUDONYMIZE = "pseudo"
    REDACT       = "redact"


# ── Per-entity config ─────────────────────────────────────────────────────────

@dataclass
class EntityConfig:
    enabled:      bool               = True
    mode:         AnonymizationMode  = AnonymizationMode.REPLACE
    # replace / redact
    label:        str                = ""   # auto-set from defaults if empty
    # mask
    mask_char:    str                = "*"
    keep_head:    int                = 3    # show first N chars
    keep_tail:    int                = 4    # show last N chars
    # pseudonymize
    token_prefix: str                = ""   # auto-set from defaults if empty


@dataclass
class CustomEntityConfig:
    """User-defined regex-based entity rule."""
    name:    str                              # display name, e.g. "员工工号"
    pattern: str                              # regex, e.g. r"EMP\d{6}"
    config:  EntityConfig = field(default_factory=EntityConfig)


# ── Built-in defaults ─────────────────────────────────────────────────────────

ALL_ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "CREDIT_CARD",
    "CHINESE_ID_NUMBER",
    "UNIFIED_SOCIAL_CREDIT_CODE",
]

_DEFAULT_LABELS: dict[str, str] = {
    "PERSON":                    "<姓名>",
    "PHONE_NUMBER":              "<手机>",
    "EMAIL_ADDRESS":             "<邮箱>",
    "IP_ADDRESS":                "<IP>",
    "CREDIT_CARD":               "<卡号>",
    "CHINESE_ID_NUMBER":         "<证件>",
    "UNIFIED_SOCIAL_CREDIT_CODE":"<企业代码>",
}

_DEFAULT_PREFIXES: dict[str, str] = {
    "PERSON":                    "USR",
    "PHONE_NUMBER":              "TEL",
    "EMAIL_ADDRESS":             "MAIL",
    "IP_ADDRESS":                "IP",
    "CREDIT_CARD":               "CARD",
    "CHINESE_ID_NUMBER":         "ID",
    "UNIFIED_SOCIAL_CREDIT_CODE":"ORG",
}

# (keep_head, keep_tail) defaults for mask mode
_DEFAULT_MASK: dict[str, tuple[int, int]] = {
    "PERSON":                    (0, 0),
    "PHONE_NUMBER":              (3, 4),   # 138****5678
    "EMAIL_ADDRESS":             (1, 0),   # a*****@***
    "IP_ADDRESS":                (0, 0),
    "CREDIT_CARD":               (0, 4),   # ************1234
    "CHINESE_ID_NUMBER":         (6, 4),   # 110101********14
    "UNIFIED_SOCIAL_CREDIT_CODE":(4, 4),   # 9111****3939M
}


def default_entity_configs() -> dict[str, EntityConfig]:
    out: dict[str, EntityConfig] = {}
    for e in ALL_ENTITIES:
        head, tail = _DEFAULT_MASK.get(e, (0, 0))
        out[e] = EntityConfig(
            label        = _DEFAULT_LABELS.get(e, f"<{e}>"),
            token_prefix = _DEFAULT_PREFIXES.get(e, "PII"),
            keep_head    = head,
            keep_tail    = tail,
        )
    return out


# ── Global anonymization config ───────────────────────────────────────────────

@dataclass
class AnonymizationConfig:
    secret_key:      str                        = "change-me-in-production"
    entities:        dict[str, EntityConfig]    = field(default_factory=default_entity_configs)
    custom_entities: list[CustomEntityConfig]   = field(default_factory=list)


# ── Layer 1: Regex pre-filter ─────────────────────────────────────────────────

_REGEX_PATTERNS: dict[str, re.Pattern] = {
    "PHONE_NUMBER": re.compile(
        r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"
    ),
    "EMAIL_ADDRESS": re.compile(
        r"[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:\d[ \-]?){15,16}\b"
    ),
    "CHINESE_ID_NUMBER": re.compile(
        r"\b\d{17}[\dXx]\b"
    ),
    # 统一社会信用代码: 登记部门(1) + 机构类别(1) + 行政区划码(6) + 主体标识码(9) + 校验码(1) = 18位
    "UNIFIED_SOCIAL_CREDIT_CODE": re.compile(
        r"\b[0-9A-HJ-NP-RT-Y]{2}\d{6}[0-9A-HJ-NP-RT-Y]{9}[0-9A-HJ-NP-RT-YXx]\b"
    ),
}

# Base64 blob detection — truncate long base64 strings to keep logs readable
_BASE64_BLOB: re.Pattern = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def _truncate_base64(text: str) -> tuple[str, int]:
    """Truncate long Base64 blobs. Returns (new_text, replacement_count)."""
    def _repl(m: re.Match) -> str:
        val = m.group()
        return f"{val[:20]}...[base64 已截断, 原长 {len(val)} 字节]"
    return _BASE64_BLOB.subn(_repl, text)


# JSON structured field patterns — match name values inside JSON key-value pairs
# Group 1 = key portion (preserved), Group 2 = name value (to be anonymized)
# Handles: "name":"张三", "姓名":"张三", "realName":"张三", "userName":"张三" etc.
_JSON_NAME_PATTERN: re.Pattern = re.compile(
    r'("(?:name|姓名|realName|userName|operatorName|staffName|applicantName)"\s*:\s*")'
    r'([\u4e00-\u9fa5a-zA-Z][\u4e00-\u9fa5a-zA-Z\s]{0,9})'
    r'(?=")'
)

# Entities NOT handled by regex (handled by NER)
_NER_ENTITIES = {"PERSON"}


# ── Layer 2: NER — HanLP (primary) → spaCy (fallback) ────────────────────────

_ner_backend: Optional[str] = None   # "hanlp" | "spacy" | "none"
_hanlp_model = None
_spacy_model = None


def _init_ner() -> str:
    global _ner_backend, _hanlp_model, _spacy_model
    if _ner_backend is not None:
        return _ner_backend

    try:
        import hanlp
        _hanlp_model = hanlp.load(
            hanlp.pretrained.mtl.CLOSE_TOK_POS_NER_SRL_DEP_SDP_CON_ELECTRA_SMALL_ZH,
            tasks="ner/msra",
        )
        _ner_backend = "hanlp"
        logger.info("NER backend: HanLP (ELECTRA-small)")
        return _ner_backend
    except Exception as exc:
        logger.warning("HanLP unavailable (%s), trying spaCy ...", exc)

    try:
        import spacy
        _spacy_model = spacy.load("zh_core_web_sm")
        _ner_backend = "spacy"
        logger.info("NER backend: spaCy zh_core_web_sm")
        return _ner_backend
    except Exception as exc:
        logger.warning("spaCy unavailable (%s) — PERSON detection disabled.", exc)

    _ner_backend = "none"
    return _ner_backend


def _ner_persons(text: str) -> list[str]:
    """Return distinct person-name strings found in *text*."""
    backend = _init_ner()

    if backend == "hanlp" and _hanlp_model is not None:
        try:
            doc = _hanlp_model(text)
            return list({
                mention
                for sent_ner in doc.get("ner/msra", [])
                for mention, etype, *_ in sent_ner
                if etype == "PERSON"
            })
        except Exception as exc:
            logger.warning("HanLP NER error: %s", exc)
            return []

    if backend == "spacy" and _spacy_model is not None:
        try:
            return list({ent.text for ent in _spacy_model(text).ents if ent.label_ == "PERSON"})
        except Exception as exc:
            logger.warning("spaCy NER error: %s", exc)
            return []

    return []


# ── Anonymization helpers ─────────────────────────────────────────────────────

def _apply(value: str, entity: str, cfg: EntityConfig, secret: bytes) -> str:
    mode = cfg.mode

    if mode == AnonymizationMode.REDACT:
        return "[REDACTED]"

    if mode == AnonymizationMode.REPLACE:
        return cfg.label or _DEFAULT_LABELS.get(entity, f"<{entity}>")

    if mode == AnonymizationMode.MASK:
        n = len(value)
        head = min(cfg.keep_head, n)
        tail = min(cfg.keep_tail, n - head)
        hidden = max(0, n - head - tail)
        return value[:head] + cfg.mask_char * hidden + (value[-tail:] if tail else "")

    if mode == AnonymizationMode.PSEUDONYMIZE:
        token  = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        prefix = cfg.token_prefix or _DEFAULT_PREFIXES.get(entity, "PII")
        return f"[{prefix}_{token}]"

    return value  # fallback


# ── Stats ─────────────────────────────────────────────────────────────────────

@dataclass
class AnonymizationStats:
    total_lines:   int             = 0
    redacted_lines: int            = 0
    entity_counts: dict[str, int]  = field(default_factory=dict)

    def record(self, entities: list[str]) -> None:
        self.total_lines += 1
        if entities:
            self.redacted_lines += 1
            for e in entities:
                self.entity_counts[e] = self.entity_counts.get(e, 0) + 1


# ── Main anonymizer ───────────────────────────────────────────────────────────

class LogAnonymizer:
    def __init__(self, config: Optional[AnonymizationConfig] = None):
        self.config = config or AnonymizationConfig()
        self._secret = self.config.secret_key.encode("utf-8")
        self.stats   = AnonymizationStats()

        # Compile custom patterns once
        self._custom: list[tuple[str, re.Pattern, EntityConfig]] = []
        for ce in self.config.custom_entities:
            try:
                self._custom.append((ce.name, re.compile(ce.pattern), ce.config))
            except re.error as exc:
                logger.warning("Invalid custom pattern %r: %s", ce.pattern, exc)

        # Pre-warm NER if PERSON is enabled
        if self._enabled("PERSON"):
            _init_ner()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _enabled(self, entity: str) -> bool:
        cfg = self.config.entities.get(entity)
        return cfg is not None and cfg.enabled

    def _cfg(self, entity: str) -> EntityConfig:
        return self.config.entities.get(entity, EntityConfig())

    # ── main entry point ─────────────────────────────────────────────────────

    def anonymize(self, text: str) -> tuple[str, list[str]]:
        """Return (anonymized_text, detected_entity_types)."""
        if not text:
            return text, []

        detected: list[str] = []

        # ── Pre-processing: truncate base64 blobs ─────────────────────────────
        text, _n_b64 = _truncate_base64(text)

        # ── Layer 1: regex ────────────────────────────────────────────────────
        for entity, pattern in _REGEX_PATTERNS.items():
            if not self._enabled(entity):
                continue
            cfg = self._cfg(entity)

            def _repl(m: re.Match, e=entity, c=cfg) -> str:
                return _apply(m.group(), e, c, self._secret)

            new_text, n = pattern.subn(_repl, text)
            if n:
                text = new_text
                detected.append(entity)

        # ── Layer 1b: JSON name fields ────────────────────────────────────────
        # Handles "name":"张三" patterns that NER models often miss in log context
        if self._enabled("PERSON"):
            cfg = self._cfg("PERSON")

            def _repl_json_name(m: re.Match) -> str:
                # Group 1 = key part (keep), Group 2 = name value (anonymize)
                return m.group(1) + _apply(m.group(2), "PERSON", cfg, self._secret)

            new_text, n = _JSON_NAME_PATTERN.subn(_repl_json_name, text)
            if n:
                text = new_text
                detected.append("PERSON")

        # ── Layer 2: NER (PERSON) ─────────────────────────────────────────────
        if self._enabled("PERSON"):
            cfg = self._cfg("PERSON")
            persons = _ner_persons(text)
            for name in persons:
                replacement = _apply(name, "PERSON", cfg, self._secret)
                text = text.replace(name, replacement)
            if persons:
                detected.append("PERSON")

        # ── Layer 3: custom entities ──────────────────────────────────────────
        for name, pattern, cfg in self._custom:
            if not cfg.enabled:
                continue

            def _repl_custom(m: re.Match, n=name, c=cfg) -> str:
                return _apply(m.group(), n, c, self._secret)

            new_text, count = pattern.subn(_repl_custom, text)
            if count:
                text = new_text
                detected.append(name)

        # deduplicate while preserving first-occurrence order
        seen: set[str] = set()
        unique = [e for e in detected if not (e in seen or seen.add(e))]  # type: ignore[func-returns-value]
        self.stats.record(unique)
        return text, unique

    def reset_stats(self) -> None:
        self.stats = AnonymizationStats()
