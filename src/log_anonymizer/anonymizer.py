"""
PII anonymization using Microsoft Presidio with custom Chinese recognizers.

Supported entities:
  PERSON, PHONE_NUMBER, EMAIL_ADDRESS, IP_ADDRESS, CREDIT_CARD,
  CHINESE_ID_NUMBER (custom), CHINESE_PHONE (custom)
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
    PatternRecognizer,
    Pattern,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom Chinese recognizers
# ---------------------------------------------------------------------------

def _make_chinese_id_recognizer() -> PatternRecognizer:
    """18-digit Chinese resident ID number (末位可为 X)."""
    pattern = Pattern(
        name="chinese_id",
        regex=r"\b\d{17}[\dXx]\b",
        score=0.85,
    )
    return PatternRecognizer(
        supported_entity="CHINESE_ID_NUMBER",
        patterns=[pattern],
        supported_language="zh",
        context=["身份证", "证件", "ID", "证号"],
    )


def _make_chinese_phone_recognizer() -> PatternRecognizer:
    """Chinese mobile numbers: 1[3-9]XXXXXXXXX, optionally prefixed with +86 or 86."""
    pattern = Pattern(
        name="chinese_phone",
        regex=r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)",
        score=0.85,
    )
    return PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[pattern],
        supported_language="zh",
        context=["电话", "手机", "联系", "phone", "mobile", "tel"],
    )


# ---------------------------------------------------------------------------
# Operator builders
# ---------------------------------------------------------------------------

_OPERATOR_PRESETS: dict[str, dict] = {
    "PERSON": {"type": "replace", "new_value": "<姓名>"},
    "PHONE_NUMBER": {"type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_end": False},
    "EMAIL_ADDRESS": {"type": "replace", "new_value": "<邮箱>"},
    "IP_ADDRESS": {"type": "replace", "new_value": "<IP地址>"},
    "CREDIT_CARD": {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_end": False},
    "CHINESE_ID_NUMBER": {"type": "mask", "masking_char": "*", "chars_to_mask": 10, "from_end": False},
}


def _build_operators(entities: list[str]) -> dict[str, OperatorConfig]:
    ops: dict[str, OperatorConfig] = {}
    for entity in entities:
        preset = _OPERATOR_PRESETS.get(entity)
        if preset:
            cfg = dict(preset)
            op_type = cfg.pop("type")
            ops[entity] = OperatorConfig(op_type, cfg)
    return ops


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class AnonymizationStats:
    total_lines: int = 0
    redacted_lines: int = 0
    entity_counts: dict[str, int] = field(default_factory=dict)

    def record(self, entities: list[str]) -> None:
        self.total_lines += 1
        if entities:
            self.redacted_lines += 1
            for e in entities:
                self.entity_counts[e] = self.entity_counts.get(e, 0) + 1


# ---------------------------------------------------------------------------
# Main anonymizer
# ---------------------------------------------------------------------------

ALL_ENTITIES = [
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "CREDIT_CARD",
    "CHINESE_ID_NUMBER",
]


class LogAnonymizer:
    def __init__(self, entities: Optional[list[str]] = None, language: str = "zh"):
        self.language = language
        self.entities = entities or ALL_ENTITIES

        # NLP engine (spaCy zh_core_web_sm)
        conf = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "zh", "model_name": "zh_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=conf)
        nlp_engine = provider.create_engine()

        # Registry with custom recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(languages=[language], nlp_engine=nlp_engine)
        registry.add_recognizer(_make_chinese_id_recognizer())
        registry.add_recognizer(_make_chinese_phone_recognizer())

        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=[language],
        )
        self.engine = AnonymizerEngine()
        self.operators = _build_operators(self.entities)
        self.stats = AnonymizationStats()

    def anonymize(self, text: str) -> tuple[str, list[str]]:
        """
        Anonymize text. Returns (anonymized_text, list_of_detected_entity_types).
        """
        if not text:
            return text, []

        try:
            results = self.analyzer.analyze(
                text=text,
                language=self.language,
                entities=[e for e in self.entities if e != "CHINESE_ID_NUMBER"],
            )
        except Exception as exc:
            logger.warning("Analyzer error for text %r: %s", text[:50], exc)
            results = []

        # Chinese ID numbers are regex-only — run separately to avoid spaCy issues
        if "CHINESE_ID_NUMBER" in self.entities:
            try:
                id_results = self.analyzer.analyze(
                    text=text,
                    language=self.language,
                    entities=["CHINESE_ID_NUMBER"],
                )
                results = results + id_results
            except Exception as exc:
                logger.warning("Chinese ID analysis error: %s", exc)

        detected = list({r.entity_type for r in results})
        self.stats.record(detected)

        if not results:
            return text, []

        try:
            anonymized = self.engine.anonymize(
                text=text,
                analyzer_results=results,
                operators=self.operators,
            )
            return anonymized.text, detected
        except Exception as exc:
            logger.warning("Anonymizer error: %s", exc)
            return text, []

    def reset_stats(self) -> None:
        self.stats = AnonymizationStats()
