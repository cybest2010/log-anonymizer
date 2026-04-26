"""
Orchestrates parsing + anonymization, returning a DataFrame.
"""

import pandas as pd
from typing import Optional

from .parser import parse_lines
from .anonymizer import LogAnonymizer, AnonymizationConfig, AnonymizationStats


class Processor:
    def __init__(self, config: Optional[AnonymizationConfig] = None):
        self.anonymizer = LogAnonymizer(config=config)

    def process(self, lines: list[str]) -> tuple[pd.DataFrame, AnonymizationStats]:
        """
        Parse and anonymize log lines.

        Returns:
            df    — DataFrame [time, level, service, msg, original_msg,
                               redacted_entities, parse_method]
            stats — AnonymizationStats summary
        """
        self.anonymizer.reset_stats()
        parsed = parse_lines(lines)

        rows = []
        for record in parsed:
            original_msg = record.get("msg", "")
            clean_msg, detected = self.anonymizer.anonymize(original_msg)
            parse_method = record.get("_parse_method", "fallback")
            rows.append({
                "time":              record.get("time", ""),
                "level":             record.get("level", "UNKNOWN"),
                "service":           record.get("service", "unknown"),
                "msg":               clean_msg,
                "original_msg":      original_msg,
                "redacted_entities": ", ".join(detected) if detected else "",
                "parse_method":      parse_method,
            })

        df = pd.DataFrame(
            rows,
            columns=["time", "level", "service", "msg", "original_msg",
                     "redacted_entities", "parse_method"],
        )
        return df, self.anonymizer.stats
