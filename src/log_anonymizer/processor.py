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
            df    — DataFrame [time, level, service, msg, redacted_entities]
            stats — AnonymizationStats summary
        """
        self.anonymizer.reset_stats()
        parsed = parse_lines(lines)

        rows = []
        for record in parsed:
            msg = record.get("msg", "")
            clean_msg, detected = self.anonymizer.anonymize(msg)
            rows.append({
                "time":             record.get("time", ""),
                "level":            record.get("level", "UNKNOWN"),
                "service":          record.get("service", "unknown"),
                "msg":              clean_msg,
                "redacted_entities": ", ".join(detected) if detected else "",
            })

        df = pd.DataFrame(rows, columns=["time", "level", "service", "msg", "redacted_entities"])
        return df, self.anonymizer.stats
