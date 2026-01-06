"""PII detection module for identifying sensitive data in values and text."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from mcp_gateway.config import get_policies_path


@dataclass
class PIIMatch:
    """Represents a detected PII occurrence."""

    pii_type: str
    value: str
    start: int
    end: int
    sensitivity: str
    default_action: str


@dataclass
class DetectionResult:
    """Result of PII detection on a value."""

    has_pii: bool
    matches: list[PIIMatch] = field(default_factory=list)
    pii_types: set[str] = field(default_factory=set)

    def merge(self, other: DetectionResult) -> DetectionResult:
        """Merge another detection result into this one."""
        return DetectionResult(
            has_pii=self.has_pii or other.has_pii,
            matches=self.matches + other.matches,
            pii_types=self.pii_types | other.pii_types,
        )


class PIIDetector:
    """Detects PII in text values using configurable patterns."""

    def __init__(self, policies_path: str | None = None) -> None:
        """Initialize the detector with policies from YAML."""
        self._policies_path = policies_path or get_policies_path()
        self._patterns: dict[str, dict[str, Any]] = {}
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load detection patterns from policies.yaml."""
        try:
            with open(self._policies_path, encoding="utf-8") as f:
                policies = yaml.safe_load(f)

            self._patterns = policies.get("detection_patterns", {})

            # Pre-compile regex patterns for performance
            for pii_type, config in self._patterns.items():
                pattern_str = config.get("pattern", "")
                if pattern_str:
                    self._compiled_patterns[pii_type] = re.compile(
                        pattern_str, re.IGNORECASE
                    )
        except FileNotFoundError:
            # Use default patterns if policies file not found
            self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load hardcoded default patterns as fallback."""
        default_patterns = {
            "email": {
                "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                "sensitivity": "high",
                "default_action": "mask",
            },
            "phone": {
                "pattern": r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
                "sensitivity": "high",
                "default_action": "mask",
            },
            "ssn": {
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "sensitivity": "critical",
                "default_action": "deny",
            },
            "iban": {
                "pattern": r"[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}",
                "sensitivity": "critical",
                "default_action": "hash",
            },
        }

        self._patterns = default_patterns
        for pii_type, config in self._patterns.items():
            self._compiled_patterns[pii_type] = re.compile(
                config["pattern"], re.IGNORECASE
            )

    def detect(self, value: Any) -> DetectionResult:
        """
        Detect PII in a given value.

        Args:
            value: The value to scan for PII (will be converted to string).

        Returns:
            DetectionResult containing all matches found.
        """
        if value is None:
            return DetectionResult(has_pii=False)

        text = str(value)
        if not text.strip():
            return DetectionResult(has_pii=False)

        matches: list[PIIMatch] = []
        pii_types: set[str] = set()

        for pii_type, pattern in self._compiled_patterns.items():
            config = self._patterns[pii_type]

            for match in pattern.finditer(text):
                pii_match = PIIMatch(
                    pii_type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                    sensitivity=config.get("sensitivity", "medium"),
                    default_action=config.get("default_action", "mask"),
                )
                matches.append(pii_match)
                pii_types.add(pii_type)

        return DetectionResult(
            has_pii=len(matches) > 0,
            matches=matches,
            pii_types=pii_types,
        )

    def detect_in_dict(self, data: dict[str, Any]) -> dict[str, DetectionResult]:
        """
        Detect PII in all values of a dictionary.

        Args:
            data: Dictionary to scan.

        Returns:
            Dictionary mapping keys to their detection results.
        """
        results: dict[str, DetectionResult] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                # Recursively check nested dicts
                nested = self.detect_in_dict(value)
                for nested_key, result in nested.items():
                    results[f"{key}.{nested_key}"] = result
            elif isinstance(value, list):
                # Check each item in lists
                combined = DetectionResult(has_pii=False)
                for item in value:
                    if isinstance(item, dict):
                        nested = self.detect_in_dict(item)
                        for result in nested.values():
                            combined = combined.merge(result)
                    else:
                        combined = combined.merge(self.detect(item))
                results[key] = combined
            else:
                results[key] = self.detect(value)

        return results

    def detect_in_rows(
        self, rows: list[dict[str, Any]]
    ) -> tuple[bool, set[str], dict[str, set[str]]]:
        """
        Detect PII across multiple data rows.

        Args:
            rows: List of row dictionaries to scan.

        Returns:
            Tuple of (has_pii, all_pii_types, column_to_pii_types_map)
        """
        has_pii = False
        all_pii_types: set[str] = set()
        column_pii: dict[str, set[str]] = {}

        for row in rows:
            for col, value in row.items():
                result = self.detect(value)
                if result.has_pii:
                    has_pii = True
                    all_pii_types |= result.pii_types
                    if col not in column_pii:
                        column_pii[col] = set()
                    column_pii[col] |= result.pii_types

        return has_pii, all_pii_types, column_pii

    def get_pattern_info(self, pii_type: str) -> dict[str, Any] | None:
        """Get configuration info for a specific PII type."""
        return self._patterns.get(pii_type)

    @property
    def supported_types(self) -> list[str]:
        """List all supported PII types."""
        return list(self._patterns.keys())
