"""Redaction and masking utilities for PII protection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp_gateway.pii.detector import PIIDetector


@dataclass
class MaskingConfig:
    """Configuration for masking different PII types."""

    # Number of characters to preserve at start/end
    preserve_start: int = 0
    preserve_end: int = 0
    # Character to use for masking
    mask_char: str = "*"
    # Fixed-length mask (ignores actual value length if set)
    fixed_length: int | None = None
    # Custom format for specific types
    format_template: str | None = None


# Default masking configurations per PII type
DEFAULT_MASK_CONFIGS: dict[str, MaskingConfig] = {
    "email": MaskingConfig(
        preserve_start=2,
        preserve_end=0,
        format_template="{start}***@***.***",
    ),
    "phone": MaskingConfig(
        preserve_start=0,
        preserve_end=4,
        mask_char="*",
    ),
    "ssn": MaskingConfig(
        fixed_length=11,
        format_template="***-**-****",
    ),
    "iban": MaskingConfig(
        preserve_start=4,
        preserve_end=4,
        mask_char="*",
    ),
    "credit_card": MaskingConfig(
        preserve_start=0,
        preserve_end=4,
        mask_char="*",
    ),
    "ip_address": MaskingConfig(
        fixed_length=11,
        format_template="***.***.***.***",
    ),
    "date_of_birth": MaskingConfig(
        fixed_length=10,
        format_template="**/**/****",
    ),
}


class PIIRedactor:
    """Redacts and masks PII in text and data structures."""

    def __init__(
        self,
        detector: PIIDetector | None = None,
        custom_configs: dict[str, MaskingConfig] | None = None,
    ) -> None:
        """
        Initialize redactor with detector and optional custom configs.

        Args:
            detector: PIIDetector instance. Creates new one if not provided.
            custom_configs: Optional custom masking configurations per PII type.
        """
        self._detector = detector or PIIDetector()
        self._configs = {**DEFAULT_MASK_CONFIGS}
        if custom_configs:
            self._configs.update(custom_configs)

    def mask_value(self, value: str, pii_type: str) -> str:
        """
        Mask a known PII value using type-specific rules.

        Args:
            value: The PII value to mask.
            pii_type: The type of PII (e.g., "email", "phone").

        Returns:
            Masked string.
        """
        config = self._configs.get(pii_type, MaskingConfig())

        # Use format template if available
        if config.format_template:
            if "{start}" in config.format_template:
                start = value[: config.preserve_start] if config.preserve_start else ""
                return config.format_template.format(start=start)
            return config.format_template

        # Fixed-length masking
        if config.fixed_length:
            return config.mask_char * config.fixed_length

        # Preserve start/end masking
        total_len = len(value)
        mask_len = total_len - config.preserve_start - config.preserve_end

        if mask_len <= 0:
            return config.mask_char * total_len

        start = value[: config.preserve_start] if config.preserve_start else ""
        end = value[-config.preserve_end :] if config.preserve_end else ""
        middle = config.mask_char * mask_len

        return f"{start}{middle}{end}"

    def redact_text(self, text: str) -> tuple[str, list[str]]:
        """
        Redact all detected PII from text.

        Args:
            text: Text to redact.

        Returns:
            Tuple of (redacted_text, list_of_detected_pii_types).
        """
        if not text:
            return text, []

        result = self._detector.detect(text)
        if not result.has_pii:
            return text, []

        # Sort matches by position (reverse) to replace from end to start
        sorted_matches = sorted(result.matches, key=lambda m: m.start, reverse=True)
        redacted = text

        for match in sorted_matches:
            masked = self.mask_value(match.value, match.pii_type)
            redacted = redacted[: match.start] + masked + redacted[match.end :]

        return redacted, list(result.pii_types)

    def redact_dict(
        self,
        data: dict[str, Any],
        columns: list[str] | set[str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, list[str]]]:
        """
        Redact PII from specified columns in a dictionary.

        Args:
            data: Dictionary containing data.
            columns: Columns to check and redact. If None, checks all.

        Returns:
            Tuple of (redacted_dict, column_to_pii_types_map).
        """
        result = data.copy()
        pii_found: dict[str, list[str]] = {}
        columns_to_check = set(columns) if columns else set(data.keys())

        for key in columns_to_check:
            if key not in result:
                continue

            value = result[key]
            if value is None:
                continue

            if isinstance(value, str):
                redacted, pii_types = self.redact_text(value)
                result[key] = redacted
                if pii_types:
                    pii_found[key] = pii_types
            elif isinstance(value, dict):
                nested_result, nested_pii = self.redact_dict(value)
                result[key] = nested_result
                for nested_key, types in nested_pii.items():
                    pii_found[f"{key}.{nested_key}"] = types

        return result, pii_found

    def redact_rows(
        self,
        rows: list[dict[str, Any]],
        columns: list[str] | set[str] | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
        """
        Redact PII from rows, tracking which columns had PII.

        Args:
            rows: List of row dictionaries.
            columns: Columns to check. If None, checks all.

        Returns:
            Tuple of (redacted_rows, column_to_pii_types_map).
        """
        redacted_rows = []
        all_pii: dict[str, set[str]] = {}

        for row in rows:
            redacted, pii_found = self.redact_dict(row, columns)
            redacted_rows.append(redacted)

            for col, types in pii_found.items():
                if col not in all_pii:
                    all_pii[col] = set()
                all_pii[col].update(types)

        return redacted_rows, all_pii


def quick_redact(text: str) -> str:
    """
    Quick redaction using default settings.

    Args:
        text: Text to redact.

    Returns:
        Redacted text.
    """
    redactor = PIIRedactor()
    redacted, _ = redactor.redact_text(text)
    return redacted


def create_safe_error_message(error: Exception) -> str:
    """
    Create a safe error message with any PII redacted.

    Args:
        error: The exception to create a message from.

    Returns:
        Error message with PII redacted.
    """
    message = str(error)
    return quick_redact(message)


def redact_filter_values(filters: dict[str, Any]) -> dict[str, Any]:
    """
    Redact any PII from filter values (for logging purposes).

    This is used to safely log filter criteria without exposing
    PII that may be in the filter values.

    Args:
        filters: Dictionary of filter key-value pairs.

    Returns:
        Dictionary with PII values redacted.
    """
    redactor = PIIRedactor()
    redacted, _ = redactor.redact_dict(filters)
    return redacted
