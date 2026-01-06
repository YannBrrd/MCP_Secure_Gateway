"""Deterministic hashing utilities for PII protection."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from mcp_gateway.config import get_settings


class PIIHasher:
    """
    Deterministic hasher for PII values.

    Uses HMAC-SHA256 with a configurable salt to produce consistent
    hash values for the same input. This allows for data linkage
    without exposing raw PII.
    """

    def __init__(self, salt: str | None = None) -> None:
        """
        Initialize the hasher with a salt.

        Args:
            salt: Optional salt string. If not provided, uses the
                  configured salt from settings.
        """
        if salt is None:
            settings = get_settings()
            salt = settings.pii.hash_salt.get_secret_value()
        self._salt = salt.encode("utf-8")

    def hash_value(self, value: Any) -> str:
        """
        Hash a single value deterministically.

        Args:
            value: Value to hash (will be converted to string).

        Returns:
            Hex-encoded HMAC-SHA256 hash prefixed with 'HASH_'.
        """
        if value is None:
            return "HASH_NULL"

        value_bytes = str(value).encode("utf-8")
        hash_bytes = hmac.new(self._salt, value_bytes, hashlib.sha256).digest()

        # Return first 16 bytes (32 hex chars) for shorter output
        return f"HASH_{hash_bytes[:16].hex().upper()}"

    def hash_dict(
        self,
        data: dict[str, Any],
        columns: list[str] | set[str] | None = None,
    ) -> dict[str, Any]:
        """
        Hash specified columns in a dictionary.

        Args:
            data: Dictionary containing data.
            columns: Columns to hash. If None, hashes all values.

        Returns:
            New dictionary with specified columns hashed.
        """
        result = data.copy()
        columns_to_hash = set(columns) if columns else set(data.keys())

        for key in columns_to_hash:
            if key in result:
                result[key] = self.hash_value(result[key])

        return result

    def hash_rows(
        self,
        rows: list[dict[str, Any]],
        columns: list[str] | set[str],
    ) -> list[dict[str, Any]]:
        """
        Hash specified columns across multiple rows.

        Args:
            rows: List of row dictionaries.
            columns: Columns to hash in each row.

        Returns:
            New list with hashed values.
        """
        columns_set = set(columns)
        return [self.hash_dict(row, columns_set) for row in rows]

    def hash_if_pii(
        self,
        value: Any,
        is_pii: bool,
    ) -> Any:
        """
        Conditionally hash a value if it's marked as PII.

        Args:
            value: Value to potentially hash.
            is_pii: Whether the value contains PII.

        Returns:
            Hashed value if is_pii is True, otherwise original value.
        """
        return self.hash_value(value) if is_pii else value


def create_lookup_hash(identifier: str, context: str) -> str:
    """
    Create a context-specific hash for lookup purposes.

    This allows creating different hash namespaces for different
    use cases while maintaining determinism within each context.

    Args:
        identifier: The identifier to hash.
        context: A context string (e.g., "user_id", "session").

    Returns:
        Context-prefixed hash string.
    """
    settings = get_settings()
    salt = settings.pii.hash_salt.get_secret_value()

    # Combine context and salt for domain separation
    combined_salt = f"{context}:{salt}".encode()
    value_bytes = str(identifier).encode("utf-8")

    hash_bytes = hmac.new(combined_salt, value_bytes, hashlib.sha256).digest()

    return f"{context.upper()}_HASH_{hash_bytes[:12].hex().upper()}"


def verify_hash_format(value: str) -> bool:
    """
    Check if a value appears to be a hash from this module.

    Args:
        value: String to check.

    Returns:
        True if the value matches our hash format.
    """
    if not isinstance(value, str):
        return False

    # Check for standard hash prefix
    if value.startswith("HASH_"):
        # HASH_NULL or HASH_ followed by 32 hex chars
        suffix = value[5:]
        if suffix == "NULL":
            return True
        return len(suffix) == 32 and all(c in "0123456789ABCDEF" for c in suffix)

    # Check for context-prefixed hashes (e.g., USER_ID_HASH_...)
    if "_HASH_" in value:
        parts = value.split("_HASH_")
        if len(parts) == 2:
            return len(parts[1]) == 24 and all(
                c in "0123456789ABCDEF" for c in parts[1]
            )

    return False
