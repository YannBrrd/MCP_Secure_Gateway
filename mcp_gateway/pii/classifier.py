"""Schema-based PII classification for columns and tables."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

import yaml

from mcp_gateway.config import get_policies_path


class PIISensitivity(str, Enum):
    """PII sensitivity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ColumnClassification:
    """Classification result for a single column."""

    column_name: str
    is_pii: bool
    sensitivity: PIISensitivity
    pii_category: str | None = None
    match_reason: str | None = None


@dataclass
class SchemaClassification:
    """Classification result for an entire schema/table."""

    table_name: str
    columns: list[ColumnClassification]
    has_pii: bool
    pii_columns: list[str]

    @property
    def critical_columns(self) -> list[str]:
        """Get columns with critical sensitivity."""
        return [
            c.column_name
            for c in self.columns
            if c.sensitivity == PIISensitivity.CRITICAL
        ]

    @property
    def high_sensitivity_columns(self) -> list[str]:
        """Get columns with high or critical sensitivity."""
        return [
            c.column_name
            for c in self.columns
            if c.sensitivity in (PIISensitivity.CRITICAL, PIISensitivity.HIGH)
        ]


class PIIClassifier:
    """Classifies columns and schemas for PII based on naming conventions and patterns."""

    def __init__(self, policies_path: str | None = None) -> None:
        """Initialize classifier with policies from YAML."""
        self._policies_path = policies_path or get_policies_path()
        self._exact_matches: set[str] = set()
        self._contains_patterns: list[str] = []
        self._regex_patterns: list[re.Pattern[str]] = []
        self._backend_overrides: dict[str, list[str]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load column classification rules from policies.yaml."""
        try:
            with open(self._policies_path, encoding="utf-8") as f:
                policies = yaml.safe_load(f)

            col_config = policies.get("column_classifications", {})

            # Load exact matches (case-insensitive)
            self._exact_matches = {
                name.lower() for name in col_config.get("exact", [])
            }

            # Load contains patterns
            self._contains_patterns = [
                p.lower() for p in col_config.get("contains", [])
            ]

            # Compile regex patterns
            for pattern in col_config.get("patterns", []):
                self._regex_patterns.append(
                    re.compile(pattern, re.IGNORECASE)
                )

            # Load backend-specific overrides
            backend_config = policies.get("backend_overrides", {})
            for backend, config in backend_config.items():
                self._backend_overrides[backend] = [
                    c.lower() for c in config.get("additional_pii_columns", [])
                ]

        except FileNotFoundError:
            self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load hardcoded default classification rules."""
        self._exact_matches = {
            "email", "email_address", "phone", "phone_number",
            "ssn", "social_security", "iban", "password",
            "credit_card", "dob", "date_of_birth",
        }
        self._contains_patterns = [
            "_email", "_phone", "_ssn", "first_name", "last_name",
            "full_name", "address", "_password", "_token",
        ]
        self._regex_patterns = [
            re.compile(r"name_?(?:first|last|full)?", re.IGNORECASE),
            re.compile(r"addr(?:ess)?_?(?:line)?_?\d?", re.IGNORECASE),
        ]

    def classify_column(
        self,
        column_name: str,
        backend: str | None = None,
    ) -> ColumnClassification:
        """
        Classify a single column name for PII.

        Args:
            column_name: Name of the column to classify.
            backend: Optional backend name for backend-specific rules.

        Returns:
            ColumnClassification with PII determination.
        """
        name_lower = column_name.lower()

        # Check exact matches first (highest confidence)
        if name_lower in self._exact_matches:
            return ColumnClassification(
                column_name=column_name,
                is_pii=True,
                sensitivity=self._infer_sensitivity(name_lower),
                pii_category=self._infer_category(name_lower),
                match_reason="exact_match",
            )

        # Check contains patterns
        for pattern in self._contains_patterns:
            if pattern in name_lower:
                return ColumnClassification(
                    column_name=column_name,
                    is_pii=True,
                    sensitivity=self._infer_sensitivity(name_lower),
                    pii_category=self._infer_category(name_lower),
                    match_reason=f"contains_pattern:{pattern}",
                )

        # Check regex patterns
        for pattern in self._regex_patterns:
            if pattern.search(name_lower):
                return ColumnClassification(
                    column_name=column_name,
                    is_pii=True,
                    sensitivity=PIISensitivity.MEDIUM,
                    pii_category="inferred",
                    match_reason=f"regex_pattern:{pattern.pattern}",
                )

        # Check backend-specific overrides
        if backend and backend in self._backend_overrides:
            if name_lower in self._backend_overrides[backend]:
                return ColumnClassification(
                    column_name=column_name,
                    is_pii=True,
                    sensitivity=PIISensitivity.MEDIUM,
                    pii_category="backend_specific",
                    match_reason=f"backend_override:{backend}",
                )

        # Not classified as PII
        return ColumnClassification(
            column_name=column_name,
            is_pii=False,
            sensitivity=PIISensitivity.NONE,
        )

    def _infer_sensitivity(self, column_name: str) -> PIISensitivity:
        """Infer sensitivity level from column name."""
        critical_keywords = {"ssn", "social_security", "password", "credit_card", "iban"}
        high_keywords = {"email", "phone", "dob", "date_of_birth", "address"}

        for kw in critical_keywords:
            if kw in column_name:
                return PIISensitivity.CRITICAL

        for kw in high_keywords:
            if kw in column_name:
                return PIISensitivity.HIGH

        return PIISensitivity.MEDIUM

    def _infer_category(self, column_name: str) -> str:
        """Infer PII category from column name."""
        category_keywords = {
            "contact": ["email", "phone", "mobile", "cell"],
            "identity": ["ssn", "social_security", "passport", "license"],
            "financial": ["credit_card", "iban", "bank", "account"],
            "personal": ["name", "dob", "birth", "age"],
            "location": ["address", "street", "city", "zip", "postal"],
            "credentials": ["password", "secret", "token", "key"],
        }

        for category, keywords in category_keywords.items():
            for kw in keywords:
                if kw in column_name:
                    return category

        return "unknown"

    def classify_schema(
        self,
        table_name: str,
        columns: list[str],
        backend: str | None = None,
    ) -> SchemaClassification:
        """
        Classify all columns in a schema/table.

        Args:
            table_name: Name of the table.
            columns: List of column names.
            backend: Optional backend for backend-specific rules.

        Returns:
            SchemaClassification with all column classifications.
        """
        classifications = [
            self.classify_column(col, backend) for col in columns
        ]

        pii_columns = [c.column_name for c in classifications if c.is_pii]

        return SchemaClassification(
            table_name=table_name,
            columns=classifications,
            has_pii=len(pii_columns) > 0,
            pii_columns=pii_columns,
        )

    def get_safe_columns(
        self,
        columns: list[str],
        backend: str | None = None,
    ) -> list[str]:
        """
        Filter columns to return only non-PII columns.

        Args:
            columns: List of column names to filter.
            backend: Optional backend for backend-specific rules.

        Returns:
            List of column names that are not classified as PII.
        """
        return [
            col for col in columns
            if not self.classify_column(col, backend).is_pii
        ]

    def get_columns_by_sensitivity(
        self,
        columns: list[str],
        max_sensitivity: PIISensitivity,
        backend: str | None = None,
    ) -> list[str]:
        """
        Get columns with sensitivity at or below the specified level.

        Args:
            columns: List of column names to filter.
            max_sensitivity: Maximum allowed sensitivity level.
            backend: Optional backend for backend-specific rules.

        Returns:
            List of columns within the sensitivity threshold.
        """
        sensitivity_order = {
            PIISensitivity.NONE: 0,
            PIISensitivity.LOW: 1,
            PIISensitivity.MEDIUM: 2,
            PIISensitivity.HIGH: 3,
            PIISensitivity.CRITICAL: 4,
        }

        max_level = sensitivity_order[max_sensitivity]

        return [
            col for col in columns
            if sensitivity_order[self.classify_column(col, backend).sensitivity] <= max_level
        ]
