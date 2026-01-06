"""Base connector class for all backend data platforms."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.pii import PIIClassifier, PIIDetector
from mcp_gateway.security import PIIHasher, PIIRedactor


@dataclass
class QueryResult:
    """Result from a backend query."""

    rows: list[dict[str, Any]]
    columns: list[str]
    row_count: int
    metadata: dict[str, Any] = field(default_factory=dict)
    pii_columns_detected: list[str] = field(default_factory=list)
    pii_types_detected: list[str] = field(default_factory=list)


@dataclass
class IntentQuery:
    """
    Represents a safe, intent-based query.

    This is what connectors receive instead of raw SQL.
    The connector is responsible for translating this into
    backend-specific queries.
    """

    intent: str
    entity: str | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    aggregations: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)
    limit: int = 100


class BaseConnector(ABC):
    """
    Abstract base class for all backend connectors.

    All connectors must:
    - Never expose raw SQL to the caller
    - Never return raw PII without processing
    - Support intent-based querying
    - Provide schema metadata safely
    """

    def __init__(
        self,
        detector: PIIDetector | None = None,
        classifier: PIIClassifier | None = None,
        hasher: PIIHasher | None = None,
        redactor: PIIRedactor | None = None,
    ) -> None:
        """
        Initialize connector with PII handling components.

        Args:
            detector: PII detector for value scanning.
            classifier: PII classifier for schema analysis.
            hasher: PII hasher for hash policy.
            redactor: PII redactor for mask policy.
        """
        self._detector = detector or PIIDetector()
        self._classifier = classifier or PIIClassifier()
        self._hasher = hasher or PIIHasher()
        self._redactor = redactor or PIIRedactor(self._detector)
        self._connected = False

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return the backend identifier (e.g., 'snowflake', 'databricks')."""
        ...

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the backend."""
        ...

    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the backend."""
        ...

    @abstractmethod
    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query.

        Args:
            query: The IntentQuery to execute.

        Returns:
            QueryResult with processed (PII-safe) data.
        """
        ...

    @abstractmethod
    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """
        Get schema metadata from the backend.

        Args:
            database: Optional database filter.
            schema: Optional schema filter.
            table: Optional table filter.

        Returns:
            Schema metadata (tables, columns, types).
        """
        ...

    @abstractmethod
    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """
        List available tables.

        Args:
            database: Optional database filter.
            schema: Optional schema filter.

        Returns:
            List of table names.
        """
        ...

    def _process_results_with_policy(
        self,
        rows: list[dict[str, Any]],
        columns: list[str],
        pii_policy: str,
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """
        Process query results according to PII policy.

        Args:
            rows: Raw query results.
            columns: Column names.
            pii_policy: Policy to apply ("mask", "hash", "deny").

        Returns:
            Tuple of (processed_rows, pii_columns, pii_types).

        Raises:
            ValueError: If policy is "deny" and PII is detected.
        """
        if not rows:
            return rows, [], []

        # First, classify columns by name
        classified_pii_cols = set()
        for col in columns:
            classification = self._classifier.classify_column(col, self.backend_name)
            if classification.is_pii:
                classified_pii_cols.add(col)

        # Then, scan actual values
        has_pii, pii_types, column_pii = self._detector.detect_in_rows(rows)

        # Combine schema-based and value-based PII columns
        all_pii_cols = classified_pii_cols | set(column_pii.keys())
        all_pii_types = list(pii_types)

        if not all_pii_cols:
            return rows, [], []

        # Handle deny policy
        if pii_policy == "deny":
            raise ValueError(
                f"PII detected in columns {list(all_pii_cols)} with policy 'deny'. "
                "Request rejected."
            )

        # Apply masking or hashing
        if pii_policy == "hash":
            processed = self._hasher.hash_rows(rows, all_pii_cols)
        else:  # mask (default)
            processed, _ = self._redactor.redact_rows(rows, all_pii_cols)

        return processed, list(all_pii_cols), all_pii_types

    def _classify_schema_columns(
        self,
        columns: list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Classify columns in a schema for PII.

        Args:
            columns: List of column names.

        Returns:
            Dictionary mapping column names to classification info.
        """
        result = {}
        for col in columns:
            classification = self._classifier.classify_column(col, self.backend_name)
            result[col] = {
                "is_pii": classification.is_pii,
                "sensitivity": classification.sensitivity.value,
                "category": classification.pii_category,
            }
        return result

    @property
    def is_connected(self) -> bool:
        """Check if connector is connected."""
        return self._connected
