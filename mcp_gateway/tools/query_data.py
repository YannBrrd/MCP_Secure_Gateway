"""
The query_data MCP tool - the ONLY tool exposed by this gateway.

This tool provides a secure interface for querying data from multiple backends
while enforcing strict PII policies. It never accepts raw SQL and never returns
raw PII to the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from mcp_gateway.audit import PIIPolicyAction, get_audit_logger
from mcp_gateway.connectors import IntentQuery, get_connector
from mcp_gateway.pii import PIIDetector
from mcp_gateway.security import PIIHasher, PIIRedactor, create_safe_error_message


class Backend(str, Enum):
    """Supported backend data platforms."""

    SNOWFLAKE = "snowflake"
    DATABRICKS = "databricks"
    TRINO = "trino"
    BIGQUERY = "bigquery"
    ATHENA = "athena"


class PIIPolicy(str, Enum):
    """PII handling policies."""

    MASK = "mask"
    HASH = "hash"
    DENY = "deny"


class QueryDataInput(BaseModel):
    """
    Input schema for the query_data tool.

    This is the contract that the agent must follow.
    """

    backend: Backend = Field(
        ...,
        description="Target data platform: snowflake, databricks, trino, bigquery, or athena",
    )

    intent: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description=(
            "Business intent describing what data you need. "
            "Must be a natural language description, NOT SQL. "
            "Example: 'Get total sales by region for Q4 2024'"
        ),
    )

    filters: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Key-value filters to apply. Keys are column names, values are filter criteria. "
            "Example: {'region': 'EMEA', 'year': 2024}"
        ),
    )

    pii_policy: PIIPolicy = Field(
        default=PIIPolicy.MASK,
        description=(
            "How to handle PII in results: "
            "'mask' replaces PII with asterisks, "
            "'hash' replaces with deterministic hashes, "
            "'deny' rejects query if PII is detected"
        ),
    )

    entity: str | None = Field(
        default=None,
        description="Optional: specific table/entity name if not inferred from intent",
    )

    aggregations: list[str] = Field(
        default_factory=list,
        description="Optional: aggregation expressions like 'SUM(amount)', 'COUNT(*)'",
    )

    group_by: list[str] = Field(
        default_factory=list,
        description="Optional: columns to group by",
    )

    order_by: list[str] = Field(
        default_factory=list,
        description="Optional: columns to order by",
    )

    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum rows to return (1-1000)",
    )

    @field_validator("intent")
    @classmethod
    def reject_sql(cls, v: str) -> str:
        """Reject any input that looks like SQL."""
        sql_patterns = [
            r"\bSELECT\b",
            r"\bFROM\b",
            r"\bWHERE\b",
            r"\bJOIN\b",
            r"\bINSERT\b",
            r"\bUPDATE\b",
            r"\bDELETE\b",
            r"\bDROP\b",
            r"\bCREATE\b",
            r"\bALTER\b",
            r"\bGRANT\b",
            r"\bREVOKE\b",
            r";\s*$",  # Trailing semicolon
            r"--",  # SQL comment
            r"/\*",  # SQL block comment
        ]

        for pattern in sql_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError(
                    f"SQL syntax detected in intent. This tool accepts only business "
                    f"intent descriptions, not SQL. Pattern matched: {pattern}"
                )

        return v

    @field_validator("filters")
    @classmethod
    def validate_filter_keys(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate filter keys are safe column names."""
        for key in v:
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", key):
                raise ValueError(
                    f"Invalid filter key: {key}. Must be a valid column name "
                    "(alphanumeric and underscores, starting with letter or underscore)"
                )
        return v


@dataclass
class QueryDataOutput:
    """Output schema for the query_data tool."""

    success: bool
    data: list[dict[str, Any]] = field(default_factory=list)
    row_count: int = 0
    columns: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    pii_status: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "data": self.data,
            "row_count": self.row_count,
            "columns": self.columns,
            "metadata": self.metadata,
            "pii_status": self.pii_status,
            "error": self.error,
        }


class QueryDataTool:
    """
    The query_data MCP tool implementation.

    This is the ONLY tool exposed by the gateway. It:
    - Validates input strictly (no SQL)
    - Routes to the appropriate backend
    - Enforces PII policies before returning data
    - Logs all operations for audit
    """

    def __init__(self) -> None:
        """Initialize the tool with required components."""
        self._audit = get_audit_logger()
        self._detector = PIIDetector()
        self._hasher = PIIHasher()
        self._redactor = PIIRedactor(self._detector)

    @property
    def name(self) -> str:
        """Tool name."""
        return "query_data"

    @property
    def description(self) -> str:
        """Tool description for MCP."""
        return (
            "Query data from enterprise data platforms (Snowflake, Databricks, Trino, "
            "BigQuery, Athena) using business intent. This tool NEVER accepts raw SQL "
            "and NEVER returns raw PII. All results are automatically processed according "
            "to the specified PII policy (mask, hash, or deny)."
        )

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """
        Example invocations for the query_data tool.

        These examples teach the model correct usage patterns beyond
        what the JSON schema alone can express: when to use optional
        parameters, which combinations make sense, etc.
        """
        return [
            {
                "description": "Simple query with business intent",
                "input": {
                    "backend": "snowflake",
                    "intent": "Get total sales by region for Q4 2024",
                    "pii_policy": "mask",
                },
                "output_summary": "Returns sales data with any PII values masked",
            },
            {
                "description": "Filtered query with aggregation",
                "input": {
                    "backend": "bigquery",
                    "intent": "Count active customers by country",
                    "filters": {"status": "active"},
                    "aggregations": ["COUNT(*)"],
                    "group_by": ["country"],
                    "entity": "customers",
                    "pii_policy": "hash",
                },
                "output_summary": (
                    "Returns customer counts grouped by country, "
                    "with PII hashed for linkability"
                ),
            },
            {
                "description": "Query with hash policy for data linkage",
                "input": {
                    "backend": "databricks",
                    "intent": "Get customer emails and order counts",
                    "entity": "customer_orders",
                    "pii_policy": "hash",
                    "limit": 50,
                },
                "output_summary": (
                    "Returns customer data with emails hashed deterministically "
                    "(same email always produces same hash for joining)"
                ),
            },
            {
                "description": "Strict compliance query with deny policy",
                "input": {
                    "backend": "snowflake",
                    "intent": "Get product revenue by category",
                    "entity": "products",
                    "pii_policy": "deny",
                },
                "output_summary": (
                    "Returns product data only if NO PII is detected. "
                    "Query is rejected if any PII values appear in results."
                ),
            },
        ]

    @property
    def input_schema(self) -> dict[str, Any]:
        """JSON Schema for tool input."""
        return {
            "type": "object",
            "properties": {
                "backend": {
                    "type": "string",
                    "enum": ["snowflake", "databricks", "trino", "bigquery", "athena"],
                    "description": "Target data platform",
                },
                "intent": {
                    "type": "string",
                    "minLength": 5,
                    "maxLength": 500,
                    "description": "Business intent (NOT SQL). Example: 'Get customer counts by region'",
                },
                "filters": {
                    "type": "object",
                    "additionalProperties": True,
                    "description": "Key-value filters (column_name: value)",
                },
                "pii_policy": {
                    "type": "string",
                    "enum": ["mask", "hash", "deny"],
                    "default": "mask",
                    "description": "How to handle PII: mask, hash, or deny",
                },
                "entity": {
                    "type": "string",
                    "description": "Optional table/entity name",
                },
                "aggregations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Aggregation expressions",
                },
                "group_by": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Group by columns",
                },
                "order_by": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Order by columns",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 100,
                    "description": "Maximum rows to return",
                },
            },
            "required": ["backend", "intent"],
        }

    async def execute(self, arguments: dict[str, Any]) -> QueryDataOutput:
        """
        Execute the query_data tool.

        Args:
            arguments: Tool arguments matching the input schema.

        Returns:
            QueryDataOutput with results or error.
        """
        invocation_id = None

        try:
            # Parse and validate input
            input_data = QueryDataInput(**arguments)

            # Log invocation
            invocation_id = self._audit.log_tool_invocation(
                tool_name=self.name,
                backend=input_data.backend.value,
                intent=input_data.intent,
                pii_policy=input_data.pii_policy.value,
                filter_keys=list(input_data.filters.keys()),
            )

            # Check filters for PII before proceeding
            filter_pii_result = self._detector.detect_in_dict(input_data.filters)
            filter_has_pii = any(r.has_pii for r in filter_pii_result.values())

            if filter_has_pii:
                # Hash any PII in filter values before sending to backend
                for key, detection in filter_pii_result.items():
                    if detection.has_pii:
                        input_data.filters[key] = self._hasher.hash_value(input_data.filters[key])

            # Get connector for backend
            connector = get_connector(input_data.backend.value)

            # Build intent query
            intent_query = IntentQuery(
                intent=input_data.intent,
                entity=input_data.entity,
                filters=input_data.filters,
                aggregations=input_data.aggregations,
                group_by=input_data.group_by,
                order_by=input_data.order_by,
                limit=input_data.limit,
            )

            # Execute query with timing
            with self._audit.timed_operation(invocation_id, input_data.backend.value, "query"):
                result = await connector.execute_intent(intent_query)

            # Apply PII policy to results
            processed_rows, pii_cols, pii_types = self._apply_pii_policy(
                result.rows,
                result.columns,
                input_data.pii_policy,
            )

            # Log PII detection
            if pii_cols or result.pii_columns_detected:
                all_pii_cols = list(set(pii_cols + result.pii_columns_detected))
                all_pii_types = list(set(pii_types + result.pii_types_detected))

                self._audit.log_pii_detection(
                    invocation_id=invocation_id,
                    detected_types=all_pii_types,
                    affected_columns=all_pii_cols,
                    row_count=len(result.rows),
                )

                # Log policy application
                policy_action = PIIPolicyAction(input_data.pii_policy.value)
                self._audit.log_policy_applied(
                    invocation_id=invocation_id,
                    policy=policy_action,
                    columns_affected=all_pii_cols,
                    action_taken=f"Applied {policy_action.value} to {len(all_pii_cols)} columns",
                )

            # Close connection
            await connector.disconnect()

            return QueryDataOutput(
                success=True,
                data=processed_rows,
                row_count=len(processed_rows),
                columns=result.columns,
                metadata={
                    "backend": input_data.backend.value,
                    "invocation_id": invocation_id,
                    **result.metadata,
                },
                pii_status={
                    "policy_applied": input_data.pii_policy.value,
                    "pii_detected": bool(pii_cols or result.pii_columns_detected),
                    "columns_processed": list(set(pii_cols + result.pii_columns_detected)),
                    "pii_types": list(set(pii_types + result.pii_types_detected)),
                },
            )

        except ValueError as e:
            # Validation errors (including SQL rejection)
            error_msg = create_safe_error_message(e)
            if invocation_id:
                self._audit.log_access_denied(
                    invocation_id=invocation_id,
                    reason=error_msg,
                    backend=arguments.get("backend"),
                )
            return QueryDataOutput(
                success=False,
                error=error_msg,
                metadata={"invocation_id": invocation_id} if invocation_id else {},
            )

        except PermissionError as e:
            # Access denied
            error_msg = str(e)
            if invocation_id:
                self._audit.log_access_denied(
                    invocation_id=invocation_id,
                    reason=error_msg,
                    backend=arguments.get("backend"),
                )
            return QueryDataOutput(
                success=False,
                error=error_msg,
                metadata={"invocation_id": invocation_id} if invocation_id else {},
            )

        except Exception as e:
            # Unexpected errors
            error_msg = create_safe_error_message(e)
            if invocation_id:
                self._audit.log_error(
                    invocation_id=invocation_id,
                    error_type=type(e).__name__,
                    error_message=error_msg,
                    backend=arguments.get("backend"),
                )
            return QueryDataOutput(
                success=False,
                error=f"Query execution failed: {error_msg}",
                metadata={"invocation_id": invocation_id} if invocation_id else {},
            )

    def _apply_pii_policy(
        self,
        rows: list[dict[str, Any]],
        columns: list[str],
        policy: PIIPolicy,
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """
        Apply PII policy to query results.

        This is an additional layer of protection on top of what
        the connector already does.

        Args:
            rows: Query result rows.
            columns: Column names.
            policy: PII policy to apply.

        Returns:
            Tuple of (processed_rows, pii_columns, pii_types).

        Raises:
            ValueError: If policy is DENY and PII is detected.
        """
        if not rows:
            return rows, [], []

        # Detect PII in all rows
        has_pii, pii_types, column_pii = self._detector.detect_in_rows(rows)

        if not has_pii:
            return rows, [], []

        pii_cols = list(column_pii.keys())

        # Handle DENY policy
        if policy == PIIPolicy.DENY:
            raise ValueError(
                f"PII detected in output columns: {pii_cols}. Query rejected due to 'deny' policy."
            )

        # Apply HASH policy
        if policy == PIIPolicy.HASH:
            processed = self._hasher.hash_rows(rows, pii_cols)
            return processed, pii_cols, list(pii_types)

        # Apply MASK policy (default)
        processed, _ = self._redactor.redact_rows(rows, set(pii_cols))
        return processed, pii_cols, list(pii_types)
