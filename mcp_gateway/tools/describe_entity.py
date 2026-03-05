"""
Tool to describe an entity (table/dataset) and its PII classification.

This tool lets agents explore schemas before querying, understanding
which columns exist and which are classified as PII, without
retrieving any actual data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.connectors import get_connector
from mcp_gateway.pii import PIIClassifier
from mcp_gateway.security import create_safe_error_message


class DescribeEntityInput(BaseModel):
    """Input for the describe_entity tool."""

    backend: str = Field(
        ...,
        description="Target data platform: snowflake, databricks, trino, bigquery, or athena",
    )

    entity: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Table or entity name to describe (e.g., 'customers', 'orders')",
    )

    database: str | None = Field(
        default=None,
        description="Optional database/catalog name",
    )

    schema_name: str | None = Field(
        default=None,
        description="Optional schema name",
    )


@dataclass
class DescribeEntityOutput:
    """Output for the describe_entity tool."""

    success: bool
    entity: str = ""
    backend: str = ""
    columns: list[dict[str, Any]] = field(default_factory=list)
    pii_summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "entity": self.entity,
            "backend": self.backend,
            "columns": self.columns,
            "pii_summary": self.pii_summary,
            "error": self.error,
        }


class DescribeEntityTool:
    """
    Describes an entity's schema with PII classification.

    Returns column names, types, and PII sensitivity levels without
    fetching any actual data. Helps agents understand what data is
    available and what PII protections will apply.
    """

    def __init__(self) -> None:
        self._audit = get_audit_logger()
        self._classifier = PIIClassifier()

    @property
    def name(self) -> str:
        return "describe_entity"

    @property
    def description(self) -> str:
        return (
            "Describe a table or entity's schema, including column names and PII "
            "classification. Returns which columns contain PII and their sensitivity "
            "levels, without fetching any actual data. Use this before query_data to "
            "understand the schema and plan your query."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "backend": {
                    "type": "string",
                    "enum": ["snowflake", "databricks", "trino", "bigquery", "athena"],
                    "description": "Target data platform",
                },
                "entity": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "description": "Table or entity name to describe",
                },
                "database": {
                    "type": "string",
                    "description": "Optional database/catalog name",
                },
                "schema_name": {
                    "type": "string",
                    "description": "Optional schema name",
                },
            },
            "required": ["backend", "entity"],
        }

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """Example invocations for this tool."""
        return [
            {
                "description": "Describe the customers table in Snowflake",
                "input": {"backend": "snowflake", "entity": "customers"},
                "output_summary": (
                    "Returns columns like id (not PII), email (high PII), "
                    "first_name (medium PII), status (not PII)"
                ),
            },
            {
                "description": "Describe a specific table in a database and schema",
                "input": {
                    "backend": "bigquery",
                    "entity": "orders",
                    "database": "analytics",
                    "schema_name": "public",
                },
                "output_summary": "Returns columns with PII classification for the orders table",
            },
        ]

    async def execute(self, arguments: dict[str, Any]) -> DescribeEntityOutput:
        """Execute the describe_entity tool."""
        invocation_id = None

        try:
            input_data = DescribeEntityInput(**arguments)

            invocation_id = self._audit.log_tool_invocation(
                tool_name=self.name,
                backend=input_data.backend,
                intent=f"describe entity: {input_data.entity}",
                pii_policy="none",
            )

            connector = get_connector(input_data.backend)

            # Get schema metadata from backend
            schema_meta = await connector.get_schema_metadata(
                database=input_data.database,
                schema=input_data.schema_name,
                table=input_data.entity,
            )

            await connector.disconnect()

            # Extract column names from metadata
            columns = schema_meta.get("columns", [])
            column_names = [
                c["name"] if isinstance(c, dict) else c for c in columns
            ]

            # Classify each column for PII
            classified_columns = []
            pii_columns = []
            for col_name in column_names:
                classification = self._classifier.classify_column(
                    col_name, input_data.backend
                )
                col_info = {
                    "name": col_name,
                    "is_pii": classification.is_pii,
                    "sensitivity": classification.sensitivity.value,
                    "pii_category": classification.pii_category,
                }
                classified_columns.append(col_info)
                if classification.is_pii:
                    pii_columns.append(col_name)

            pii_summary = {
                "has_pii": bool(pii_columns),
                "pii_column_count": len(pii_columns),
                "total_columns": len(column_names),
                "pii_columns": pii_columns,
            }

            return DescribeEntityOutput(
                success=True,
                entity=input_data.entity,
                backend=input_data.backend,
                columns=classified_columns,
                pii_summary=pii_summary,
            )

        except Exception as e:
            error_msg = create_safe_error_message(e)
            if invocation_id:
                self._audit.log_error(
                    invocation_id=invocation_id,
                    error_type=type(e).__name__,
                    error_message=error_msg,
                    backend=arguments.get("backend"),
                )
            return DescribeEntityOutput(
                success=False,
                error=error_msg,
            )
