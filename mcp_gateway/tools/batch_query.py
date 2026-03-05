"""
Batch query tool for programmatic tool calling patterns.

This tool allows executing multiple queries in a single call,
reducing round-trip overhead and context window pollution.
Results are returned as a compact summary, keeping intermediate
data out of the agent's context.

This implements the "Programmatic Tool Calling" pattern from
Anthropic's Advanced Tool Use guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field, field_validator

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.security import create_safe_error_message
from mcp_gateway.tools.query_data import QueryDataTool


class SingleQuery(BaseModel):
    """A single query within a batch."""

    query_id: str = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Unique identifier for this query within the batch",
    )

    backend: str = Field(
        ...,
        description="Target data platform",
    )

    intent: str = Field(
        ...,
        min_length=5,
        max_length=500,
        description="Business intent (NOT SQL)",
    )

    filters: dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value filters",
    )

    pii_policy: str = Field(
        default="mask",
        description="PII policy: mask, hash, or deny",
    )

    entity: str | None = Field(default=None)
    aggregations: list[str] = Field(default_factory=list)
    group_by: list[str] = Field(default_factory=list)
    order_by: list[str] = Field(default_factory=list)
    limit: int = Field(default=100, ge=1, le=1000)


class BatchQueryInput(BaseModel):
    """Input for the batch_query tool."""

    queries: list[SingleQuery] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="List of queries to execute (max 10)",
    )

    summary_only: bool = Field(
        default=False,
        description=(
            "If true, return only row counts and metadata per query, "
            "not the full data. Reduces token usage for large result sets."
        ),
    )

    @field_validator("queries")
    @classmethod
    def validate_unique_ids(cls, v: list[SingleQuery]) -> list[SingleQuery]:
        """Ensure all query IDs are unique."""
        ids = [q.query_id for q in v]
        if len(ids) != len(set(ids)):
            raise ValueError("All query_id values must be unique within a batch")
        return v


@dataclass
class BatchQueryOutput:
    """Output for the batch_query tool."""

    success: bool
    total_queries: int = 0
    successful: int = 0
    failed: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "total_queries": self.total_queries,
            "successful": self.successful,
            "failed": self.failed,
            "results": self.results,
            "error": self.error,
        }


class BatchQueryTool:
    """
    Execute multiple queries in a single tool call.

    This implements the "Programmatic Tool Calling" pattern: instead of
    the agent making N separate query_data calls (consuming N round-trips
    and flooding the context with intermediate results), it batches them
    into one call.

    With summary_only=true, only metadata and row counts are returned,
    keeping large intermediate datasets out of the context window.
    """

    def __init__(self) -> None:
        self._audit = get_audit_logger()
        self._query_tool = QueryDataTool()

    @property
    def name(self) -> str:
        return "batch_query"

    @property
    def description(self) -> str:
        return (
            "Execute multiple data queries in a single call. Reduces round-trip "
            "overhead when you need data from multiple backends or entities. "
            "Use summary_only=true to get row counts and metadata without full "
            "data, keeping your context clean. Max 10 queries per batch."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "queries": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "properties": {
                            "query_id": {
                                "type": "string",
                                "description": "Unique ID for this query in the batch",
                            },
                            "backend": {
                                "type": "string",
                                "enum": [
                                    "snowflake",
                                    "databricks",
                                    "trino",
                                    "bigquery",
                                    "athena",
                                ],
                                "description": "Target data platform",
                            },
                            "intent": {
                                "type": "string",
                                "description": "Business intent (NOT SQL)",
                            },
                            "filters": {
                                "type": "object",
                                "additionalProperties": True,
                                "description": "Key-value filters",
                            },
                            "pii_policy": {
                                "type": "string",
                                "enum": ["mask", "hash", "deny"],
                                "default": "mask",
                            },
                            "entity": {"type": "string"},
                            "aggregations": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "group_by": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "order_by": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "limit": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 1000,
                                "default": 100,
                            },
                        },
                        "required": ["query_id", "backend", "intent"],
                    },
                    "description": "List of queries to execute",
                },
                "summary_only": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Return only metadata and row counts (no data). "
                        "Dramatically reduces tokens in context."
                    ),
                },
            },
            "required": ["queries"],
        }

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """Example invocations for this tool."""
        return [
            {
                "description": "Query sales from two backends in one call",
                "input": {
                    "queries": [
                        {
                            "query_id": "us_sales",
                            "backend": "snowflake",
                            "intent": "Get total sales by region for US",
                            "filters": {"country": "US"},
                            "pii_policy": "mask",
                        },
                        {
                            "query_id": "eu_sales",
                            "backend": "bigquery",
                            "intent": "Get total sales by region for EU",
                            "filters": {"country": "EU"},
                            "pii_policy": "mask",
                        },
                    ],
                    "summary_only": False,
                },
                "output_summary": "Returns both result sets with query_id for correlation",
            },
            {
                "description": "Get row counts only from multiple tables (saves tokens)",
                "input": {
                    "queries": [
                        {
                            "query_id": "customers",
                            "backend": "snowflake",
                            "intent": "Count all customers",
                            "entity": "customers",
                        },
                        {
                            "query_id": "orders",
                            "backend": "snowflake",
                            "intent": "Count all orders",
                            "entity": "orders",
                        },
                    ],
                    "summary_only": True,
                },
                "output_summary": (
                    "Returns only row counts and metadata, no actual data rows. "
                    "Token usage drops from ~150K to ~2K for large datasets."
                ),
            },
        ]

    async def execute(self, arguments: dict[str, Any]) -> BatchQueryOutput:
        """Execute the batch_query tool."""
        try:
            input_data = BatchQueryInput(**arguments)

            invocation_id = self._audit.log_tool_invocation(
                tool_name=self.name,
                backend="batch",
                intent=f"batch query: {len(input_data.queries)} queries",
                pii_policy="mixed",
            )

            results = []
            successful = 0
            failed = 0

            for query in input_data.queries:
                query_args = {
                    "backend": query.backend,
                    "intent": query.intent,
                    "filters": query.filters,
                    "pii_policy": query.pii_policy,
                    "entity": query.entity,
                    "aggregations": query.aggregations,
                    "group_by": query.group_by,
                    "order_by": query.order_by,
                    "limit": query.limit,
                }

                result = await self._query_tool.execute(query_args)
                result_dict = result.to_dict()

                if input_data.summary_only:
                    # Strip actual data to save tokens
                    result_dict = {
                        "query_id": query.query_id,
                        "success": result_dict["success"],
                        "row_count": result_dict["row_count"],
                        "columns": result_dict["columns"],
                        "pii_status": result_dict["pii_status"],
                        "metadata": result_dict["metadata"],
                        "error": result_dict.get("error"),
                    }
                else:
                    result_dict["query_id"] = query.query_id

                results.append(result_dict)

                if result.success:
                    successful += 1
                else:
                    failed += 1

            return BatchQueryOutput(
                success=failed == 0,
                total_queries=len(input_data.queries),
                successful=successful,
                failed=failed,
                results=results,
            )

        except Exception as e:
            error_msg = create_safe_error_message(e)
            return BatchQueryOutput(
                success=False,
                error=f"Batch query failed: {error_msg}",
            )
