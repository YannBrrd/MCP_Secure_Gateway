"""
Tool to list available backends and their status.

This tool helps agents discover which data platforms are available
before making queries. It is lightweight and designed for fast discovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.connectors import CONNECTOR_REGISTRY


@dataclass
class ListBackendsOutput:
    """Output for the list_backends tool."""

    success: bool
    backends: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "backends": self.backends,
            "error": self.error,
        }


class ListBackendsTool:
    """
    Lists available backend data platforms.

    Returns the list of configured backends with connection status
    and capabilities. Use this before query_data to know which
    backends are available.
    """

    def __init__(self) -> None:
        self._audit = get_audit_logger()

    @property
    def name(self) -> str:
        return "list_backends"

    @property
    def description(self) -> str:
        return (
            "List available data platform backends (Snowflake, Databricks, Trino, "
            "BigQuery, Athena, etc.) and their capabilities. Use this to discover "
            "which backends you can query."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {},
            "required": [],
        }

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """Example invocations for this tool."""
        return [
            {
                "description": "List all available backends",
                "input": {},
                "output_summary": "Returns list of backends with names and capabilities",
            },
        ]

    async def execute(self, arguments: dict[str, Any]) -> ListBackendsOutput:
        """Execute the list_backends tool."""
        invocation_id = self._audit.log_tool_invocation(
            tool_name=self.name,
            backend="all",
            intent="list available backends",
            pii_policy="none",
        )

        backends = []
        for name, connector_cls in CONNECTOR_REGISTRY.items():
            backends.append(
                {
                    "name": name,
                    "connector": connector_cls.__name__,
                    "queryable": name
                    in {"snowflake", "databricks", "trino", "bigquery", "athena"},
                }
            )

        return ListBackendsOutput(
            success=True,
            backends=backends,
        )
