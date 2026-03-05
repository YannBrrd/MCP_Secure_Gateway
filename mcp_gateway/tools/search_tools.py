"""
Tool Search meta-tool for dynamic tool discovery.

This implements the "Tool Search Tool" pattern from Anthropic's Advanced
Tool Use guidance. Instead of loading all tool definitions into the
agent's context upfront (consuming tokens), this tool lets the agent
search for capabilities on demand.

The agent always sees:
  1. search_tools (this meta-tool, ~500 tokens)
  2. query_data (the core tool, always loaded)

All other tools (describe_entity, check_pii_policy, list_backends,
batch_query) are discoverable on demand via this tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


# Tool metadata for search index
TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "query_data",
        "description": (
            "Query data from enterprise platforms using business intent. "
            "Supports Snowflake, Databricks, Trino, BigQuery, Athena. "
            "Never accepts SQL, never returns raw PII."
        ),
        "keywords": [
            "query",
            "data",
            "select",
            "fetch",
            "get",
            "retrieve",
            "search",
            "filter",
            "aggregate",
            "count",
            "sum",
            "average",
            "sales",
            "customers",
            "orders",
        ],
        "category": "data_access",
        "always_loaded": True,
    },
    {
        "name": "list_backends",
        "description": (
            "List available data platform backends and their capabilities. "
            "Use to discover which backends you can query."
        ),
        "keywords": [
            "backends",
            "platforms",
            "connectors",
            "available",
            "list",
            "discover",
            "snowflake",
            "databricks",
            "bigquery",
            "trino",
            "athena",
        ],
        "category": "discovery",
        "always_loaded": False,
    },
    {
        "name": "describe_entity",
        "description": (
            "Describe a table or entity's schema with PII classification. "
            "Shows columns, types, and sensitivity levels without fetching data."
        ),
        "keywords": [
            "describe",
            "schema",
            "table",
            "columns",
            "entity",
            "structure",
            "metadata",
            "pii",
            "classification",
            "sensitivity",
        ],
        "category": "discovery",
        "always_loaded": False,
    },
    {
        "name": "check_pii_policy",
        "description": (
            "Preview PII policy effects on columns. Shows which columns "
            "are classified as PII and what mask/hash/deny would do."
        ),
        "keywords": [
            "pii",
            "policy",
            "mask",
            "hash",
            "deny",
            "privacy",
            "sensitive",
            "redact",
            "check",
            "preview",
            "compliance",
        ],
        "category": "security",
        "always_loaded": False,
    },
    {
        "name": "batch_query",
        "description": (
            "Execute multiple queries in a single call. Reduces round-trips "
            "and context pollution. Supports summary_only mode for token efficiency."
        ),
        "keywords": [
            "batch",
            "multiple",
            "bulk",
            "parallel",
            "many",
            "several",
            "combined",
            "together",
            "summary",
            "efficient",
        ],
        "category": "data_access",
        "always_loaded": False,
    },
]


class SearchToolsInput(BaseModel):
    """Input for the search_tools tool."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Search query describing what you need to do",
    )

    category: str | None = Field(
        default=None,
        description="Optional category filter: 'data_access', 'discovery', or 'security'",
    )


@dataclass
class SearchToolsOutput:
    """Output for the search_tools tool."""

    success: bool
    matches: list[dict[str, Any]] = field(default_factory=list)
    total_tools: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "matches": self.matches,
            "total_tools": self.total_tools,
            "error": self.error,
        }


class SearchToolsTool:
    """
    Meta-tool for discovering available tools on demand.

    Instead of loading all tool definitions upfront (which consumes
    tokens in the context window), this tool allows the agent to
    search for capabilities when needed.

    Always-loaded tools: search_tools, query_data
    Discoverable tools: list_backends, describe_entity, check_pii_policy, batch_query
    """

    @property
    def name(self) -> str:
        return "search_tools"

    @property
    def description(self) -> str:
        return (
            "Search for available tools by capability. Describe what you need to do "
            "and this tool returns matching tools with their descriptions and schemas. "
            "Use this to discover tools instead of guessing tool names."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 200,
                    "description": "What do you need to do? (e.g., 'explore table schema')",
                },
                "category": {
                    "type": "string",
                    "enum": ["data_access", "discovery", "security"],
                    "description": "Optional category filter",
                },
            },
            "required": ["query"],
        }

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """Example invocations for this tool."""
        return [
            {
                "description": "Find tools for exploring a table's structure",
                "input": {"query": "explore table schema columns"},
                "output_summary": "Returns describe_entity tool with its full schema",
            },
            {
                "description": "Find tools for querying multiple tables at once",
                "input": {"query": "query multiple tables batch"},
                "output_summary": "Returns batch_query tool for multi-query execution",
            },
            {
                "description": "Find security-related tools",
                "input": {"query": "PII privacy", "category": "security"},
                "output_summary": "Returns check_pii_policy tool",
            },
        ]

    async def execute(self, arguments: dict[str, Any]) -> SearchToolsOutput:
        """Search for tools matching the query."""
        try:
            input_data = SearchToolsInput(**arguments)
            query_lower = input_data.query.lower()
            query_words = set(re.split(r"\W+", query_lower))

            matches = []

            for tool in TOOL_CATALOG:
                # Category filter
                if input_data.category and tool["category"] != input_data.category:
                    continue

                # Score by keyword overlap
                tool_keywords = set(tool["keywords"])
                overlap = query_words & tool_keywords

                # Also check if query words appear in description
                desc_lower = tool["description"].lower()
                desc_matches = sum(1 for w in query_words if w in desc_lower and len(w) > 2)

                score = len(overlap) * 2 + desc_matches

                if score > 0:
                    matches.append(
                        {
                            "name": tool["name"],
                            "description": tool["description"],
                            "category": tool["category"],
                            "relevance_score": score,
                            "always_loaded": tool["always_loaded"],
                        }
                    )

            # Sort by relevance
            matches.sort(key=lambda m: m["relevance_score"], reverse=True)

            return SearchToolsOutput(
                success=True,
                matches=matches,
                total_tools=len(TOOL_CATALOG),
            )

        except Exception as e:
            return SearchToolsOutput(
                success=False,
                error=str(e),
            )
