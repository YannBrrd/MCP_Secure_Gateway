"""
MCP Secure Gateway Server

This server implements three Advanced Tool Use patterns from Anthropic:

1. **Tool Search Tool**: A meta-tool for dynamic discovery. Instead of
   loading all tool definitions upfront (token overhead), the agent sees
   only `search_tools` + `query_data` by default. Other tools are
   discoverable on demand via search_tools.

2. **Tool Use Examples**: Each tool includes `input_examples` that teach
   the model correct invocation patterns beyond what JSON schemas express.

3. **Programmatic Tool Calling**: The `batch_query` tool allows executing
   multiple queries in one call, avoiding N round-trips and keeping
   intermediate results out of the context window.

Core Security Guarantees:
- The agent NEVER receives raw PII
- The agent NEVER sends raw SQL
- All data passes through PII detection and policy enforcement
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListToolsResult,
    TextContent,
    Tool,
    ToolAnnotations,
)

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.config import get_settings
from mcp_gateway.tools import (
    BatchQueryTool,
    CheckPIIPolicyTool,
    DescribeEntityTool,
    ListBackendsTool,
    QueryDataTool,
    SearchToolsTool,
)

# MCP annotations per tool for standard hints
TOOL_ANNOTATIONS: dict[str, ToolAnnotations] = {
    "search_tools": ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
    "query_data": ToolAnnotations(
        readOnlyHint=True,
    ),
    "list_backends": ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
    "describe_entity": ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
    "check_pii_policy": ToolAnnotations(
        readOnlyHint=True,
        idempotentHint=True,
    ),
    "batch_query": ToolAnnotations(
        readOnlyHint=True,
    ),
}

# Tools always loaded in context vs. deferred (Tool Search pattern)
ALWAYS_LOADED_TOOLS = {"search_tools", "query_data"}


def _build_tool_definition(tool_instance: Any) -> Tool:
    """
    Build an MCP Tool definition with annotations, examples, and defer metadata.

    Implements all three Advanced Tool Use patterns:
    - Tool annotations for MCP-standard hints (readOnly, idempotent)
    - Tool meta with defer_loading flag for the Tool Search pattern
    - Input examples appended to description for Tool Use Examples pattern
    """
    description = tool_instance.description

    # Append examples to description for model guidance
    if hasattr(tool_instance, "input_examples") and tool_instance.input_examples:
        examples_text = "\n\nExamples:"
        for ex in tool_instance.input_examples:
            examples_text += f"\n- {ex['description']}: {json.dumps(ex['input'])}"
            if "output_summary" in ex:
                examples_text += f"\n  → {ex['output_summary']}"
        description += examples_text

    # Build meta dict with defer_loading and structured examples
    meta: dict[str, Any] = {
        "defer_loading": tool_instance.name not in ALWAYS_LOADED_TOOLS,
    }
    if hasattr(tool_instance, "input_examples") and tool_instance.input_examples:
        meta["input_examples"] = tool_instance.input_examples

    return Tool.model_validate({
        "name": tool_instance.name,
        "description": description,
        "inputSchema": tool_instance.input_schema,
        "annotations": TOOL_ANNOTATIONS.get(tool_instance.name),
        "_meta": meta,
    })


def create_server() -> Server:
    """
    Create and configure the MCP server.

    Tool Loading Strategy (Tool Search pattern):
    - Always loaded: search_tools, query_data (core functionality)
    - Discoverable: list_backends, describe_entity, check_pii_policy, batch_query

    When clients call list_tools(), they get ALL tools. But for API-level
    consumers using defer_loading, only the always-loaded tools consume
    context tokens. The search_tools meta-tool discovers the rest.

    Returns:
        Configured MCP Server instance.
    """
    settings = get_settings()
    server = Server(settings.name)
    _audit = get_audit_logger()

    # Initialize all tools
    search_tool = SearchToolsTool()
    query_tool = QueryDataTool()
    list_backends_tool = ListBackendsTool()
    describe_entity_tool = DescribeEntityTool()
    check_pii_tool = CheckPIIPolicyTool()
    batch_query_tool = BatchQueryTool()

    # Tool registry for dispatch
    tool_registry: dict[str, Any] = {
        search_tool.name: search_tool,
        query_tool.name: query_tool,
        list_backends_tool.name: list_backends_tool,
        describe_entity_tool.name: describe_entity_tool,
        check_pii_tool.name: check_pii_tool,
        batch_query_tool.name: batch_query_tool,
    }

    @server.list_tools()
    async def list_tools() -> ListToolsResult:
        """
        List available tools with annotations and defer_loading metadata.

        All tools are returned for MCP protocol compliance. Clients
        implementing the Tool Search pattern can check
        ``tool.meta.defer_loading`` to decide which definitions to
        load into the model's context upfront vs. discover on demand.
        """
        tools = []
        for _name, tool_instance in tool_registry.items():
            tool_def = _build_tool_definition(tool_instance)
            tools.append(tool_def)

        return ListToolsResult(tools=tools)

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        """
        Handle tool calls.

        Dispatches to the appropriate tool handler from the registry.

        Args:
            name: Tool name.
            arguments: Tool arguments.

        Returns:
            CallToolResult with JSON response.
        """
        if name not in tool_registry:
            available = list(tool_registry.keys())
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "success": False,
                                "error": (
                                    f"Unknown tool: {name}. "
                                    f"Available tools: {available}. "
                                    "Use 'search_tools' to discover tools by capability."
                                ),
                            }
                        ),
                    )
                ],
                isError=True,
            )

        tool_instance = tool_registry[name]
        result = await tool_instance.execute(arguments)

        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=json.dumps(result.to_dict(), default=str),
                )
            ],
            isError=not result.success,
        )

    return server


async def run_server() -> None:
    """Run the MCP server using stdio transport."""
    server = create_server()
    audit = get_audit_logger()

    # Log session start
    _session_id = audit.log_session_start()

    invocation_count = 0

    async with stdio_server() as (read_stream, write_stream):
        try:
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
        finally:
            # Log session end
            audit.log_session_end(total_invocations=invocation_count)


def main() -> None:
    """Main entry point."""
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
