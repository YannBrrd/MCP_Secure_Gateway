"""
MCP Secure Gateway Server

This is the main entry point for the MCP server. It exposes a single tool
(query_data) that provides secure, PII-safe access to enterprise data platforms.

The agent MUST:
- Use business intent, not SQL
- Specify which backend to query
- Choose a PII policy for result handling

The agent CANNOT:
- Send raw SQL queries
- Receive raw PII in results
- Access backends directly
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
)

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.config import get_settings
from mcp_gateway.tools import QueryDataTool


def create_server() -> Server:
    """
    Create and configure the MCP server.

    Returns:
        Configured MCP Server instance.
    """
    settings = get_settings()
    server = Server(settings.name)
    _audit = get_audit_logger()

    # Initialize tools
    query_tool = QueryDataTool()

    @server.list_tools()
    async def list_tools() -> ListToolsResult:
        """List available tools - only query_data is exposed."""
        return ListToolsResult(
            tools=[
                Tool(
                    name=query_tool.name,
                    description=query_tool.description,
                    inputSchema=query_tool.input_schema,
                )
            ]
        )

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        """
        Handle tool calls.

        Only the query_data tool is available.

        Args:
            name: Tool name (must be "query_data").
            arguments: Tool arguments.

        Returns:
            CallToolResult with JSON response.
        """
        if name != query_tool.name:
            return CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=json.dumps({
                            "success": False,
                            "error": f"Unknown tool: {name}. Only 'query_data' is available.",
                        }),
                    )
                ],
                isError=True,
            )

        # Execute the tool
        result = await query_tool.execute(arguments)

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
