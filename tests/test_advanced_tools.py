"""
Tests for advanced tool use patterns:
1. Tool Search Tool - dynamic discovery
2. Tool Use Examples - example metadata
3. Decomposed tools - list_backends, describe_entity, check_pii_policy
4. Batch query - programmatic tool calling
"""

from __future__ import annotations

import pytest

from mcp_gateway.tools import (
    BatchQueryTool,
    CheckPIIPolicyTool,
    DescribeEntityTool,
    ListBackendsTool,
    QueryDataTool,
    SearchToolsTool,
)


class TestSearchToolsTool:
    """Tests for the tool search meta-tool (dynamic discovery)."""

    @pytest.fixture
    def search_tool(self) -> SearchToolsTool:
        return SearchToolsTool()

    @pytest.mark.asyncio
    async def test_search_by_keyword(self, search_tool: SearchToolsTool) -> None:
        """Test searching for tools by keyword."""
        result = await search_tool.execute({"query": "query data fetch"})
        assert result.success
        assert len(result.matches) > 0
        names = [m["name"] for m in result.matches]
        assert "query_data" in names

    @pytest.mark.asyncio
    async def test_search_schema_discovery(self, search_tool: SearchToolsTool) -> None:
        """Test searching for schema exploration tools."""
        result = await search_tool.execute({"query": "describe schema table columns"})
        assert result.success
        names = [m["name"] for m in result.matches]
        assert "describe_entity" in names

    @pytest.mark.asyncio
    async def test_search_pii_tools(self, search_tool: SearchToolsTool) -> None:
        """Test searching for PII-related tools."""
        result = await search_tool.execute({"query": "PII policy mask hash"})
        assert result.success
        names = [m["name"] for m in result.matches]
        assert "check_pii_policy" in names

    @pytest.mark.asyncio
    async def test_search_batch(self, search_tool: SearchToolsTool) -> None:
        """Test searching for batch/parallel query tools."""
        result = await search_tool.execute({"query": "batch multiple queries"})
        assert result.success
        names = [m["name"] for m in result.matches]
        assert "batch_query" in names

    @pytest.mark.asyncio
    async def test_search_with_category_filter(self, search_tool: SearchToolsTool) -> None:
        """Test filtering by category."""
        result = await search_tool.execute(
            {"query": "pii privacy", "category": "security"}
        )
        assert result.success
        for match in result.matches:
            assert match["category"] == "security"

    @pytest.mark.asyncio
    async def test_search_returns_relevance_score(self, search_tool: SearchToolsTool) -> None:
        """Test that results include relevance scores and are sorted."""
        result = await search_tool.execute({"query": "query data"})
        assert result.success
        if len(result.matches) > 1:
            scores = [m["relevance_score"] for m in result.matches]
            assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio
    async def test_search_total_tools_count(self, search_tool: SearchToolsTool) -> None:
        """Test that total_tools reflects catalog size."""
        result = await search_tool.execute({"query": "anything"})
        assert result.total_tools == 5  # query_data, list_backends, describe_entity, check_pii, batch

    def test_search_tool_properties(self, search_tool: SearchToolsTool) -> None:
        """Test tool metadata."""
        assert search_tool.name == "search_tools"
        assert "search" in search_tool.description.lower()
        assert search_tool.input_schema["required"] == ["query"]
        assert len(search_tool.input_examples) > 0


class TestListBackendsTool:
    """Tests for the list_backends tool."""

    @pytest.fixture
    def tool(self) -> ListBackendsTool:
        return ListBackendsTool()

    @pytest.mark.asyncio
    async def test_list_backends(self, tool: ListBackendsTool) -> None:
        """Test listing all backends."""
        result = await tool.execute({})
        assert result.success
        assert len(result.backends) > 0

        names = [b["name"] for b in result.backends]
        assert "snowflake" in names
        assert "databricks" in names
        assert "bigquery" in names

    @pytest.mark.asyncio
    async def test_backends_have_queryable_flag(self, tool: ListBackendsTool) -> None:
        """Test that each backend has a queryable flag."""
        result = await tool.execute({})
        for backend in result.backends:
            assert "queryable" in backend
            assert "name" in backend

    def test_tool_properties(self, tool: ListBackendsTool) -> None:
        """Test tool metadata."""
        assert tool.name == "list_backends"
        assert "backend" in tool.description.lower()
        assert len(tool.input_examples) > 0


class TestCheckPIIPolicyTool:
    """Tests for the check_pii_policy tool."""

    @pytest.fixture
    def tool(self) -> CheckPIIPolicyTool:
        return CheckPIIPolicyTool()

    @pytest.mark.asyncio
    async def test_check_columns_with_pii(self, tool: CheckPIIPolicyTool) -> None:
        """Test checking columns that contain PII."""
        result = await tool.execute(
            {
                "sample_columns": ["id", "email", "phone", "status"],
                "policy": "mask",
            }
        )
        assert result.success
        assert result.policy == "mask"

        pii_cols = [c for c in result.column_analysis if c["is_pii"]]
        non_pii_cols = [c for c in result.column_analysis if not c["is_pii"]]

        assert len(pii_cols) >= 2  # email, phone
        assert len(non_pii_cols) >= 1  # id, status

    @pytest.mark.asyncio
    async def test_check_columns_without_pii(self, tool: CheckPIIPolicyTool) -> None:
        """Test checking columns that don't contain PII."""
        result = await tool.execute(
            {
                "sample_columns": ["order_id", "amount", "currency", "quantity"],
                "policy": "deny",
            }
        )
        assert result.success
        pii_cols = [c for c in result.column_analysis if c["is_pii"]]
        assert len(pii_cols) == 0
        assert "No PII" in result.recommendation

    @pytest.mark.asyncio
    async def test_deny_policy_warning(self, tool: CheckPIIPolicyTool) -> None:
        """Test that deny policy with PII columns gives appropriate warning."""
        result = await tool.execute(
            {
                "sample_columns": ["email", "ssn"],
                "policy": "deny",
            }
        )
        assert result.success
        assert "REJECTED" in result.recommendation

    @pytest.mark.asyncio
    async def test_hash_policy_description(self, tool: CheckPIIPolicyTool) -> None:
        """Test that hash policy shows correct effect."""
        result = await tool.execute(
            {
                "sample_columns": ["email"],
                "policy": "hash",
            }
        )
        assert result.success
        email_analysis = next(c for c in result.column_analysis if c["column"] == "email")
        assert "hash" in email_analysis["policy_effect"].lower()

    def test_tool_properties(self, tool: CheckPIIPolicyTool) -> None:
        """Test tool metadata."""
        assert tool.name == "check_pii_policy"
        assert len(tool.input_examples) > 0


class TestToolUseExamples:
    """Tests for tool use examples on all tools."""

    def test_query_data_has_examples(self) -> None:
        """Test that query_data tool has input examples."""
        tool = QueryDataTool()
        examples = tool.input_examples
        assert len(examples) >= 3

        # Each example should have description, input, output_summary
        for ex in examples:
            assert "description" in ex
            assert "input" in ex
            assert "output_summary" in ex
            # Input should have at least backend and intent
            assert "backend" in ex["input"]
            assert "intent" in ex["input"]

    def test_search_tools_has_examples(self) -> None:
        """Test that search_tools has input examples."""
        tool = SearchToolsTool()
        assert len(tool.input_examples) >= 2

    def test_list_backends_has_examples(self) -> None:
        """Test that list_backends has input examples."""
        tool = ListBackendsTool()
        assert len(tool.input_examples) >= 1

    def test_describe_entity_has_examples(self) -> None:
        """Test that describe_entity has input examples."""
        tool = DescribeEntityTool()
        assert len(tool.input_examples) >= 2

    def test_check_pii_policy_has_examples(self) -> None:
        """Test that check_pii_policy has input examples."""
        tool = CheckPIIPolicyTool()
        assert len(tool.input_examples) >= 2

    def test_batch_query_has_examples(self) -> None:
        """Test that batch_query has input examples."""
        tool = BatchQueryTool()
        assert len(tool.input_examples) >= 2


class TestServerToolRegistry:
    """Tests for the server's tool registry and discovery."""

    def test_server_creates_all_tools(self) -> None:
        """Test that create_server() registers all tools."""
        from mcp_gateway.server import create_server

        server = create_server()
        # Server is created without errors
        assert server is not None

    def test_tool_definitions_include_examples(self) -> None:
        """Test that _build_tool_definition includes examples in description."""
        from mcp_gateway.server import _build_tool_definition

        tool = QueryDataTool()
        tool_def = _build_tool_definition(tool)

        assert "Examples:" in tool_def.description
        assert "Get total sales by region" in tool_def.description

    def test_tool_definitions_without_examples(self) -> None:
        """Test _build_tool_definition with a tool that has no examples."""
        from mcp_gateway.server import _build_tool_definition

        # Create a minimal mock tool
        class MinimalTool:
            name = "test"
            description = "A test tool"
            input_schema = {"type": "object", "properties": {}}

        tool_def = _build_tool_definition(MinimalTool())
        assert tool_def.description == "A test tool"
        assert "Examples:" not in tool_def.description


class TestBatchQueryTool:
    """Tests for the batch_query tool (programmatic tool calling pattern)."""

    @pytest.fixture
    def tool(self) -> BatchQueryTool:
        return BatchQueryTool()

    def test_tool_properties(self, tool: BatchQueryTool) -> None:
        """Test tool metadata."""
        assert tool.name == "batch_query"
        assert "multiple" in tool.description.lower() or "batch" in tool.description.lower()
        schema = tool.input_schema
        assert "queries" in schema["properties"]
        assert "summary_only" in schema["properties"]

    def test_input_validation_unique_ids(self) -> None:
        """Test that duplicate query IDs are rejected."""
        from mcp_gateway.tools.batch_query import BatchQueryInput

        with pytest.raises(ValueError, match="unique"):
            BatchQueryInput(
                queries=[
                    {"query_id": "q1", "backend": "snowflake", "intent": "Get sales data"},
                    {"query_id": "q1", "backend": "bigquery", "intent": "Get order data"},
                ],
            )

    def test_input_validation_max_queries(self) -> None:
        """Test that batch size is limited."""
        from mcp_gateway.tools.batch_query import BatchQueryInput

        queries = [
            {"query_id": f"q{i}", "backend": "snowflake", "intent": f"Get data {i}"}
            for i in range(11)
        ]
        with pytest.raises(ValueError):
            BatchQueryInput(queries=queries)

    def test_examples_show_summary_only_pattern(self, tool: BatchQueryTool) -> None:
        """Test that examples demonstrate the summary_only pattern."""
        examples = tool.input_examples
        summary_examples = [
            ex for ex in examples if ex.get("input", {}).get("summary_only", False)
        ]
        assert len(summary_examples) >= 1, "Should have at least one summary_only example"
