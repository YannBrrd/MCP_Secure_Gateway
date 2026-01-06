# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Secure Gateway is an MCP server that acts as a secure data gateway for enterprise data platforms. It enforces PII protection policies and prevents raw SQL injection.

**Core Principle**: The agent NEVER receives raw PII or sends raw SQL. All data passes through PII detection and policy enforcement.

## Common Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run the MCP server
python -m mcp_gateway.server
# Or using the CLI entry point
mcp-gateway

# Run all tests
pytest

# Run tests with coverage
pytest --cov=mcp_gateway --cov-report=term-missing

# Run specific test file
pytest tests/test_pii_flow.py -v

# Run specific test
pytest tests/test_pii_flow.py::TestPIIDetector::test_detect_email -v

# Type checking
mypy mcp_gateway

# Linting
ruff check mcp_gateway
ruff format mcp_gateway
```

## Architecture

### Request Flow
```
Agent Request → query_data tool → Input Validation (reject SQL)
    → PII check on filters → Backend Connector → Raw Results
    → PII Detection → Policy Enforcement (mask/hash/deny)
    → Safe Response → Agent
```

### Key Components

1. **`server.py`**: MCP server entry point. Exposes only the `query_data` tool.

2. **`tools/query_data.py`**: The single tool implementation. Validates input, rejects SQL, routes to backends, enforces PII policies.

3. **`pii/detector.py`**: Regex-based PII detection in values. Returns `DetectionResult` with matches and types.

4. **`pii/classifier.py`**: Schema-based column classification. Uses column naming patterns to identify PII columns.

5. **`connectors/base.py`**: Abstract `BaseConnector` class. All connectors inherit from this and implement `execute_intent()`.

6. **`security/hashing.py`**: Deterministic HMAC-SHA256 hashing with salt. Produces `HASH_` prefixed outputs.

7. **`security/redaction.py`**: Masking utilities. Type-specific masking rules (email preserves first 2 chars, phone preserves last 4, etc.).

8. **`audit/logger.py`**: Structured JSON logging. Logs tool invocations, PII detection, policy applications, errors. Never logs raw PII values.

### Adding a New Backend

1. Create connector class inheriting from `BaseConnector`
2. Implement: `backend_name`, `connect()`, `disconnect()`, `execute_intent()`, `get_schema_metadata()`, `list_tables()`
3. Register in `connectors/__init__.py` `CONNECTOR_REGISTRY`
4. Add settings class in `config/settings.py`

### PII Policy Enforcement

- **mask**: Uses `PIIRedactor` to replace PII with type-specific masks
- **hash**: Uses `PIIHasher` for deterministic hashing (same input = same hash)
- **deny**: Raises `ValueError` if any PII detected in output

### Intent Query Translation

Connectors translate `IntentQuery` objects to backend-specific queries internally. The agent never sees or sends SQL. The `intent` field is a natural language description; connectors use keyword matching to infer tables.

## Testing Patterns

Tests are in `tests/test_pii_flow.py`. Key test categories:
- `TestPIIDetector`: Value-based detection
- `TestPIIClassifier`: Column classification
- `TestPIIHasher`: Hashing consistency
- `TestPIIRedactor`: Masking behavior
- `TestPIIPolicyEnforcement`: Policy application
- `TestSQLRejection`: SQL pattern detection
- `TestBackendRouting`: Connector selection

Use fixtures from `conftest.py` for sample data:
- `sample_rows_with_pii`
- `sample_rows_without_pii`
- `sample_schema_with_pii`

## Configuration

All settings via environment variables with `GATEWAY_`, `SNOWFLAKE_`, `DATABRICKS_`, etc. prefixes. See `config/settings.py` for full list.

Critical settings:
- `PII_HASH_SALT`: Must be set in production for deterministic hashing
- `PII_DEFAULT_POLICY`: Default policy when not specified (mask/hash/deny)
- `GATEWAY_MAX_ROWS`: Maximum rows per query (default 1000)
