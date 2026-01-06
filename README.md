# MCP Secure Gateway

[![CI](https://github.com/YannBrrd/MCP_Secure_Gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/YannBrrd/MCP_Secure_Gateway/actions/workflows/ci.yml)

A Model Context Protocol (MCP) server that acts as a **Secure Data Gateway** with strict enterprise-grade guarantees for PII protection.

## Overview

This gateway is the **ONLY** MCP server that should be exposed to AI agents when accessing enterprise data. It provides:

- **PII Protection**: No raw PII ever reaches the agent
- **No Raw SQL**: Agents use business intent, not SQL
- **Multi-Backend Support**: Snowflake, Databricks, Trino, BigQuery, Athena
- **Audit Logging**: Complete audit trail for compliance
- **Policy Enforcement**: Configurable mask/hash/deny policies

## Security Guarantees

| Guarantee | Description |
|-----------|-------------|
| No PII Leakage | All data is processed through PII detection before returning |
| No SQL Injection | Intent-based queries only; SQL patterns are rejected |
| Audit Trail | Every operation is logged with correlation IDs |
| Policy Enforcement | PII handling policy is enforced at the boundary |

## Installation

```bash
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

## Configuration

Configure via environment variables:

```bash
# Backend connections
export SNOWFLAKE_ACCOUNT="your-account"
export SNOWFLAKE_USER="your-user"
export SNOWFLAKE_PASSWORD="your-password"
export SNOWFLAKE_WAREHOUSE="your-warehouse"
export SNOWFLAKE_DATABASE="your-database"

export DATABRICKS_HOST="your-workspace.databricks.com"
export DATABRICKS_HTTP_PATH="/sql/1.0/warehouses/xxx"
export DATABRICKS_ACCESS_TOKEN="your-token"

# PII settings
export PII_HASH_SALT="your-secret-salt"
export PII_DEFAULT_POLICY="mask"  # mask | hash | deny

# Audit settings
export AUDIT_LOG_LEVEL="INFO"
export AUDIT_LOG_PATH="/var/log/mcp-gateway/audit.log"
```

## Usage

### Starting the Server

```bash
mcp-gateway
# Or
python -m mcp_gateway.server
```

### MCP Tool: query_data

The gateway exposes exactly **ONE** tool:

```json
{
  "name": "query_data",
  "input": {
    "backend": "snowflake | databricks | trino | bigquery | athena",
    "intent": "Business intent describing what data you need",
    "filters": {"column": "value"},
    "pii_policy": "mask | hash | deny",
    "entity": "optional table name",
    "aggregations": ["SUM(amount)"],
    "group_by": ["region"],
    "order_by": ["total DESC"],
    "limit": 100
  }
}
```

### Example Requests

**Get customer counts by region:**
```json
{
  "backend": "snowflake",
  "intent": "Get total customer counts grouped by region",
  "entity": "customers",
  "aggregations": ["COUNT(*) as total"],
  "group_by": ["region"],
  "pii_policy": "mask"
}
```

**Find high-value orders:**
```json
{
  "backend": "databricks",
  "intent": "Find orders with total value over 1000",
  "filters": {"status": "completed"},
  "pii_policy": "hash"
}
```

## PII Handling

### Detection
- Email addresses
- Phone numbers (US and international)
- SSN
- IBAN
- Credit card numbers
- IP addresses
- Dates of birth

### Classification
Columns are classified based on naming patterns:
- Exact matches: `email`, `phone`, `ssn`, etc.
- Contains patterns: `_email`, `first_name`, `address`
- Regex patterns: `name_?(?:first|last|full)?`

### Policies

| Policy | Behavior |
|--------|----------|
| `mask` | Replace PII with asterisks (e.g., `jo***@***.***`) |
| `hash` | Replace with deterministic hash (e.g., `HASH_A1B2C3...`) |
| `deny` | Reject query if PII is detected in results |

## Adding New Connectors

1. Create a new connector in `mcp_gateway/connectors/`:

```python
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult

class MyConnector(BaseConnector):
    @property
    def backend_name(self) -> str:
        return "mybackend"

    async def connect(self) -> None:
        # Initialize connection
        pass

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        # Execute query and return PII-processed results
        pass
```

2. Register in `mcp_gateway/connectors/__init__.py`:

```python
CONNECTOR_REGISTRY["mybackend"] = MyConnector
```

3. Add settings in `mcp_gateway/config/settings.py`

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_gateway --cov-report=html

# Run specific test file
pytest tests/test_pii_flow.py -v
```

## Architecture

```
mcp_gateway/
├── server.py           # MCP server entry point
├── tools/
│   └── query_data.py   # The single exposed tool
├── pii/
│   ├── detector.py     # Value-based PII detection
│   ├── classifier.py   # Schema-based classification
│   └── policies.yaml   # Detection patterns and rules
├── connectors/
│   ├── base.py         # Abstract connector interface
│   ├── snowflake.py    # Snowflake connector
│   ├── databricks.py   # Databricks connector
│   ├── trino.py        # Trino/Starburst connector
│   ├── gcp.py          # BigQuery and GCS connectors
│   └── aws/            # Athena, S3, Glue connectors
├── security/
│   ├── hashing.py      # Deterministic PII hashing
│   └── redaction.py    # PII masking utilities
├── audit/
│   └── logger.py       # Structured audit logging
└── config/
    └── settings.py     # Environment-based configuration
```

## License

MIT
