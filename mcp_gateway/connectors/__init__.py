"""Backend connectors for the MCP Secure Gateway."""

from mcp_gateway.connectors.aws import AthenaConnector, GlueConnector, S3Connector
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult
from mcp_gateway.connectors.databricks import DatabricksConnector
from mcp_gateway.connectors.gcp import BigQueryConnector, GCSConnector
from mcp_gateway.connectors.snowflake import SnowflakeConnector
from mcp_gateway.connectors.trino import TrinoConnector

# Connector registry for dynamic backend selection
CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = {
    "snowflake": SnowflakeConnector,
    "databricks": DatabricksConnector,
    "trino": TrinoConnector,
    "bigquery": BigQueryConnector,
    "gcs": GCSConnector,
    "athena": AthenaConnector,
    "s3": S3Connector,
    "glue": GlueConnector,
}


def get_connector(backend: str) -> BaseConnector:
    """
    Get a connector instance for the specified backend.

    Args:
        backend: Backend name (e.g., "snowflake", "databricks").

    Returns:
        Configured connector instance.

    Raises:
        ValueError: If backend is not supported.
    """
    backend_lower = backend.lower()
    if backend_lower not in CONNECTOR_REGISTRY:
        raise ValueError(
            f"Unsupported backend: {backend}. Available backends: {list(CONNECTOR_REGISTRY.keys())}"
        )
    return CONNECTOR_REGISTRY[backend_lower]()


__all__ = [
    "CONNECTOR_REGISTRY",
    "AthenaConnector",
    "BaseConnector",
    "BigQueryConnector",
    "DatabricksConnector",
    "GCSConnector",
    "GlueConnector",
    "IntentQuery",
    "QueryResult",
    "S3Connector",
    "SnowflakeConnector",
    "TrinoConnector",
    "get_connector",
]
