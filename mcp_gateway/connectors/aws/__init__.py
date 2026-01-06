"""AWS connectors for the MCP Secure Gateway."""

from mcp_gateway.connectors.aws.athena import AthenaConnector
from mcp_gateway.connectors.aws.glue import GlueConnector
from mcp_gateway.connectors.aws.s3 import S3Connector

__all__ = [
    "AthenaConnector",
    "GlueConnector",
    "S3Connector",
]
