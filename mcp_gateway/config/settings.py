"""Configuration settings for the MCP Secure Gateway."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class SnowflakeSettings(BaseSettings):
    """Snowflake connection settings."""

    model_config = SettingsConfigDict(env_prefix="SNOWFLAKE_")

    account: str = Field(default="", description="Snowflake account identifier")
    user: str = Field(default="", description="Snowflake username")
    password: SecretStr = Field(default=SecretStr(""), description="Snowflake password")
    warehouse: str = Field(default="", description="Snowflake warehouse")
    database: str = Field(default="", description="Default database")
    schema_name: str = Field(default="PUBLIC", alias="schema", description="Default schema")
    role: str = Field(default="", description="Snowflake role")


class DatabricksSettings(BaseSettings):
    """Databricks connection settings."""

    model_config = SettingsConfigDict(env_prefix="DATABRICKS_")

    host: str = Field(default="", description="Databricks workspace URL")
    http_path: str = Field(default="", description="SQL warehouse HTTP path")
    access_token: SecretStr = Field(default=SecretStr(""), description="Access token")
    catalog: str = Field(default="", description="Unity Catalog name")
    schema_name: str = Field(default="default", alias="schema", description="Default schema")


class TrinoSettings(BaseSettings):
    """Trino/Starburst connection settings."""

    model_config = SettingsConfigDict(env_prefix="TRINO_")

    host: str = Field(default="localhost", description="Trino coordinator host")
    port: int = Field(default=8080, description="Trino coordinator port")
    user: str = Field(default="", description="Trino username")
    password: SecretStr = Field(default=SecretStr(""), description="Trino password")
    catalog: str = Field(default="", description="Default catalog")
    schema_name: str = Field(default="", alias="schema", description="Default schema")
    http_scheme: Literal["http", "https"] = Field(default="https", description="HTTP scheme")


class BigQuerySettings(BaseSettings):
    """Google BigQuery connection settings."""

    model_config = SettingsConfigDict(env_prefix="BIGQUERY_")

    project_id: str = Field(default="", description="GCP project ID")
    dataset: str = Field(default="", description="Default dataset")
    credentials_path: str = Field(default="", description="Path to service account JSON")
    location: str = Field(default="US", description="Dataset location")


class GCSSettings(BaseSettings):
    """Google Cloud Storage settings."""

    model_config = SettingsConfigDict(env_prefix="GCS_")

    project_id: str = Field(default="", description="GCP project ID")
    credentials_path: str = Field(default="", description="Path to service account JSON")
    allowed_buckets: list[str] = Field(default_factory=list, description="Allowed bucket names")


class AthenaSettings(BaseSettings):
    """AWS Athena connection settings."""

    model_config = SettingsConfigDict(env_prefix="ATHENA_")

    region: str = Field(default="us-east-1", description="AWS region")
    database: str = Field(default="", description="Default database")
    workgroup: str = Field(default="primary", description="Athena workgroup")
    output_location: str = Field(default="", description="S3 output location for query results")


class S3Settings(BaseSettings):
    """AWS S3 settings."""

    model_config = SettingsConfigDict(env_prefix="S3_")

    region: str = Field(default="us-east-1", description="AWS region")
    allowed_buckets: list[str] = Field(default_factory=list, description="Allowed bucket names")
    allowed_prefixes: list[str] = Field(default_factory=list, description="Allowed key prefixes")


class GlueSettings(BaseSettings):
    """AWS Glue settings."""

    model_config = SettingsConfigDict(env_prefix="GLUE_")

    region: str = Field(default="us-east-1", description="AWS region")
    database: str = Field(default="", description="Default Glue database")


class PIISettings(BaseSettings):
    """PII detection and handling settings."""

    model_config = SettingsConfigDict(env_prefix="PII_")

    hash_salt: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="Salt for deterministic hashing",
    )
    default_policy: Literal["mask", "hash", "deny"] = Field(
        default="mask",
        description="Default PII handling policy",
    )
    policies_path: str = Field(
        default="",
        description="Path to custom policies.yaml file",
    )
    allow_insecure_salt: bool = Field(
        default=False,
        description="Set to True to allow insecure default salt (NOT for production)",
    )

    def validate_salt_security(self) -> None:
        """
        Validate that a secure salt is configured.

        Call this method at startup to ensure production security.

        Raises:
            ValueError: If default salt is used without explicit override.
        """
        default_salt = "change-me-in-production"
        if (
            self.hash_salt.get_secret_value() == default_salt
            and not self.allow_insecure_salt
        ):
            raise ValueError(
                "SECURITY ERROR: Using default PII hash salt in production is not allowed. "
                "Please set the PII_HASH_SALT environment variable to a secure random value. "
                "If you are in development/testing, set PII_ALLOW_INSECURE_SALT=true to bypass."
            )


class AuditSettings(BaseSettings):
    """Audit logging settings."""

    model_config = SettingsConfigDict(env_prefix="AUDIT_")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Audit log level",
    )
    log_path: str = Field(default="", description="Path for audit log files")
    log_to_stdout: bool = Field(default=True, description="Also log to stdout")


class GatewaySettings(BaseSettings):
    """Main gateway settings aggregating all subsystem configs."""

    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_nested_delimiter="__",
    )

    # Server settings
    name: str = Field(default="mcp-secure-gateway", description="MCP server name")
    version: str = Field(default="0.1.0", description="Server version")
    max_rows: int = Field(default=1000, description="Maximum rows per query result")
    query_timeout: int = Field(default=300, description="Query timeout in seconds")

    # Subsystem configs
    snowflake: SnowflakeSettings = Field(default_factory=SnowflakeSettings)
    databricks: DatabricksSettings = Field(default_factory=DatabricksSettings)
    trino: TrinoSettings = Field(default_factory=TrinoSettings)
    bigquery: BigQuerySettings = Field(default_factory=BigQuerySettings)
    gcs: GCSSettings = Field(default_factory=GCSSettings)
    athena: AthenaSettings = Field(default_factory=AthenaSettings)
    s3: S3Settings = Field(default_factory=S3Settings)
    glue: GlueSettings = Field(default_factory=GlueSettings)
    pii: PIISettings = Field(default_factory=PIISettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)


@lru_cache
def get_settings() -> GatewaySettings:
    """Get cached gateway settings singleton."""
    return GatewaySettings()


def get_policies_path() -> str:
    """Get the path to the PII policies file."""
    settings = get_settings()
    if settings.pii.policies_path:
        return settings.pii.policies_path
    # Default to policies.yaml in the pii module directory
    return os.path.join(os.path.dirname(__file__), "..", "pii", "policies.yaml")
