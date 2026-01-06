"""AWS S3 connector for the MCP Secure Gateway."""

from __future__ import annotations

from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult


class S3Connector(BaseConnector):
    """
    Read-only connector for AWS S3.

    Only allows reading from pre-approved buckets and prefixes.
    """

    def __init__(self) -> None:
        """Initialize S3 connector with settings."""
        super().__init__()
        self._settings = get_settings().s3
        self._client: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "s3"

    async def connect(self) -> None:
        """Initialize S3 client."""
        try:
            import boto3

            self._client = boto3.client(
                "s3",
                region_name=self._settings.region,
            )
            self._connected = True
        except ImportError:
            raise ImportError("boto3 is required. Install with: pip install boto3")

    async def disconnect(self) -> None:
        """Close S3 client."""
        self._client = None
        self._connected = False

    def _validate_access(self, bucket: str, prefix: str = "") -> None:
        """
        Validate that access to the bucket/prefix is allowed.

        Args:
            bucket: S3 bucket name.
            prefix: S3 key prefix.

        Raises:
            PermissionError: If access is not allowed.
        """
        if self._settings.allowed_buckets:
            if bucket not in self._settings.allowed_buckets:
                raise PermissionError(
                    f"Access to bucket '{bucket}' is not allowed. "
                    f"Allowed buckets: {self._settings.allowed_buckets}"
                )

        if self._settings.allowed_prefixes and prefix:
            allowed = False
            for allowed_prefix in self._settings.allowed_prefixes:
                if prefix.startswith(allowed_prefix):
                    allowed = True
                    break
            if not allowed:
                raise PermissionError(
                    f"Access to prefix '{prefix}' is not allowed. "
                    f"Allowed prefixes: {self._settings.allowed_prefixes}"
                )

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        S3 doesn't support SQL queries.

        This method lists objects matching the intent criteria.

        Args:
            query: IntentQuery where entity is the bucket name.

        Returns:
            QueryResult with object metadata.
        """
        if not self._connected:
            await self.connect()

        bucket = query.entity
        if not bucket:
            raise ValueError("S3 requires 'entity' to specify bucket name")

        prefix = query.filters.get("prefix", "")
        self._validate_access(bucket, prefix)

        # List objects
        response = self._client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix,
            MaxKeys=min(query.limit, get_settings().max_rows),
        )

        rows = []
        for obj in response.get("Contents", []):
            rows.append(
                {
                    "key": obj["Key"],
                    "size_bytes": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                    "storage_class": obj.get("StorageClass", "STANDARD"),
                }
            )

        return QueryResult(
            rows=rows,
            columns=["key", "size_bytes", "last_modified", "storage_class"],
            row_count=len(rows),
            metadata={
                "backend": self.backend_name,
                "bucket": bucket,
                "prefix": prefix,
                "is_truncated": response.get("IsTruncated", False),
            },
        )

    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """Get S3 bucket metadata."""
        if not self._connected:
            await self.connect()

        if database:
            self._validate_access(database)
            # Get bucket info
            response = self._client.head_bucket(Bucket=database)
            return {
                "bucket": database,
                "region": self._client.get_bucket_location(Bucket=database).get(
                    "LocationConstraint", "us-east-1"
                ),
            }
        else:
            # List accessible buckets
            response = self._client.list_buckets()
            buckets = []
            for bucket in response["Buckets"]:
                if (
                    not self._settings.allowed_buckets
                    or bucket["Name"] in self._settings.allowed_buckets
                ):
                    buckets.append(
                        {
                            "name": bucket["Name"],
                            "created": bucket["CreationDate"].isoformat(),
                        }
                    )
            return {"buckets": buckets}

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List accessible S3 buckets."""
        if not self._connected:
            await self.connect()

        response = self._client.list_buckets()
        buckets = []
        for bucket in response["Buckets"]:
            if (
                not self._settings.allowed_buckets
                or bucket["Name"] in self._settings.allowed_buckets
            ):
                buckets.append(bucket["Name"])
        return buckets

    async def list_prefixes(
        self,
        bucket: str,
        prefix: str = "",
        delimiter: str = "/",
    ) -> list[str]:
        """
        List common prefixes (like directories) in a bucket.

        Args:
            bucket: S3 bucket name.
            prefix: Starting prefix.
            delimiter: Delimiter for grouping (default "/").

        Returns:
            List of common prefixes.
        """
        if not self._connected:
            await self.connect()

        self._validate_access(bucket, prefix)

        response = self._client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix,
            Delimiter=delimiter,
        )

        return [p["Prefix"] for p in response.get("CommonPrefixes", [])]
