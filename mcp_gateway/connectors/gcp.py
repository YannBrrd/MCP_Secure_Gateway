"""Google Cloud Platform connectors (BigQuery, GCS) for the MCP Secure Gateway."""

from __future__ import annotations

from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult


class BigQueryConnector(BaseConnector):
    """
    Connector for Google BigQuery.

    Uses google-cloud-bigquery for database operations.
    """

    def __init__(self) -> None:
        """Initialize BigQuery connector with settings."""
        super().__init__()
        self._settings = get_settings().bigquery
        self._client: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "bigquery"

    async def connect(self) -> None:
        """Initialize BigQuery client."""
        try:
            from google.cloud import bigquery

            # Use service account if path provided
            if self._settings.credentials_path:
                self._client = bigquery.Client.from_service_account_json(
                    self._settings.credentials_path,
                    project=self._settings.project_id,
                )
            else:
                # Use default credentials (ADC)
                self._client = bigquery.Client(project=self._settings.project_id)

            self._connected = True
        except ImportError:
            raise ImportError(
                "google-cloud-bigquery is required. "
                "Install with: pip install google-cloud-bigquery"
            )

    async def disconnect(self) -> None:
        """Close BigQuery client."""
        if self._client:
            self._client.close()
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query against BigQuery.

        Args:
            query: IntentQuery with business intent and filters.

        Returns:
            QueryResult with PII-processed data.
        """
        if not self._connected:
            await self.connect()

        # Build safe SQL from intent
        sql, params = self._build_safe_query(query)

        # Configure query job
        from google.cloud import bigquery

        job_config = bigquery.QueryJobConfig(
            query_parameters=params,
            maximum_bytes_billed=10 * 1024 * 1024 * 1024,  # 10GB limit
        )

        # Execute query
        query_job = self._client.query(sql, job_config=job_config)
        results = query_job.result()

        # Extract columns and rows
        columns = [field.name for field in results.schema]
        raw_rows = [dict(row.items()) for row in results]

        # Get configured PII policy
        settings = get_settings()
        pii_policy = settings.pii.default_policy

        # Process results
        processed_rows, pii_cols, pii_types = self._process_results_with_policy(
            raw_rows, columns, pii_policy
        )

        return QueryResult(
            rows=processed_rows,
            columns=columns,
            row_count=len(processed_rows),
            metadata={
                "backend": self.backend_name,
                "project": self._settings.project_id,
                "dataset": self._settings.dataset,
                "bytes_processed": query_job.total_bytes_processed,
            },
            pii_columns_detected=pii_cols,
            pii_types_detected=pii_types,
        )

    def _build_safe_query(
        self,
        query: IntentQuery,
    ) -> tuple[str, list[Any]]:
        """
        Build a parameterized SQL query from intent.

        Uses BigQuery's named parameters for safety.

        Args:
            query: The IntentQuery to translate.

        Returns:
            Tuple of (sql_string, parameters_list).
        """
        from google.cloud import bigquery

        intent_lower = query.intent.lower()
        table = query.entity or self._infer_table_from_intent(intent_lower)

        # Fully qualified table name
        dataset = self._settings.dataset
        full_table = f"`{self._settings.project_id}.{dataset}.{table}`"

        # Build SELECT clause
        select_cols = "*"
        if query.aggregations:
            select_cols = ", ".join(query.aggregations)
            if query.group_by:
                select_cols += ", " + ", ".join(query.group_by)

        sql_parts = [f"SELECT {select_cols}", f"FROM {full_table}"]
        params: list[Any] = []

        # Build WHERE clause with named parameters
        if query.filters:
            conditions = []
            for key, value in query.filters.items():
                param_name = f"param_{key}"
                conditions.append(f"{key} = @{param_name}")

                # Create appropriate parameter type
                if isinstance(value, str):
                    params.append(
                        bigquery.ScalarQueryParameter(param_name, "STRING", value)
                    )
                elif isinstance(value, int):
                    params.append(
                        bigquery.ScalarQueryParameter(param_name, "INT64", value)
                    )
                elif isinstance(value, float):
                    params.append(
                        bigquery.ScalarQueryParameter(param_name, "FLOAT64", value)
                    )
                elif isinstance(value, bool):
                    params.append(
                        bigquery.ScalarQueryParameter(param_name, "BOOL", value)
                    )

            sql_parts.append("WHERE " + " AND ".join(conditions))

        # GROUP BY
        if query.group_by:
            sql_parts.append("GROUP BY " + ", ".join(query.group_by))

        # ORDER BY
        if query.order_by:
            sql_parts.append("ORDER BY " + ", ".join(query.order_by))

        # LIMIT
        sql_parts.append(f"LIMIT {min(query.limit, get_settings().max_rows)}")

        return " ".join(sql_parts), params

    def _infer_table_from_intent(self, intent: str) -> str:
        """Infer table name from intent string."""
        intent_table_map = {
            "customer": "customers",
            "user": "users",
            "order": "orders",
            "product": "products",
            "transaction": "transactions",
            "event": "events",
            "analytics": "analytics",
            "log": "logs",
        }

        for keyword, table in intent_table_map.items():
            if keyword in intent:
                return table

        raise ValueError(
            f"Cannot infer table from intent: {intent}. "
            "Please specify entity explicitly."
        )

    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """Get schema metadata from BigQuery."""
        if not self._connected:
            await self.connect()

        dataset_id = database or self._settings.dataset
        dataset_ref = self._client.dataset(dataset_id)

        if table:
            # Get specific table schema
            table_ref = dataset_ref.table(table)
            bq_table = self._client.get_table(table_ref)

            columns = []
            for field in bq_table.schema:
                classification = self._classifier.classify_column(
                    field.name, self.backend_name
                )
                columns.append({
                    "column_name": field.name,
                    "data_type": field.field_type,
                    "nullable": field.mode != "REQUIRED",
                    "is_pii": classification.is_pii,
                    "pii_sensitivity": classification.sensitivity.value,
                })

            return {
                "project": self._settings.project_id,
                "dataset": dataset_id,
                "tables": {table: columns},
            }
        else:
            # Get all tables in dataset
            tables: dict[str, list[dict[str, Any]]] = {}
            for bq_table in self._client.list_tables(dataset_ref):
                full_table = self._client.get_table(bq_table.reference)
                columns = []
                for field in full_table.schema:
                    classification = self._classifier.classify_column(
                        field.name, self.backend_name
                    )
                    columns.append({
                        "column_name": field.name,
                        "data_type": field.field_type,
                        "nullable": field.mode != "REQUIRED",
                        "is_pii": classification.is_pii,
                        "pii_sensitivity": classification.sensitivity.value,
                    })
                tables[bq_table.table_id] = columns

            return {
                "project": self._settings.project_id,
                "dataset": dataset_id,
                "tables": tables,
            }

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List tables in BigQuery dataset."""
        if not self._connected:
            await self.connect()

        dataset_id = database or self._settings.dataset
        dataset_ref = self._client.dataset(dataset_id)

        return [table.table_id for table in self._client.list_tables(dataset_ref)]


class GCSConnector(BaseConnector):
    """
    Read-only connector for Google Cloud Storage.

    Only allows reading from pre-approved buckets and paths.
    Does not execute queries but can list and read objects.
    """

    def __init__(self) -> None:
        """Initialize GCS connector with settings."""
        super().__init__()
        self._settings = get_settings().gcs
        self._client: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "gcs"

    async def connect(self) -> None:
        """Initialize GCS client."""
        try:
            from google.cloud import storage

            if self._settings.credentials_path:
                self._client = storage.Client.from_service_account_json(
                    self._settings.credentials_path,
                    project=self._settings.project_id,
                )
            else:
                self._client = storage.Client(project=self._settings.project_id)

            self._connected = True
        except ImportError:
            raise ImportError(
                "google-cloud-storage is required. "
                "Install with: pip install google-cloud-storage"
            )

    async def disconnect(self) -> None:
        """Close GCS client."""
        if self._client:
            self._client.close()
        self._connected = False

    def _validate_bucket_access(self, bucket_name: str) -> None:
        """Validate that bucket access is allowed."""
        if self._settings.allowed_buckets:
            if bucket_name not in self._settings.allowed_buckets:
                raise PermissionError(
                    f"Access to bucket '{bucket_name}' is not allowed. "
                    f"Allowed buckets: {self._settings.allowed_buckets}"
                )

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        GCS doesn't support SQL queries.

        This method lists objects matching the intent criteria.
        """
        if not self._connected:
            await self.connect()

        # For GCS, intent should describe what to list
        bucket_name = query.entity
        if not bucket_name:
            raise ValueError("GCS requires 'entity' to specify bucket name")

        self._validate_bucket_access(bucket_name)

        prefix = query.filters.get("prefix", "")
        bucket = self._client.bucket(bucket_name)

        # List objects with prefix
        blobs = list(bucket.list_blobs(prefix=prefix, max_results=query.limit))

        rows = [
            {
                "name": blob.name,
                "size_bytes": blob.size,
                "content_type": blob.content_type,
                "updated": blob.updated.isoformat() if blob.updated else None,
            }
            for blob in blobs
        ]

        return QueryResult(
            rows=rows,
            columns=["name", "size_bytes", "content_type", "updated"],
            row_count=len(rows),
            metadata={
                "backend": self.backend_name,
                "bucket": bucket_name,
                "prefix": prefix,
            },
        )

    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """Get GCS bucket metadata."""
        if not self._connected:
            await self.connect()

        if database:
            self._validate_bucket_access(database)
            bucket = self._client.get_bucket(database)
            return {
                "bucket": bucket.name,
                "location": bucket.location,
                "storage_class": bucket.storage_class,
                "created": bucket.time_created.isoformat() if bucket.time_created else None,
            }
        else:
            # List allowed buckets
            buckets = []
            for bucket in self._client.list_buckets():
                if not self._settings.allowed_buckets or bucket.name in self._settings.allowed_buckets:
                    buckets.append({
                        "name": bucket.name,
                        "location": bucket.location,
                    })
            return {"buckets": buckets}

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List allowed GCS buckets."""
        if not self._connected:
            await self.connect()

        buckets = []
        for bucket in self._client.list_buckets():
            if not self._settings.allowed_buckets or bucket.name in self._settings.allowed_buckets:
                buckets.append(bucket.name)
        return buckets
