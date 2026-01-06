"""AWS Glue connector for the MCP Secure Gateway."""

from __future__ import annotations

from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult


class GlueConnector(BaseConnector):
    """
    Connector for AWS Glue Data Catalog.

    Provides schema metadata only - no data querying.
    Use Athena or other query engines for actual data access.
    """

    def __init__(self) -> None:
        """Initialize Glue connector with settings."""
        super().__init__()
        self._settings = get_settings().glue
        self._client: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "glue"

    async def connect(self) -> None:
        """Initialize Glue client."""
        try:
            import boto3

            self._client = boto3.client(
                "glue",
                region_name=self._settings.region,
            )
            self._connected = True
        except ImportError:
            raise ImportError(
                "boto3 is required. Install with: pip install boto3"
            )

    async def disconnect(self) -> None:
        """Close Glue client."""
        self._client = None
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Glue doesn't support data queries.

        Returns schema information based on intent.

        Args:
            query: IntentQuery describing what metadata to retrieve.

        Returns:
            QueryResult with schema metadata.
        """
        if not self._connected:
            await self.connect()

        intent_lower = query.intent.lower()

        if "database" in intent_lower or "catalog" in intent_lower:
            # List databases
            databases = await self.list_databases()
            rows = [{"database_name": db} for db in databases]
            return QueryResult(
                rows=rows,
                columns=["database_name"],
                row_count=len(rows),
                metadata={"backend": self.backend_name, "operation": "list_databases"},
            )

        elif "table" in intent_lower:
            # List tables in database
            database = query.entity or self._settings.database
            tables = await self.list_tables(database=database)
            rows = [{"table_name": tbl} for tbl in tables]
            return QueryResult(
                rows=rows,
                columns=["table_name"],
                row_count=len(rows),
                metadata={
                    "backend": self.backend_name,
                    "database": database,
                    "operation": "list_tables",
                },
            )

        elif "column" in intent_lower or "schema" in intent_lower:
            # Get table schema
            database = query.filters.get("database", self._settings.database)
            table = query.entity
            if not table:
                raise ValueError("Table name required for schema lookup")

            schema = await self.get_schema_metadata(database=database, table=table)
            columns = schema.get("tables", {}).get(table, [])
            return QueryResult(
                rows=columns,
                columns=["column_name", "data_type", "is_pii", "pii_sensitivity"],
                row_count=len(columns),
                metadata={
                    "backend": self.backend_name,
                    "database": database,
                    "table": table,
                    "operation": "get_schema",
                },
            )

        else:
            raise ValueError(
                f"Glue connector requires intent to specify 'database', 'table', or 'column'. "
                f"Got: {query.intent}"
            )

    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """Get schema metadata from Glue Data Catalog."""
        if not self._connected:
            await self.connect()

        db = database or self._settings.database

        if table:
            # Get specific table
            response = self._client.get_table(DatabaseName=db, Name=table)
            tbl = response["Table"]

            columns = []
            all_cols = tbl["StorageDescriptor"]["Columns"]

            # Include partition keys if present
            if "PartitionKeys" in tbl:
                all_cols = all_cols + tbl["PartitionKeys"]

            for col in all_cols:
                classification = self._classifier.classify_column(
                    col["Name"], self.backend_name
                )
                columns.append({
                    "column_name": col["Name"],
                    "data_type": col["Type"],
                    "comment": col.get("Comment", ""),
                    "is_pii": classification.is_pii,
                    "pii_sensitivity": classification.sensitivity.value,
                    "pii_category": classification.pii_category,
                })

            return {
                "database": db,
                "tables": {table: columns},
                "table_info": {
                    "location": tbl["StorageDescriptor"].get("Location", ""),
                    "input_format": tbl["StorageDescriptor"].get("InputFormat", ""),
                    "output_format": tbl["StorageDescriptor"].get("OutputFormat", ""),
                    "serde": tbl["StorageDescriptor"]
                    .get("SerdeInfo", {})
                    .get("SerializationLibrary", ""),
                },
            }
        else:
            # Get all tables in database
            paginator = self._client.get_paginator("get_tables")
            tables: dict[str, list[dict[str, Any]]] = {}

            for page in paginator.paginate(DatabaseName=db):
                for tbl in page["TableList"]:
                    columns = []
                    all_cols = tbl["StorageDescriptor"]["Columns"]

                    if "PartitionKeys" in tbl:
                        all_cols = all_cols + tbl["PartitionKeys"]

                    for col in all_cols:
                        classification = self._classifier.classify_column(
                            col["Name"], self.backend_name
                        )
                        columns.append({
                            "column_name": col["Name"],
                            "data_type": col["Type"],
                            "is_pii": classification.is_pii,
                            "pii_sensitivity": classification.sensitivity.value,
                        })
                    tables[tbl["Name"]] = columns

            return {
                "database": db,
                "tables": tables,
            }

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List tables in Glue database."""
        if not self._connected:
            await self.connect()

        db = database or self._settings.database
        paginator = self._client.get_paginator("get_tables")

        tables = []
        for page in paginator.paginate(DatabaseName=db):
            for tbl in page["TableList"]:
                tables.append(tbl["Name"])

        return tables

    async def list_databases(self) -> list[str]:
        """List all Glue databases."""
        if not self._connected:
            await self.connect()

        paginator = self._client.get_paginator("get_databases")

        databases = []
        for page in paginator.paginate():
            for db in page["DatabaseList"]:
                databases.append(db["Name"])

        return databases

    async def get_table_partitions(
        self,
        database: str,
        table: str,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Get partition information for a table.

        Args:
            database: Glue database name.
            table: Table name.
            max_results: Maximum partitions to return.

        Returns:
            List of partition information dictionaries.
        """
        if not self._connected:
            await self.connect()

        response = self._client.get_partitions(
            DatabaseName=database,
            TableName=table,
            MaxResults=max_results,
        )

        partitions = []
        for part in response.get("Partitions", []):
            partitions.append({
                "values": part["Values"],
                "location": part["StorageDescriptor"].get("Location", ""),
                "creation_time": (
                    part["CreationTime"].isoformat()
                    if "CreationTime" in part
                    else None
                ),
            })

        return partitions

    async def search_tables(
        self,
        search_text: str,
        database: str | None = None,
    ) -> list[dict[str, str]]:
        """
        Search for tables by name pattern.

        Args:
            search_text: Text to search for in table names.
            database: Optional database to limit search.

        Returns:
            List of matching table info.
        """
        if not self._connected:
            await self.connect()

        filters = []
        if database:
            filters.append({
                "Key": "DatabaseName",
                "Value": database,
                "Comparator": "EQUALS",
            })

        response = self._client.search_tables(
            SearchText=search_text,
            Filters=filters if filters else None,
            MaxResults=100,
        )

        return [
            {
                "database": tbl["DatabaseName"],
                "table": tbl["Name"],
                "description": tbl.get("Description", ""),
            }
            for tbl in response.get("TableList", [])
        ]
