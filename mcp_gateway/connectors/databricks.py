"""Databricks connector for the MCP Secure Gateway."""

from __future__ import annotations

from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult


class DatabricksConnector(BaseConnector):
    """
    Connector for Databricks SQL Warehouse.

    Uses databricks-sql-connector for database operations.
    Supports Unity Catalog for fine-grained access control.
    """

    def __init__(self) -> None:
        """Initialize Databricks connector with settings."""
        super().__init__()
        self._settings = get_settings().databricks
        self._connection: Any = None
        self._cursor: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "databricks"

    async def connect(self) -> None:
        """Establish connection to Databricks SQL Warehouse."""
        try:
            from databricks import sql

            self._connection = sql.connect(
                server_hostname=self._settings.host,
                http_path=self._settings.http_path,
                access_token=self._settings.access_token.get_secret_value(),
                catalog=self._settings.catalog or None,
                schema=self._settings.schema_name or None,
            )
            self._cursor = self._connection.cursor()
            self._connected = True
        except ImportError:
            raise ImportError(
                "databricks-sql-connector is required. "
                "Install with: pip install databricks-sql-connector"
            )

    async def disconnect(self) -> None:
        """Close Databricks connection."""
        if self._cursor:
            self._cursor.close()
        if self._connection:
            self._connection.close()
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query against Databricks.

        Args:
            query: IntentQuery with business intent and filters.

        Returns:
            QueryResult with PII-processed data.
        """
        if not self._connected:
            await self.connect()

        # Build safe SQL from intent
        sql, params = self._build_safe_query(query)

        # Execute with parameters
        self._cursor.execute(sql, params)
        columns = [desc[0] for desc in self._cursor.description]
        raw_rows = [dict(zip(columns, row)) for row in self._cursor.fetchall()]

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
                "catalog": self._settings.catalog,
                "schema": self._settings.schema_name,
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

        Args:
            query: The IntentQuery to translate.

        Returns:
            Tuple of (sql_string, parameters_list).
        """
        intent_lower = query.intent.lower()
        table = query.entity or self._infer_table_from_intent(intent_lower)

        # Build SELECT clause
        select_cols = "*"
        if query.aggregations:
            select_cols = ", ".join(query.aggregations)
            if query.group_by:
                select_cols += ", " + ", ".join(query.group_by)

        sql_parts = [f"SELECT {select_cols}", f"FROM {table}"]
        params: list[Any] = []

        # Build WHERE clause with positional parameters
        if query.filters:
            conditions = []
            for key, value in query.filters.items():
                conditions.append(f"{key} = ?")
                params.append(value)
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
            "sale": "sales",
            "event": "events",
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
        """Get schema metadata from Databricks."""
        if not self._connected:
            await self.connect()

        catalog = database or self._settings.catalog
        sch = schema or self._settings.schema_name

        # Query Unity Catalog information schema
        sql = """
        SELECT table_name, column_name, data_type, is_nullable
        FROM system.information_schema.columns
        WHERE table_catalog = ? AND table_schema = ?
        """
        params = [catalog, sch]

        if table:
            sql += " AND table_name = ?"
            params.append(table)

        self._cursor.execute(sql, params)
        rows = self._cursor.fetchall()

        tables: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            table_name, col_name, data_type, nullable = row
            if table_name not in tables:
                tables[table_name] = []

            classification = self._classifier.classify_column(col_name, self.backend_name)

            tables[table_name].append({
                "column_name": col_name,
                "data_type": data_type,
                "nullable": nullable == "YES",
                "is_pii": classification.is_pii,
                "pii_sensitivity": classification.sensitivity.value,
            })

        return {
            "catalog": catalog,
            "schema": sch,
            "tables": tables,
        }

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List tables in Databricks."""
        if not self._connected:
            await self.connect()

        catalog = database or self._settings.catalog
        sch = schema or self._settings.schema_name

        sql = """
        SELECT table_name
        FROM system.information_schema.tables
        WHERE table_catalog = ? AND table_schema = ?
        ORDER BY table_name
        """

        self._cursor.execute(sql, [catalog, sch])
        return [row[0] for row in self._cursor.fetchall()]
