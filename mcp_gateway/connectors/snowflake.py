"""Snowflake connector for the MCP Secure Gateway."""

from __future__ import annotations

from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult


class SnowflakeConnector(BaseConnector):
    """
    Connector for Snowflake data warehouse.

    Uses snowflake-connector-python for database operations.
    Only accepts IntentQuery objects, never raw SQL.
    """

    def __init__(self) -> None:
        """Initialize Snowflake connector with settings."""
        super().__init__()
        self._settings = get_settings().snowflake
        self._connection: Any = None
        self._cursor: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "snowflake"

    async def connect(self) -> None:
        """Establish connection to Snowflake."""
        try:
            import snowflake.connector

            self._connection = snowflake.connector.connect(
                account=self._settings.account,
                user=self._settings.user,
                password=self._settings.password.get_secret_value(),
                warehouse=self._settings.warehouse,
                database=self._settings.database,
                schema=self._settings.schema_name,
                role=self._settings.role or None,
            )
            self._cursor = self._connection.cursor()
            self._connected = True
        except ImportError:
            raise ImportError(
                "snowflake-connector-python is required. "
                "Install with: pip install snowflake-connector-python"
            )

    async def disconnect(self) -> None:
        """Close Snowflake connection."""
        if self._cursor:
            self._cursor.close()
        if self._connection:
            self._connection.close()
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query against Snowflake.

        Args:
            query: IntentQuery with business intent and filters.

        Returns:
            QueryResult with PII-processed data.
        """
        if not self._connected:
            await self.connect()

        # Build safe SQL from intent (internal only, never exposed)
        sql, params = self._build_safe_query(query)

        # Execute query
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
                "database": self._settings.database,
                "schema": self._settings.schema_name,
            },
            pii_columns_detected=pii_cols,
            pii_types_detected=pii_types,
        )

    def _build_safe_query(
        self,
        query: IntentQuery,
    ) -> tuple[str, dict[str, Any]]:
        """
        Build a parameterized SQL query from intent.

        This is internal and never exposed to the agent.
        Uses parameterized queries to prevent injection.

        Args:
            query: The IntentQuery to translate.

        Returns:
            Tuple of (sql_string, parameters_dict).
        """
        # Map common intents to safe SQL patterns
        intent_lower = query.intent.lower()

        # Determine table from entity
        table = query.entity or self._infer_table_from_intent(intent_lower)

        # Start building query
        select_cols = "*"  # Will be filtered by PII processing
        if query.aggregations:
            select_cols = ", ".join(query.aggregations)
            if query.group_by:
                select_cols += ", " + ", ".join(query.group_by)

        sql_parts = [f"SELECT {select_cols}", f"FROM {table}"]
        params: dict[str, Any] = {}

        # Add WHERE clause from filters
        if query.filters:
            conditions = []
            for i, (key, value) in enumerate(query.filters.items()):
                param_name = f"p{i}"
                conditions.append(f"{key} = %({param_name})s")
                params[param_name] = value
            sql_parts.append("WHERE " + " AND ".join(conditions))

        # Add GROUP BY
        if query.group_by:
            sql_parts.append("GROUP BY " + ", ".join(query.group_by))

        # Add ORDER BY
        if query.order_by:
            sql_parts.append("ORDER BY " + ", ".join(query.order_by))

        # Add LIMIT
        sql_parts.append(f"LIMIT {min(query.limit, get_settings().max_rows)}")

        return " ".join(sql_parts), params

    def _infer_table_from_intent(self, intent: str) -> str:
        """
        Infer table name from intent string.

        Args:
            intent: Business intent string.

        Returns:
            Inferred table name.

        Raises:
            ValueError: If table cannot be inferred.
        """
        # Simple keyword-to-table mapping
        intent_table_map = {
            "customer": "customers",
            "user": "users",
            "order": "orders",
            "product": "products",
            "transaction": "transactions",
            "sale": "sales",
            "inventory": "inventory",
        }

        for keyword, table in intent_table_map.items():
            if keyword in intent:
                return table

        raise ValueError(
            f"Cannot infer table from intent: {intent}. Please specify entity explicitly."
        )

    async def get_schema_metadata(
        self,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        """Get schema metadata from Snowflake."""
        if not self._connected:
            await self.connect()

        db = database or self._settings.database
        sch = schema or self._settings.schema_name

        # Query information schema
        sql = """
        SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_CATALOG = %(db)s AND TABLE_SCHEMA = %(schema)s
        """
        params = {"db": db, "schema": sch}

        if table:
            sql += " AND TABLE_NAME = %(table)s"
            params["table"] = table

        self._cursor.execute(sql, params)
        rows = self._cursor.fetchall()

        # Organize by table
        tables: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            table_name, col_name, data_type, nullable = row
            if table_name not in tables:
                tables[table_name] = []

            # Add PII classification
            classification = self._classifier.classify_column(col_name, self.backend_name)

            tables[table_name].append(
                {
                    "column_name": col_name,
                    "data_type": data_type,
                    "nullable": nullable == "YES",
                    "is_pii": classification.is_pii,
                    "pii_sensitivity": classification.sensitivity.value,
                }
            )

        return {
            "database": db,
            "schema": sch,
            "tables": tables,
        }

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List tables in Snowflake."""
        if not self._connected:
            await self.connect()

        db = database or self._settings.database
        sch = schema or self._settings.schema_name

        sql = """
        SELECT TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_CATALOG = %(db)s AND TABLE_SCHEMA = %(schema)s
        ORDER BY TABLE_NAME
        """

        self._cursor.execute(sql, {"db": db, "schema": sch})
        return [row[0] for row in self._cursor.fetchall()]
