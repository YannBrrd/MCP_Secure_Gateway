"""Trino/Starburst connector for the MCP Secure Gateway."""

from __future__ import annotations

import re
from typing import Any

from mcp_gateway.config import get_settings
from mcp_gateway.connectors.base import BaseConnector, IntentQuery, QueryResult

# Strict pattern for identifiers (table names, column names)
IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Whitelist of allowed SQL aggregation functions
ALLOWED_AGGREGATIONS = frozenset(
    {
        "COUNT",
        "SUM",
        "AVG",
        "MIN",
        "MAX",
        "STDDEV",
        "VARIANCE",
        "ARRAY_AGG",
        "BOOL_AND",
        "BOOL_OR",
        "EVERY",
        "APPROX_DISTINCT",
    }
)

# Whitelist of allowed tables (should be configured per deployment)
ALLOWED_TABLES = frozenset(
    {
        "customers",
        "users",
        "orders",
        "products",
        "transactions",
        "sales",
        "metrics",
        "events",
        "inventory",
        "logs",
    }
)


class TrinoConnector(BaseConnector):
    """
    Connector for Trino and Starburst.

    Uses trino-python-client for database operations.
    Supports federated queries across multiple data sources.
    """

    def __init__(self) -> None:
        """Initialize Trino connector with settings."""
        super().__init__()
        self._settings = get_settings().trino
        self._connection: Any = None
        self._cursor: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "trino"

    async def connect(self) -> None:
        """Establish connection to Trino/Starburst."""
        try:
            import trino

            auth = None
            if self._settings.password.get_secret_value():
                auth = trino.auth.BasicAuthentication(
                    self._settings.user,
                    self._settings.password.get_secret_value(),
                )

            self._connection = trino.dbapi.connect(
                host=self._settings.host,
                port=self._settings.port,
                user=self._settings.user,
                catalog=self._settings.catalog or None,
                schema=self._settings.schema_name or None,
                http_scheme=self._settings.http_scheme,
                auth=auth,
            )
            self._cursor = self._connection.cursor()
            self._connected = True
        except ImportError:
            raise ImportError("trino is required. Install with: pip install trino")

    async def disconnect(self) -> None:
        """Close Trino connection."""
        if self._cursor:
            self._cursor.close()
        if self._connection:
            self._connection.close()
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query against Trino.

        Args:
            query: IntentQuery with business intent and filters.

        Returns:
            QueryResult with PII-processed data.
        """
        if not self._connected:
            await self.connect()

        # Build safe SQL from intent with parameters
        sql, params = self._build_safe_query(query)

        # Execute query with parameters
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

    def _validate_identifier(self, name: str, context: str = "identifier") -> str:
        """
        Validate that a string is a safe SQL identifier.

        Args:
            name: The identifier to validate.
            context: Description for error messages.

        Returns:
            The validated identifier.

        Raises:
            ValueError: If the identifier is invalid.
        """
        if not IDENTIFIER_PATTERN.match(name):
            raise ValueError(
                f"Invalid {context}: '{name}'. "
                "Must contain only alphanumeric characters and underscores, "
                "starting with a letter or underscore."
            )
        return name

    def _validate_table_name(self, table: str) -> str:
        """
        Validate table name against whitelist.

        Args:
            table: Table name to validate.

        Returns:
            The validated table name.

        Raises:
            ValueError: If table is not in whitelist.
        """
        self._validate_identifier(table, "table name")
        if table.lower() not in ALLOWED_TABLES:
            raise ValueError(
                f"Table '{table}' is not in the allowed tables list. "
                f"Allowed tables: {sorted(ALLOWED_TABLES)}"
            )
        return table

    def _validate_aggregation(self, expr: str) -> str:
        """
        Validate an aggregation expression.

        Only allows safe patterns like: COUNT(*), SUM(column_name), AVG(column)

        Args:
            expr: Aggregation expression to validate.

        Returns:
            The validated expression.

        Raises:
            ValueError: If the expression is not safe.
        """
        # Pattern: FUNCTION(column) or FUNCTION(*) with optional AS alias
        agg_pattern = re.compile(
            r"^([A-Z_]+)\s*\(\s*(\*|[a-zA-Z_][a-zA-Z0-9_]*)\s*\)"
            r"(\s+AS\s+[a-zA-Z_][a-zA-Z0-9_]*)?$",
            re.IGNORECASE,
        )
        match = agg_pattern.match(expr.strip())
        if not match:
            raise ValueError(
                f"Invalid aggregation expression: '{expr}'. "
                "Must be in format: FUNCTION(column) or FUNCTION(*)"
            )

        func_name = match.group(1).upper()
        if func_name not in ALLOWED_AGGREGATIONS:
            raise ValueError(
                f"Aggregation function '{func_name}' is not allowed. "
                f"Allowed functions: {sorted(ALLOWED_AGGREGATIONS)}"
            )

        return expr

    def _validate_order_by(self, expr: str) -> str:
        """
        Validate an ORDER BY expression.

        Args:
            expr: ORDER BY expression (column with optional ASC/DESC).

        Returns:
            The validated expression.

        Raises:
            ValueError: If the expression is not safe.
        """
        # Pattern: column_name [ASC|DESC] [NULLS FIRST|LAST]
        order_pattern = re.compile(
            r"^([a-zA-Z_][a-zA-Z0-9_]*)(\s+(ASC|DESC))?(\s+NULLS\s+(FIRST|LAST))?$",
            re.IGNORECASE,
        )
        if not order_pattern.match(expr.strip()):
            raise ValueError(
                f"Invalid ORDER BY expression: '{expr}'. "
                "Must be: column_name [ASC|DESC] [NULLS FIRST|LAST]"
            )
        return expr

    def _build_safe_query(self, query: IntentQuery) -> tuple[str, list[Any]]:
        """
        Build a safe parameterized SQL query from intent.

        Args:
            query: The IntentQuery to translate.

        Returns:
            Tuple of (SQL string with ? placeholders, parameter values).
        """
        intent_lower = query.intent.lower()
        table = query.entity or self._infer_table_from_intent(intent_lower)

        # Validate table name against whitelist
        table = self._validate_table_name(table)

        # Build SELECT clause with validated aggregations
        select_cols = "*"
        if query.aggregations:
            validated_aggs = [self._validate_aggregation(agg) for agg in query.aggregations]
            select_cols = ", ".join(validated_aggs)
            if query.group_by:
                validated_groups = [
                    self._validate_identifier(col, "GROUP BY column") for col in query.group_by
                ]
                select_cols += ", " + ", ".join(validated_groups)

        sql_parts = [f"SELECT {select_cols}", f"FROM {table}"]
        params: list[Any] = []

        # Build WHERE clause with parameterized values
        if query.filters:
            conditions = []
            for key, value in query.filters.items():
                # Validate column name
                self._validate_identifier(key, "filter column")

                # Use parameterized queries for values
                if value is None:
                    conditions.append(f"{key} IS NULL")
                else:
                    conditions.append(f"{key} = ?")
                    params.append(value)

            sql_parts.append("WHERE " + " AND ".join(conditions))

        # GROUP BY with validated identifiers
        if query.group_by:
            validated_groups = [
                self._validate_identifier(col, "GROUP BY column") for col in query.group_by
            ]
            sql_parts.append("GROUP BY " + ", ".join(validated_groups))

        # ORDER BY with validated expressions
        if query.order_by:
            validated_orders = [self._validate_order_by(expr) for expr in query.order_by]
            sql_parts.append("ORDER BY " + ", ".join(validated_orders))

        # LIMIT (always an integer, safe)
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
            "metric": "metrics",
            "event": "events",
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
        """Get schema metadata from Trino."""
        if not self._connected:
            await self.connect()

        catalog = database or self._settings.catalog
        sch = schema or self._settings.schema_name

        # Query information schema
        sql = f"""
        SELECT table_name, column_name, data_type, is_nullable
        FROM {catalog}.information_schema.columns
        WHERE table_catalog = '{catalog}' AND table_schema = '{sch}'
        """

        if table:
            sql += f" AND table_name = '{table}'"

        self._cursor.execute(sql)
        rows = self._cursor.fetchall()

        tables: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            table_name, col_name, data_type, nullable = row
            if table_name not in tables:
                tables[table_name] = []

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
            "catalog": catalog,
            "schema": sch,
            "tables": tables,
        }

    async def list_tables(
        self,
        database: str | None = None,
        schema: str | None = None,
    ) -> list[str]:
        """List tables in Trino."""
        if not self._connected:
            await self.connect()

        catalog = database or self._settings.catalog
        sch = schema or self._settings.schema_name

        sql = f"""
        SELECT table_name
        FROM {catalog}.information_schema.tables
        WHERE table_catalog = '{catalog}' AND table_schema = '{sch}'
        ORDER BY table_name
        """

        self._cursor.execute(sql)
        return [row[0] for row in self._cursor.fetchall()]
