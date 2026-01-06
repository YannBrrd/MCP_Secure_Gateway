"""AWS Athena connector for the MCP Secure Gateway."""

from __future__ import annotations

import asyncio
import re
import time
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
        "APPROX_DISTINCT",
        "APPROX_PERCENTILE",
        "ARBITRARY",
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
        "logs",
        "events",
        "clickstream",
        "inventory",
    }
)


class AthenaConnector(BaseConnector):
    """
    Connector for AWS Athena.

    Uses boto3 for query execution with polling for results.
    """

    def __init__(self) -> None:
        """Initialize Athena connector with settings."""
        super().__init__()
        self._settings = get_settings().athena
        self._client: Any = None

    @property
    def backend_name(self) -> str:
        """Return backend identifier."""
        return "athena"

    async def connect(self) -> None:
        """Initialize Athena client."""
        try:
            import boto3

            self._client = boto3.client(
                "athena",
                region_name=self._settings.region,
            )
            self._connected = True
        except ImportError:
            raise ImportError("boto3 is required. Install with: pip install boto3")

    async def disconnect(self) -> None:
        """Close Athena client."""
        self._client = None
        self._connected = False

    async def execute_intent(self, query: IntentQuery) -> QueryResult:
        """
        Execute an intent-based query against Athena.

        Uses start_query_execution and polls for completion.

        Args:
            query: IntentQuery with business intent and filters.

        Returns:
            QueryResult with PII-processed data.
        """
        if not self._connected:
            await self.connect()

        # Build safe SQL from intent
        sql = self._build_safe_query(query)

        # Start query execution
        response = self._client.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": self._settings.database},
            ResultConfiguration={"OutputLocation": self._settings.output_location},
            WorkGroup=self._settings.workgroup,
        )

        query_execution_id = response["QueryExecutionId"]

        # Poll for completion
        raw_rows, columns = await self._wait_for_results(query_execution_id)

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
                "query_execution_id": query_execution_id,
            },
            pii_columns_detected=pii_cols,
            pii_types_detected=pii_types,
        )

    async def _wait_for_results(
        self,
        query_execution_id: str,
        max_wait_seconds: int = 300,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Poll for query completion and fetch results.

        Args:
            query_execution_id: The Athena query execution ID.
            max_wait_seconds: Maximum time to wait for completion.

        Returns:
            Tuple of (rows, columns).

        Raises:
            TimeoutError: If query doesn't complete in time.
            RuntimeError: If query fails.
        """
        start_time = time.time()

        while True:
            response = self._client.get_query_execution(QueryExecutionId=query_execution_id)

            state = response["QueryExecution"]["Status"]["State"]

            if state == "SUCCEEDED":
                break
            elif state in ("FAILED", "CANCELLED"):
                reason = response["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown error"
                )
                raise RuntimeError(f"Athena query {state}: {reason}")

            if time.time() - start_time > max_wait_seconds:
                # Cancel the query
                self._client.stop_query_execution(QueryExecutionId=query_execution_id)
                raise TimeoutError(f"Athena query timed out after {max_wait_seconds} seconds")

            # Wait before polling again (non-blocking)
            await asyncio.sleep(1)

        # Fetch results
        results = self._client.get_query_results(QueryExecutionId=query_execution_id)

        # Extract columns
        columns = [
            col["Label"] or col["Name"]
            for col in results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
        ]

        # Extract rows (skip header row)
        rows = []
        result_rows = results["ResultSet"]["Rows"]
        if len(result_rows) > 1:  # First row is headers
            for row in result_rows[1:]:
                row_data = {}
                for i, datum in enumerate(row["Data"]):
                    value = datum.get("VarCharValue")
                    row_data[columns[i]] = value
                rows.append(row_data)

        return rows, columns

    def _validate_identifier(self, name: str, context: str = "identifier") -> str:
        """Validate that a string is a safe SQL identifier."""
        if not IDENTIFIER_PATTERN.match(name):
            raise ValueError(
                f"Invalid {context}: '{name}'. "
                "Must contain only alphanumeric characters and underscores."
            )
        return name

    def _validate_table_name(self, table: str) -> str:
        """Validate table name against whitelist."""
        self._validate_identifier(table, "table name")
        if table.lower() not in ALLOWED_TABLES:
            raise ValueError(
                f"Table '{table}' is not in the allowed tables list. "
                f"Allowed tables: {sorted(ALLOWED_TABLES)}"
            )
        return table

    def _validate_aggregation(self, expr: str) -> str:
        """Validate an aggregation expression against allowed functions."""
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
        """Validate an ORDER BY expression."""
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

    def _escape_string_value(self, value: str) -> str:
        """Safely escape a string value for Athena SQL."""
        dangerous_patterns = [
            r";\s*--",
            r";\s*\w",
            r"\/\*",
            r"\*\/",
            r"xp_",
            r"EXEC\s",
            r"EXECUTE\s",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError("Potentially dangerous pattern detected in value.")
        return value.replace("'", "''")

    def _build_safe_query(self, query: IntentQuery) -> str:
        """Build a safe SQL query from intent with strict validation."""
        intent_lower = query.intent.lower()
        table = query.entity or self._infer_table_from_intent(intent_lower)
        table = self._validate_table_name(table)

        select_cols = "*"
        if query.aggregations:
            validated_aggs = [self._validate_aggregation(a) for a in query.aggregations]
            select_cols = ", ".join(validated_aggs)
            if query.group_by:
                groups = [self._validate_identifier(c, "GROUP BY column") for c in query.group_by]
                select_cols += ", " + ", ".join(groups)

        sql_parts = [f"SELECT {select_cols}", f"FROM {table}"]

        if query.filters:
            conditions = []
            for key, value in query.filters.items():
                self._validate_identifier(key, "filter column")
                if value is None:
                    conditions.append(f"{key} IS NULL")
                elif isinstance(value, bool):
                    conditions.append(f"{key} = {str(value).upper()}")
                elif isinstance(value, int):
                    conditions.append(f"{key} = {value}")
                elif isinstance(value, float):
                    import math

                    if math.isnan(value) or math.isinf(value):
                        raise ValueError("NaN and Inf values not allowed")
                    conditions.append(f"{key} = {value}")
                elif isinstance(value, str):
                    safe_value = self._escape_string_value(value)
                    conditions.append(f"{key} = '{safe_value}'")
                else:
                    raise ValueError(f"Unsupported filter value type: {type(value)}")
            sql_parts.append("WHERE " + " AND ".join(conditions))

        if query.group_by:
            groups = [self._validate_identifier(c, "GROUP BY column") for c in query.group_by]
            sql_parts.append("GROUP BY " + ", ".join(groups))

        if query.order_by:
            orders = [self._validate_order_by(o) for o in query.order_by]
            sql_parts.append("ORDER BY " + ", ".join(orders))

        sql_parts.append(f"LIMIT {min(query.limit, get_settings().max_rows)}")
        return " ".join(sql_parts)

    def _infer_table_from_intent(self, intent: str) -> str:
        """Infer table name from intent string."""
        intent_table_map = {
            "customer": "customers",
            "user": "users",
            "order": "orders",
            "product": "products",
            "transaction": "transactions",
            "log": "logs",
            "event": "events",
            "click": "clickstream",
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
        """Get schema metadata from Athena via Glue catalog."""
        if not self._connected:
            await self.connect()

        import boto3

        glue = boto3.client("glue", region_name=self._settings.region)
        db = database or self._settings.database

        if table:
            # Get specific table
            response = glue.get_table(DatabaseName=db, Name=table)
            columns = []
            for col in response["Table"]["StorageDescriptor"]["Columns"]:
                classification = self._classifier.classify_column(col["Name"], self.backend_name)
                columns.append(
                    {
                        "column_name": col["Name"],
                        "data_type": col["Type"],
                        "is_pii": classification.is_pii,
                        "pii_sensitivity": classification.sensitivity.value,
                    }
                )
            return {
                "database": db,
                "tables": {table: columns},
            }
        else:
            # Get all tables
            response = glue.get_tables(DatabaseName=db)
            tables: dict[str, list[dict[str, Any]]] = {}

            for tbl in response["TableList"]:
                columns = []
                for col in tbl["StorageDescriptor"]["Columns"]:
                    classification = self._classifier.classify_column(
                        col["Name"], self.backend_name
                    )
                    columns.append(
                        {
                            "column_name": col["Name"],
                            "data_type": col["Type"],
                            "is_pii": classification.is_pii,
                            "pii_sensitivity": classification.sensitivity.value,
                        }
                    )
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
        """List tables in Athena database."""
        if not self._connected:
            await self.connect()

        import boto3

        glue = boto3.client("glue", region_name=self._settings.region)
        db = database or self._settings.database

        response = glue.get_tables(DatabaseName=db)
        return [tbl["Name"] for tbl in response["TableList"]]
