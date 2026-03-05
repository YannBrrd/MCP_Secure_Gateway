"""
Tool to preview PII policy effects on sample data.

This tool lets agents understand what a PII policy will do to their data
before actually running a query. It demonstrates masking, hashing,
or deny behavior on provided sample values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from mcp_gateway.audit import get_audit_logger
from mcp_gateway.pii import PIIDetector
from mcp_gateway.security import PIIHasher, PIIRedactor, create_safe_error_message


class CheckPIIPolicyInput(BaseModel):
    """Input for the check_pii_policy tool."""

    sample_columns: list[str] = Field(
        ...,
        min_length=1,
        description="Column names to check (e.g., ['email', 'phone', 'status'])",
    )

    policy: str = Field(
        default="mask",
        description="PII policy to preview: 'mask', 'hash', or 'deny'",
    )


@dataclass
class CheckPIIPolicyOutput:
    """Output for the check_pii_policy tool."""

    success: bool
    policy: str = ""
    column_analysis: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "policy": self.policy,
            "column_analysis": self.column_analysis,
            "recommendation": self.recommendation,
            "error": self.error,
        }


class CheckPIIPolicyTool:
    """
    Preview PII policy effects on columns.

    Analyzes column names to predict which will be classified as PII
    and shows what the specified policy would do (mask, hash, or deny).
    No actual data is accessed.
    """

    def __init__(self) -> None:
        self._audit = get_audit_logger()
        self._detector = PIIDetector()
        self._hasher = PIIHasher()
        self._redactor = PIIRedactor(self._detector)

    @property
    def name(self) -> str:
        return "check_pii_policy"

    @property
    def description(self) -> str:
        return (
            "Preview what a PII policy (mask, hash, deny) would do to specific columns. "
            "Analyzes column names for PII classification and shows the expected behavior. "
            "Use this to understand PII protections before running query_data."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "sample_columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Column names to analyze for PII",
                },
                "policy": {
                    "type": "string",
                    "enum": ["mask", "hash", "deny"],
                    "default": "mask",
                    "description": "PII policy to preview",
                },
            },
            "required": ["sample_columns"],
        }

    @property
    def input_examples(self) -> list[dict[str, Any]]:
        """Example invocations for this tool."""
        return [
            {
                "description": "Check which columns would be affected by mask policy",
                "input": {
                    "sample_columns": ["id", "email", "first_name", "status", "phone"],
                    "policy": "mask",
                },
                "output_summary": (
                    "email, first_name, phone classified as PII and would be masked; "
                    "id and status pass through unchanged"
                ),
            },
            {
                "description": "Check if deny policy would block a query",
                "input": {
                    "sample_columns": ["order_id", "amount", "currency"],
                    "policy": "deny",
                },
                "output_summary": "No PII columns detected, deny policy would not block this query",
            },
        ]

    async def execute(self, arguments: dict[str, Any]) -> CheckPIIPolicyOutput:
        """Execute the check_pii_policy tool."""
        try:
            input_data = CheckPIIPolicyInput(**arguments)

            from mcp_gateway.pii import PIIClassifier

            classifier = PIIClassifier()

            column_analysis = []
            pii_columns = []

            for col in input_data.sample_columns:
                classification = classifier.classify_column(col)
                analysis = {
                    "column": col,
                    "is_pii": classification.is_pii,
                    "sensitivity": classification.sensitivity.value,
                    "category": classification.pii_category,
                }

                if classification.is_pii:
                    pii_columns.append(col)
                    if input_data.policy == "mask":
                        analysis["policy_effect"] = "Value will be masked (e.g., jo***@***.***)"
                    elif input_data.policy == "hash":
                        analysis["policy_effect"] = "Value will be hashed (e.g., HASH_abc123...)"
                    elif input_data.policy == "deny":
                        analysis["policy_effect"] = "Query will be REJECTED if PII values detected"
                else:
                    analysis["policy_effect"] = "No PII processing - value passes through unchanged"

                column_analysis.append(analysis)

            if not pii_columns:
                recommendation = (
                    "No PII columns detected. Any policy (mask, hash, deny) will "
                    "allow this query to proceed with all data intact."
                )
            elif input_data.policy == "deny":
                recommendation = (
                    f"PII detected in {len(pii_columns)} column(s): {pii_columns}. "
                    "With 'deny' policy, the query will be REJECTED. Consider using "
                    "'mask' or 'hash' instead, or exclude PII columns."
                )
            else:
                recommendation = (
                    f"PII detected in {len(pii_columns)} column(s): {pii_columns}. "
                    f"With '{input_data.policy}' policy, these values will be "
                    f"{'masked' if input_data.policy == 'mask' else 'hashed'} in results."
                )

            return CheckPIIPolicyOutput(
                success=True,
                policy=input_data.policy,
                column_analysis=column_analysis,
                recommendation=recommendation,
            )

        except Exception as e:
            error_msg = create_safe_error_message(e)
            return CheckPIIPolicyOutput(
                success=False,
                error=error_msg,
            )
