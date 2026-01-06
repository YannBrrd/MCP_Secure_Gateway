"""Pytest configuration and fixtures for MCP Secure Gateway tests."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def set_test_environment() -> None:
    """Set environment variables for testing."""
    # Use test salt for consistent hashing in tests
    os.environ.setdefault("PII_HASH_SALT", "test-salt-for-testing")
    # Disable actual backend connections
    os.environ.setdefault("GATEWAY_TEST_MODE", "true")


@pytest.fixture
def sample_rows_with_pii() -> list[dict]:
    """Sample data rows containing PII for testing."""
    return [
        {
            "id": 1,
            "email": "john.doe@example.com",
            "phone": "555-123-4567",
            "first_name": "John",
            "last_name": "Doe",
            "status": "active",
        },
        {
            "id": 2,
            "email": "jane.smith@example.com",
            "phone": "555-987-6543",
            "first_name": "Jane",
            "last_name": "Smith",
            "status": "inactive",
        },
    ]


@pytest.fixture
def sample_rows_without_pii() -> list[dict]:
    """Sample data rows without PII for testing."""
    return [
        {"id": 1, "product_name": "Widget A", "quantity": 100, "price": 9.99},
        {"id": 2, "product_name": "Widget B", "quantity": 50, "price": 19.99},
    ]


@pytest.fixture
def sample_schema_with_pii() -> list[str]:
    """Sample column list containing PII columns."""
    return [
        "id",
        "email",
        "first_name",
        "last_name",
        "phone",
        "address",
        "created_at",
        "status",
    ]


@pytest.fixture
def sample_schema_without_pii() -> list[str]:
    """Sample column list without PII columns."""
    return ["id", "product_name", "sku", "quantity", "price", "created_at"]
