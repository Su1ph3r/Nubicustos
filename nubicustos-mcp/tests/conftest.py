"""Shared fixtures for Nubicustos MCP tests."""

import pytest
import respx

from nubicustos_mcp.client import NubicustosClient

TEST_BASE_URL = "http://test-api:8000"


@pytest.fixture
def client():
    """Create a NubicustosClient pointed at the test base URL."""
    return NubicustosClient(base_url=TEST_BASE_URL, api_key="test-key")


@pytest.fixture
def mock_api():
    """Provide a respx mock router scoped to the test base URL."""
    with respx.mock(base_url=TEST_BASE_URL, assert_all_called=False) as router:
        yield router
