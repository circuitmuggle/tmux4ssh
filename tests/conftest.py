"""Pytest configuration and fixtures."""

from __future__ import annotations

import pytest

from tmux_ssh.client import Config

# Test configuration for live integration tests
INTEGRATION_HOST = "ees-lin32.ecs.apple.com"
INTEGRATION_USER = "gaofeng_fan"


@pytest.fixture
def mock_config() -> Config:
    """Create a mock configuration for testing."""
    return Config(
        hostname="test-host.example.com",
        username="test_user",
        app_name="TestTmuxSSH",
        timestamp_file="/tmp/test_tmux_ssh_timestamp",
        default_session="test_session",
    )


@pytest.fixture
def integration_config() -> Config:
    """Create configuration for integration tests."""
    return Config(
        hostname=INTEGRATION_HOST,
        username=INTEGRATION_USER,
    )
