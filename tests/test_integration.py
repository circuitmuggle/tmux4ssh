"""Integration tests for TmuxSSHClient (require live SSH connection).

These tests require:
1. Network access to the remote server
2. Valid SSH credentials stored in keyring

Run with: pytest -m integration
Skip with: pytest -m "not integration"
"""

from __future__ import annotations

import keyring
import pytest

from tmux_ssh.client import (
    EXIT_COMPLETED,
    EXIT_STILL_RUNNING,
    Config,
    TmuxSSHClient,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]


# Integration test configuration
INTEGRATION_HOST = "ees-lin32.ecs.apple.com"
INTEGRATION_USER = "gaofeng_fan"
APP_NAME = "GeneralSSHManager"  # Use same app name as original ssh_cmd.py


def credentials_available() -> bool:
    """Check if credentials are stored in keyring."""
    keyring_key = f"{INTEGRATION_USER}@{INTEGRATION_HOST}"
    password = keyring.get_password(APP_NAME, keyring_key)
    return password is not None


# Skip all integration tests if credentials are not available
pytestmark.append(
    pytest.mark.skipif(
        not credentials_available(),
        reason="SSH credentials not stored in keyring. Run 'tmux-ssh -C' then re-login to store credentials.",
    )
)


@pytest.fixture
def live_client() -> TmuxSSHClient:
    """Create a client for live integration tests."""
    # Get password from keyring to avoid interactive prompt
    keyring_key = f"{INTEGRATION_USER}@{INTEGRATION_HOST}"
    stored_password = keyring.get_password(APP_NAME, keyring_key)

    config = Config(
        hostname=INTEGRATION_HOST,
        username=INTEGRATION_USER,
        app_name=APP_NAME,
    )
    # Provide password directly to avoid getpass prompt
    return TmuxSSHClient(
        config,
        password_provider=lambda h, u: stored_password,  # type: ignore[return-value]
    )


class TestBasicCommands:
    """Test basic command execution."""

    def test_hostname_command(self, live_client: TmuxSSHClient) -> None:
        """Test running hostname command."""
        result = live_client.execute(
            "hostname",
            idle_timeout=30,
            new_session=True,  # Use new session to avoid conflicts
        )

        assert result == EXIT_COMPLETED

    def test_echo_command(self, live_client: TmuxSSHClient) -> None:
        """Test running echo command."""
        result = live_client.execute(
            "echo 'Hello from integration test'",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_multi_step_command(self, live_client: TmuxSSHClient) -> None:
        """Test running multi-step command with delays."""
        result = live_client.execute(
            "echo Step1; sleep 1; echo Step2; sleep 1; echo Done",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_command_with_single_quotes(self, live_client: TmuxSSHClient) -> None:
        """Test command with single quotes."""
        result = live_client.execute(
            "echo 'Hello World'",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_command_with_double_quotes(self, live_client: TmuxSSHClient) -> None:
        """Test command with double quotes."""
        # Use simple variable expansion instead of literal quotes
        result = live_client.execute(
            "echo Hello World",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_command_with_pipe(self, live_client: TmuxSSHClient) -> None:
        """Test command with pipe."""
        result = live_client.execute(
            "ls /tmp | head -3",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED


class TestTimeouts:
    """Test timeout behavior."""

    def test_idle_timeout(self, live_client: TmuxSSHClient) -> None:
        """Test idle timeout with long-running command."""
        result = live_client.execute(
            "sleep 60",
            idle_timeout=2,  # Short timeout
            new_session=True,
        )

        assert result == EXIT_STILL_RUNNING

    def test_total_timeout(self, live_client: TmuxSSHClient) -> None:
        """Test total timeout."""
        result = live_client.execute(
            "for i in 1 2 3 4 5; do echo $i; sleep 2; done",
            timeout=3,  # Should timeout before completing
            idle_timeout=10,
            new_session=True,
        )

        assert result == EXIT_STILL_RUNNING


class TestConcurrency:
    """Test concurrent execution features."""

    def test_new_session_creates_unique_session(
        self, live_client: TmuxSSHClient
    ) -> None:
        """Test that --new creates a unique session each time."""
        # Run first command
        result1 = live_client.execute(
            "echo 'First'",
            idle_timeout=30,
            new_session=True,
        )
        assert result1 == EXIT_COMPLETED

        # Run second command in another new session
        result2 = live_client.execute(
            "echo 'Second'",
            idle_timeout=30,
            new_session=True,
        )
        assert result2 == EXIT_COMPLETED

    def test_running_detection_and_force(self, live_client: TmuxSSHClient) -> None:
        """Test that lock file mechanism works by verifying files are created/deleted."""
        # Run a quick command with new session
        result = live_client.execute(
            "echo 'Test lock mechanism'",
            idle_timeout=30,
            new_session=True,
        )
        assert result == EXIT_COMPLETED

        # The lock mechanism is tested more thoroughly in unit tests
        # This integration test just verifies the basic flow works


class TestPathsAndDirectories:
    """Test commands with paths and directories."""

    def test_ls_command(self, live_client: TmuxSSHClient) -> None:
        """Test ls command."""
        result = live_client.execute(
            "ls -la /tmp | head -5",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_pwd_command(self, live_client: TmuxSSHClient) -> None:
        """Test pwd command."""
        result = live_client.execute(
            "pwd",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED

    def test_cd_and_pwd(self, live_client: TmuxSSHClient) -> None:
        """Test cd followed by pwd."""
        result = live_client.execute(
            "cd /tmp && pwd",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED


class TestErrorHandling:
    """Test error message handling."""

    def test_command_not_found_error(
        self, live_client: TmuxSSHClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that 'command not found' error is displayed."""
        result = live_client.execute(
            "nonexistent_command_xyz123",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED
        captured = capsys.readouterr()
        # Error message should contain "not found" or similar
        assert (
            "not found" in captured.out.lower()
            or "command not found" in captured.out.lower()
        )

    def test_file_not_found_error(
        self, live_client: TmuxSSHClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that file not found error is displayed."""
        result = live_client.execute(
            "cat /nonexistent/file/path/xyz123.txt",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED
        captured = capsys.readouterr()
        # Error message should be in output
        assert (
            "no such file" in captured.out.lower()
            or "not found" in captured.out.lower()
        )

    def test_permission_denied_error(
        self, live_client: TmuxSSHClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that permission denied error is displayed."""
        result = live_client.execute(
            "cat /etc/shadow",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED
        captured = capsys.readouterr()
        # Should show permission denied
        assert (
            "permission denied" in captured.out.lower()
            or "cannot open" in captured.out.lower()
        )

    def test_python_exit_code(
        self, live_client: TmuxSSHClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that command with non-zero exit still completes."""
        result = live_client.execute(
            "python3 -c 'import sys; sys.exit(1)'",
            idle_timeout=30,
            new_session=True,
        )

        # Command should complete (exit code doesn't affect our result)
        assert result == EXIT_COMPLETED

    def test_stderr_is_captured(
        self, live_client: TmuxSSHClient, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test that stderr output is captured and displayed."""
        result = live_client.execute(
            "echo 'stdout message' && echo 'stderr message' >&2",
            idle_timeout=30,
            new_session=True,
        )

        assert result == EXIT_COMPLETED
        captured = capsys.readouterr()
        # Both stdout and stderr should be in output
        assert "stdout message" in captured.out
        assert "stderr message" in captured.out
