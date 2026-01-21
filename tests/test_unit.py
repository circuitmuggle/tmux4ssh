"""Unit tests for TmuxSSHClient (mocked, no network required)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tmux_ssh.client import (
    EXIT_BLOCKED,
    EXIT_ERROR,
    Config,
    TmuxSSHClient,
)

pytestmark = pytest.mark.unit


class TestConfig:
    """Tests for Config dataclass."""

    def test_config_defaults(self) -> None:
        """Test that Config has sensible defaults."""
        config = Config(hostname="host", username="user")

        assert config.hostname == "host"
        assert config.username == "user"
        assert config.app_name == "TmuxSSHManager"
        assert config.expiry_days == 30
        assert config.default_session == "remote_task"
        assert "___CMD_START_MARKER___" in config.start_marker
        assert "___CMD_COMPLETE_MARKER___" in config.end_marker

    def test_config_custom_values(self) -> None:
        """Test Config with custom values."""
        config = Config(
            hostname="custom-host",
            username="custom-user",
            app_name="CustomApp",
            expiry_days=7,
            default_session="custom_session",
        )

        assert config.hostname == "custom-host"
        assert config.app_name == "CustomApp"
        assert config.expiry_days == 7
        assert config.default_session == "custom_session"


class TestTmuxSSHClient:
    """Tests for TmuxSSHClient class."""

    def test_get_log_file(self) -> None:
        """Test log file path generation."""
        assert (
            TmuxSSHClient.get_log_file("my_session") == "/tmp/cmd_output_my_session.log"
        )
        assert (
            TmuxSSHClient.get_log_file("session/with/slash")
            == "/tmp/cmd_output_session_with_slash.log"
        )
        assert (
            TmuxSSHClient.get_log_file("session with space")
            == "/tmp/cmd_output_session_with_space.log"
        )

    def test_get_lock_file(self) -> None:
        """Test lock file path generation."""
        assert (
            TmuxSSHClient.get_lock_file("my_session")
            == "/tmp/cmd_running_my_session.lock"
        )
        assert (
            TmuxSSHClient.get_lock_file("session/test")
            == "/tmp/cmd_running_session_test.lock"
        )

    def test_client_initialization(self, mock_config: Config) -> None:
        """Test client initialization."""
        client = TmuxSSHClient(mock_config)

        assert client.config == mock_config
        assert client._password_provider is None

    def test_client_with_password_provider(self, mock_config: Config) -> None:
        """Test client with custom password provider."""
        provider = lambda h, u: "custom_password"
        client = TmuxSSHClient(mock_config, password_provider=provider)

        assert client._password_provider is provider


class TestCredentials:
    """Tests for credential management."""

    def test_get_credentials_with_valid_timestamp(
        self,
        mock_config: Config,
        tmp_path: pytest.TempPathFactory,
    ) -> None:
        """Test that valid timestamp prevents password prompt."""
        from datetime import datetime

        # Create a valid timestamp file
        timestamp_file = tmp_path / "timestamp"  # type: ignore[operator]
        timestamp_file.write_text(datetime.now().isoformat())

        config = Config(
            hostname="host",
            username="user",
            timestamp_file=str(timestamp_file),
        )

        with patch("tmux_ssh.client.keyring") as mock_keyring:
            mock_keyring.get_password.return_value = "stored_password"
            client = TmuxSSHClient(config)
            password = client.get_credentials()

        assert password == "stored_password"

    def test_clear_credentials(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test clearing credentials."""
        with patch("os.path.exists", return_value=False):
            with patch("tmux_ssh.client.keyring") as mock_keyring:
                client = TmuxSSHClient(mock_config)
                client.clear_credentials()

                mock_keyring.delete_password.assert_called_once()

        captured = capsys.readouterr()
        assert "Clearing stored credentials" in captured.out


class TestCommandExecution:
    """Tests for command execution logic."""

    def test_execute_connection_error(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test handling of connection errors."""
        with patch("os.path.exists", return_value=False):
            with patch("tmux_ssh.client.keyring") as mock_keyring:
                mock_keyring.get_password.return_value = None
                with patch(
                    "paramiko.Transport",
                    side_effect=Exception("Connection refused"),
                ):
                    client = TmuxSSHClient(
                        mock_config,
                        password_provider=lambda h, u: "password",
                    )
                    result = client.execute("hostname")

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "Connection error" in captured.out

    def test_execute_blocked_by_running_command(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test that execution is blocked when command is already running."""
        with patch("os.path.exists", return_value=False):
            with patch("tmux_ssh.client.keyring") as mock_keyring:
                mock_keyring.get_password.return_value = None

                # Mock SSH client
                mock_transport = MagicMock()
                mock_ssh_client = MagicMock()

                def exec_command_side_effect(
                    cmd: str,
                ) -> tuple[MagicMock, MagicMock, MagicMock]:
                    stdin = MagicMock()
                    stdout = MagicMock()
                    stderr = MagicMock()

                    if "tmux has-session" in cmd and "echo" in cmd:
                        stdout.read.return_value = b"existing_session"
                    elif "[ -f" in cmd and "lock" in cmd:
                        stdout.read.return_value = b"running"
                    else:
                        stdout.read.return_value = b""

                    return stdin, stdout, stderr

                mock_ssh_client.exec_command.side_effect = exec_command_side_effect

                with patch("paramiko.Transport", return_value=mock_transport):
                    with patch("paramiko.SSHClient", return_value=mock_ssh_client):
                        client = TmuxSSHClient(
                            mock_config,
                            password_provider=lambda h, u: "password",
                        )
                        result = client.execute("hostname", force=False)

        assert result == EXIT_BLOCKED
        captured = capsys.readouterr()
        assert "Command already running" in captured.out
        assert "--new" in captured.out
        assert "--force" in captured.out


class TestCLI:
    """Tests for command-line interface."""

    def test_cli_parse_args(self) -> None:
        """Test CLI argument parsing."""
        from tmux_ssh.cli import main

        assert callable(main)

    def test_cli_help(self) -> None:
        """Test CLI help output."""
        from tmux_ssh.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0
