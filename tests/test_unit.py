"""Unit tests for TmuxSSHClient (mocked, no network required)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tmux_ssh.client import (
    EXIT_BLOCKED,
    EXIT_COMPLETED,
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
        log_dir = "/tmp/logs"
        timestamp = "20240101_120000"
        assert (
            TmuxSSHClient.get_log_file("my_session", log_dir, timestamp)
            == "/tmp/logs/my_session_20240101_120000.log"
        )
        assert (
            TmuxSSHClient.get_log_file("session/with/slash", log_dir, timestamp)
            == "/tmp/logs/session_with_slash_20240101_120000.log"
        )
        assert (
            TmuxSSHClient.get_log_file("session with space", log_dir, timestamp)
            == "/tmp/logs/session_with_space_20240101_120000.log"
        )

    def test_get_lock_file(self) -> None:
        """Test lock file path generation."""
        log_dir = "/tmp/logs"
        assert (
            TmuxSSHClient.get_lock_file("my_session", log_dir)
            == "/tmp/logs/my_session.lock"
        )
        assert (
            TmuxSSHClient.get_lock_file("session/test", log_dir)
            == "/tmp/logs/session_test.lock"
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
                        result = client.execute("hostname", force=False, auto=False)

        assert result == EXIT_BLOCKED
        captured = capsys.readouterr()
        assert "Command already running" in captured.out
        assert "--new" in captured.out
        assert "--force" in captured.out

    def test_dispatch_cmd_shell_quoting(
        self,
        mock_config: Config,
    ) -> None:
        """Test that dispatch command has correct shell quoting."""
        mock_ssh_client = MagicMock()
        dispatched_cmds: list[str] = []

        def exec_command_side_effect(
            cmd: str,
        ) -> tuple[MagicMock, MagicMock, MagicMock]:
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            dispatched_cmds.append(cmd)

            if "tmux has-session" in cmd and "echo" in cmd:
                # No existing session
                stdout.read.return_value = b""
            elif "[ -f" in cmd and "lock" in cmd:
                # No running command
                stdout.read.return_value = b""
            elif "pwd" in cmd or "tmux display" in cmd:
                # No cwd to inherit
                stdout.read.return_value = b""
            else:
                stdout.read.return_value = b"task_session"

            stdout.channel = MagicMock()
            stdout.channel.recv_ready.return_value = False
            return stdin, stdout, stderr

        mock_ssh_client.exec_command.side_effect = exec_command_side_effect

        client = TmuxSSHClient(mock_config)

        with patch.object(client, "_connect", return_value=mock_ssh_client):
            with patch.object(client, "_check_server_change"):
                with patch.object(client, "_update_timestamp"):
                    # Use timeout=1 so it exits quickly
                    client.execute("ls /some/path", timeout=1, new_session=True)

        # Find the dispatch command (the one with tmux new-session)
        dispatch = [c for c in dispatched_cmds if "tmux new-session" in c]
        assert len(dispatch) == 1, f"Expected 1 dispatch cmd, got {len(dispatch)}"
        cmd = dispatch[0]

        # Validate shell quoting using shlex (POSIX shell parser)
        import shlex

        assert cmd.startswith("sh -c "), "Must start with sh -c"
        tokens = shlex.split(cmd)
        assert tokens[0] == "sh", "First token must be 'sh'"
        assert tokens[1] == "-c", "Second token must be '-c'"
        sh_script = tokens[2]

        # Lock file cleanup must be present
        assert "rm -f" in sh_script, "rm -f must appear in dispatch command"
        assert ".lock" in sh_script, "lock file path must appear in dispatch command"

        # Start and end markers must be present
        assert "___CMD_START_MARKER___" in sh_script
        assert "___CMD_COMPLETE_MARKER___" in sh_script


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


class TestListRunning:
    """Tests for list_running with stale lock detection."""

    def test_list_running_stale_lock_removed(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test that stale lock files are detected and removed."""
        mock_ssh_client = MagicMock()

        # Track rm -f calls
        removed_files: list[str] = []

        def exec_command_side_effect(
            cmd: str,
        ) -> tuple[MagicMock, MagicMock, MagicMock]:
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "hostname" in cmd and "tmux" not in cmd and "find" not in cmd:
                stdout.read.return_value = b"server1"
            elif "tmux ls" in cmd:
                # Only "active_task" session exists
                stdout.read.return_value = b"active_task\n"
            elif "find" in cmd and ".lock" in cmd:
                # Two lock files: one active, one stale
                stdout.read.return_value = (
                    b"=== /tmp/logs/active_task.lock ===\n"
                    b"cmd: sleep 100\n"
                    b"started: Mon Jan 1 12:00:00 2024\n"
                    b"server: server1\n"
                    b"session: active_task\n"
                    b"log: /tmp/logs/active_task_20240101.log\n"
                    b"\n"
                    b"=== /tmp/logs/stale_task.lock ===\n"
                    b"cmd: echo hello\n"
                    b"started: Mon Jan 1 11:00:00 2024\n"
                    b"server: server1\n"
                    b"session: stale_task\n"
                    b"log: /tmp/logs/stale_task_20240101.log\n"
                )
            elif "rm -f" in cmd:
                removed_files.append(cmd)
                stdout.read.return_value = b""
            else:
                stdout.read.return_value = b""

            return stdin, stdout, stderr

        mock_ssh_client.exec_command.side_effect = exec_command_side_effect

        client = TmuxSSHClient(mock_config)

        with patch.object(client, "_connect", return_value=mock_ssh_client):
            with patch.object(client, "_check_server_change"):
                with patch.object(client, "_update_timestamp"):
                    result = client.list_running()

        assert result == EXIT_COMPLETED

        captured = capsys.readouterr()
        # Active session should be listed as running
        assert "active_task" in captured.out
        assert "sleep 100" in captured.out
        # Stale session should be flagged and removed
        assert "stale" in captured.out.lower()
        assert "stale_task" in captured.out
        # Verify rm -f was called for the stale lock file
        assert len(removed_files) == 1
        assert "stale_task.lock" in removed_files[0]

    def test_list_running_other_server(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test that lock files from another server are shown with a note."""
        mock_ssh_client = MagicMock()

        def exec_command_side_effect(
            cmd: str,
        ) -> tuple[MagicMock, MagicMock, MagicMock]:
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "hostname" in cmd and "tmux" not in cmd and "find" not in cmd:
                stdout.read.return_value = b"server1"
            elif "tmux ls" in cmd:
                stdout.read.return_value = b""
            elif "find" in cmd and ".lock" in cmd:
                stdout.read.return_value = (
                    b"=== /tmp/logs/remote_task.lock ===\n"
                    b"cmd: long_running_job\n"
                    b"started: Mon Jan 1 10:00:00 2024\n"
                    b"server: server2\n"
                    b"session: remote_task\n"
                    b"log: /tmp/logs/remote_task_20240101.log\n"
                )
            else:
                stdout.read.return_value = b""

            return stdin, stdout, stderr

        mock_ssh_client.exec_command.side_effect = exec_command_side_effect

        client = TmuxSSHClient(mock_config)

        with patch.object(client, "_connect", return_value=mock_ssh_client):
            with patch.object(client, "_check_server_change"):
                with patch.object(client, "_update_timestamp"):
                    result = client.list_running()

        assert result == EXIT_COMPLETED

        captured = capsys.readouterr()
        assert "On another server" in captured.out
        assert "(on server2)" in captured.out

    def test_list_running_no_locks(
        self,
        mock_config: Config,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test that no lock files shows appropriate message."""
        mock_ssh_client = MagicMock()

        def exec_command_side_effect(
            cmd: str,
        ) -> tuple[MagicMock, MagicMock, MagicMock]:
            stdin = MagicMock()
            stdout = MagicMock()
            stderr = MagicMock()

            if "hostname" in cmd and "tmux" not in cmd and "find" not in cmd:
                stdout.read.return_value = b"server1"
            else:
                stdout.read.return_value = b""

            return stdin, stdout, stderr

        mock_ssh_client.exec_command.side_effect = exec_command_side_effect

        client = TmuxSSHClient(mock_config)

        with patch.object(client, "_connect", return_value=mock_ssh_client):
            with patch.object(client, "_check_server_change"):
                with patch.object(client, "_update_timestamp"):
                    result = client.list_running()

        assert result == EXIT_COMPLETED

        captured = capsys.readouterr()
        assert "No running commands found" in captured.out
