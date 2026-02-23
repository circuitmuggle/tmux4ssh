"""SSH client for executing commands in remote tmux sessions."""

from __future__ import annotations

import getpass
import os
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

import keyring
import paramiko

# ANSI color codes
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
WHITE = "\033[37m"
RESET = "\033[0m"


# Color helpers for consistent output styling
def info(msg: str) -> str:
    """Format info message [*] in cyan."""
    return f"{CYAN}[*]{RESET} {msg}"


def success(msg: str) -> str:
    """Format success message [+] in green."""
    return f"{GREEN}[+]{RESET} {msg}"


def warning(msg: str) -> str:
    """Format warning message [!] in yellow."""
    return f"{YELLOW}[!]{RESET} {msg}"


def error(msg: str) -> str:
    """Format error message [!] in red."""
    return f"{RED}[!]{RESET} {msg}"


def remote_output(line: str) -> str:
    """Format remote server output in white/default for distinction."""
    return f"{WHITE}{line}{RESET}"


# Exit codes
EXIT_COMPLETED = 0
EXIT_ERROR = 1
EXIT_STILL_RUNNING = 2
EXIT_BLOCKED = 3


@dataclass
class Config:
    """Configuration for TmuxSSHClient."""

    hostname: str
    username: str
    port: int = 22
    app_name: str = "TmuxSSHManager"
    timestamp_file: str = os.path.expanduser("~/.tmux_ssh_last_login")
    expiry_days: int = 30
    default_session: str = "remote_task"
    start_marker: str = "___CMD_START_MARKER___"
    end_marker: str = "___CMD_COMPLETE_MARKER___"
    ssh_key_path: str = os.path.expanduser("~/.ssh/id_ed25519")
    log_dir: str = "$HOME/tmux_ssh_logs"  # Remote server log directory


class TmuxSSHClient:
    """Client for executing commands on remote servers via SSH in tmux sessions."""

    def __init__(
        self,
        config: Config,
        password_provider: Callable[[str, str], str] | None = None,
        last_server: str | None = None,
        server_changed_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            config: Configuration settings
            password_provider: Optional callable to get password (for testing)
            last_server: Previously connected server hostname (for change detection)
            server_changed_callback: Callback when server changes (old, new)
        """
        self.config = config
        self._password_provider = password_provider
        self._client: paramiko.SSHClient | None = None
        self._last_server = last_server
        self._server_changed_callback = server_changed_callback
        self._current_server: str | None = None

    def get_credentials(self) -> str:
        """Retrieve credentials from keyring or prompt user securely."""
        keyring_key = f"{self.config.username}@{self.config.hostname}"
        password = keyring.get_password(self.config.app_name, keyring_key)

        expired = True
        if os.path.exists(self.config.timestamp_file):
            with open(self.config.timestamp_file) as f:
                try:
                    last_login_str = f.read().strip()
                    last_login = datetime.fromisoformat(last_login_str)
                    if datetime.now() - last_login < timedelta(
                        days=self.config.expiry_days
                    ):
                        expired = False
                except ValueError:
                    pass

        if not password or expired:
            if self._password_provider:
                password = self._password_provider(
                    self.config.hostname, self.config.username
                )
            else:
                print(info("Credentials missing or expired."))
                prompt = (
                    f"[?] Enter passphrase/password for "
                    f"{self.config.username}@{self.config.hostname}: "
                )
                password = getpass.getpass(prompt)

            if password:
                keyring.set_password(self.config.app_name, keyring_key, password)
                self._update_timestamp()

        return password

    def _update_timestamp(self) -> None:
        """Mark login as successful."""
        with open(self.config.timestamp_file, "w") as f:
            f.write(datetime.now().isoformat())

    def clear_credentials(self) -> None:
        """Wipe credentials from keyring."""
        keyring_key = f"{self.config.username}@{self.config.hostname}"
        print(info(f"Clearing stored credentials for {keyring_key}..."))
        try:
            keyring.delete_password(self.config.app_name, keyring_key)
            print(success("Keyring entry removed."))
        except Exception as e:
            print(warning(f"No keyring entry found or error occurred: {e}"))

        if os.path.exists(self.config.timestamp_file):
            os.remove(self.config.timestamp_file)
            print(success("Local timestamp file removed."))

    def _try_agent_auth(self, transport: paramiko.Transport) -> bool:
        """Try to authenticate using SSH agent.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        try:
            agent = paramiko.Agent()
            agent_keys = agent.get_keys()

            if not agent_keys:
                return False

            for key in agent_keys:
                try:
                    transport.auth_publickey(self.config.username, key)
                    return True
                except paramiko.AuthenticationException:
                    continue

            return False
        except Exception:
            return False

    def _create_ssh_client(self, password: str | None = None) -> paramiko.SSHClient:
        """Create and authenticate SSH client.

        Tries authentication in this order:
        1. SSH agent (keys loaded via ssh-add or macOS Keychain)
        2. SSH key file with passphrase
        3. Interactive authentication
        4. Password authentication

        Args:
            password: Optional password/passphrase for fallback auth methods.
                      If None and agent auth fails, will raise an exception.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        transport = paramiko.Transport((self.config.hostname, self.config.port))
        transport.start_client()

        # Try SSH agent first (no password needed)
        if self._try_agent_auth(transport):
            client._transport = transport  # type: ignore[attr-defined]
            return client

        # Agent auth failed, need password for remaining methods
        if password is None:
            transport.close()
            raise paramiko.AuthenticationException(
                "SSH agent authentication failed and no password provided"
            )

        def interactive_handler(
            title: str, instructions: str, prompt_list: list[tuple[str, bool]]
        ) -> list[str]:
            return [password]

        authenticated = False
        if os.path.exists(self.config.ssh_key_path):
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(
                    self.config.ssh_key_path, password=password
                )
                transport.auth_publickey(self.config.username, pkey)
                authenticated = True
            except Exception:
                pass

        if not authenticated:
            try:
                transport.auth_interactive(self.config.username, interactive_handler)
                authenticated = True
            except Exception:
                transport.auth_password(self.config.username, password)
                authenticated = True

        client._transport = transport  # type: ignore[attr-defined]
        return client

    @staticmethod
    def _exec(
        client: paramiko.SSHClient, cmd: str
    ) -> tuple[paramiko.ChannelFile, paramiko.ChannelFile, paramiko.ChannelFile]:
        """Execute a command on the remote server via /bin/sh.

        Wraps all commands in sh -c to avoid tcsh compatibility issues,
        since the remote login shell may be tcsh which mishandles bash-isms
        like $(), #{}, and 2>/dev/null redirects.
        """
        # Commands already wrapped in sh -c don't need double-wrapping
        if (
            cmd.startswith("sh -c ")
            or cmd.startswith("sh -c'")
            or cmd.startswith('sh -c"')
        ):
            return client.exec_command(cmd)
        # Simple commands without special chars can run directly
        # But for consistency and safety, always wrap in sh -c
        escaped = cmd.replace("'", "'\\''")
        return client.exec_command(f"sh -c '{escaped}'")

    def _get_remote_hostname(self, client: paramiko.SSHClient) -> str:
        """Get the actual hostname of the remote server."""
        _stdin, stdout, _stderr = self._exec(client, "hostname")
        return stdout.read().decode().strip()

    def _connect(self) -> paramiko.SSHClient:
        """Connect to the remote server, trying SSH agent first.

        Returns:
            Connected SSH client.

        This method:
        1. First tries SSH agent authentication (no password prompt)
        2. If agent fails, prompts for credentials and tries other methods
        """
        # First, try connecting with SSH agent only (no password)
        try:
            client = self._create_ssh_client(password=None)
            return client
        except paramiko.AuthenticationException:
            pass  # Agent auth failed, fall back to password

        # Agent failed, get credentials and try again
        password = self.get_credentials()
        return self._create_ssh_client(password=password)

    def _check_server_change(self, client: paramiko.SSHClient) -> None:
        """Check if connected to a different server than before and warn user."""
        self._current_server = self._get_remote_hostname(client)

        if self._last_server and self._current_server != self._last_server:
            print(f"\n{warning('WARNING: Server changed!')}")
            print(f"    Previous server: {self._last_server}")
            print(f"    Current server:  {self._current_server}")
            print(
                warning(
                    f"Your tmux sessions from '{self._last_server}' "
                    f"are NOT available on '{self._current_server}'."
                )
            )
            print(
                info(
                    f"To access previous sessions, connect directly to: "
                    f"{self._last_server}"
                )
            )
            print()

            if self._server_changed_callback:
                self._server_changed_callback(self._last_server, self._current_server)

    @property
    def current_server(self) -> str | None:
        """Return the actual hostname of the currently connected server."""
        return self._current_server

    @staticmethod
    def get_log_file(
        session_name: str, log_dir: str, timestamp: str | None = None
    ) -> str:
        """Get session-specific log file path with timestamp."""
        safe_name = session_name.replace("/", "_").replace(" ", "_")
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{log_dir}/{safe_name}_{timestamp}.log"

    @staticmethod
    def get_log_symlink(session_name: str, log_dir: str) -> str:
        """Get path to the 'latest' symlink for a session."""
        safe_name = session_name.replace("/", "_").replace(" ", "_")
        return f"{log_dir}/{safe_name}_latest.log"

    @staticmethod
    def get_lock_file(session_name: str, log_dir: str) -> str:
        """Get session-specific lock file path."""
        safe_name = session_name.replace("/", "_").replace(" ", "_")
        return f"{log_dir}/{safe_name}.lock"

    def _find_existing_session(self, client: paramiko.SSHClient) -> str:
        """Find an existing tmux session to use."""
        check_cmd = (
            f'sh -c \'T_SESS="{self.config.default_session}"; '
            f'if tmux has-session -t "$T_SESS" 2>/dev/null; then '
            f'  echo "$T_SESS"; '
            f"else "
            f'  DEF_S=$(tmux ls -F "#S" 2>/dev/null | head -n 1); '
            f'  if [ -n "$DEF_S" ]; then echo "$DEF_S"; fi; '
            f"fi'"
        )
        _stdin, stdout, _stderr = self._exec(client, check_cmd)
        return stdout.read().decode().strip()

    def _check_command_running(
        self, client: paramiko.SSHClient, session_name: str
    ) -> bool:
        """Check if a command is currently running by checking lock file."""
        lock_file = self.get_lock_file(session_name, self.config.log_dir)
        check_cmd = f"sh -c '[ -f \"{lock_file}\" ] && echo running || echo idle'"
        _stdin, stdout, _stderr = self._exec(client, check_cmd)
        result = stdout.read().decode().strip()
        return result == "running"

    def _find_running_session_from_locks(
        self, client: paramiko.SSHClient
    ) -> tuple[str | None, list[str]]:
        """
        Find session name by scanning lock files.
        Returns session name if exactly one lock file exists, None otherwise.
        Also returns list of all sessions with locks.
        """
        log_dir = self.config.log_dir
        # Use find wrapped in sh -c to avoid tcsh glob/redirect issues
        list_cmd = (
            f"sh -c 'find {log_dir} -maxdepth 1 -name \"*.lock\" -type f 2>/dev/null'"
        )
        _stdin, stdout, _stderr = self._exec(client, list_cmd)
        output = stdout.read().decode().strip()

        if not output:
            return None, []

        lock_files = output.split("\n")
        sessions = []

        for lock_file in lock_files:
            # Extract session name from lock file path
            # Format: ~/tmux_ssh_logs/{session}.lock
            basename = lock_file.split("/")[-1]  # {session}.lock
            session = basename.replace(".lock", "")
            sessions.append(session)

        if len(sessions) == 1:
            return sessions[0], sessions
        return None, sessions

    def _get_session_cwd(
        self, client: paramiko.SSHClient, session_name: str
    ) -> str | None:
        """Get the current working directory of a tmux session."""
        cmd = f"tmux display-message -t \"{session_name}\" -p '#{{pane_current_path}}' 2>/dev/null"
        _stdin, stdout, _stderr = self._exec(client, cmd)
        cwd = stdout.read().decode().strip()
        return cwd if cwd else None

    def cleanup(self) -> int:
        """
        Clean up idle tmux sessions created by tmux-ssh (task_* sessions).
        Keeps the default remote_task session.

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR)
        """
        try:
            print(
                info(
                    f"Connecting to {self.config.hostname} "
                    f"as {self.config.username}..."
                )
            )
            client = self._connect()
            self._check_server_change(client)

            # Get list of all tmux sessions
            list_cmd = "tmux ls -F '#{session_name}' 2>/dev/null"
            _stdin, stdout, _stderr = self._exec(client, list_cmd)
            output = stdout.read().decode().strip()

            if not output:
                print(info("No tmux sessions found."))
                client.close()
                return EXIT_COMPLETED

            sessions = output.split("\n")
            killed = []
            kept = []

            for session in sessions:
                # Skip the default session
                if session == self.config.default_session:
                    kept.append(session)
                    continue

                # Kill task_* sessions (created by --new)
                if session.startswith("task_"):
                    # Check if it has an active lock file
                    lock_file = self.get_lock_file(session, self.config.log_dir)
                    check_cmd = (
                        f"sh -c '[ -f \"{lock_file}\" ] && echo running || echo idle'"
                    )
                    _stdin, stdout, _stderr = self._exec(client, check_cmd)
                    status = stdout.read().decode().strip()

                    if status == "idle":
                        kill_cmd = f'tmux kill-session -t "{session}" 2>/dev/null'
                        self._exec(client, kill_cmd)
                        killed.append(session)
                    else:
                        kept.append(f"{session} (running)")
                else:
                    kept.append(session)

            if killed:
                print(
                    success(
                        f"Killed {len(killed)} idle session(s): {', '.join(killed)}"
                    )
                )
            else:
                print(info("No idle task_* sessions to clean up."))

            if kept:
                print(info(f"Kept session(s): {', '.join(kept)}"))

            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(error(f"Connection error: {e}"))
            return EXIT_ERROR

    def list_running(self) -> int:
        """
        List all sessions with active lock files (running commands).

        Validates each lock file against active tmux sessions:
        - Running: tmux session exists on this server
        - On another server: lock file's server differs from current hostname
        - Stale: lock file's server matches but tmux session doesn't exist
          (auto-removed)

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR)
        """
        try:
            print(
                info(
                    f"Connecting to {self.config.hostname} "
                    f"as {self.config.username}..."
                )
            )
            client = self._connect()
            self._check_server_change(client)

            log_dir = self.config.log_dir

            # Get current hostname
            _stdin, stdout, _stderr = self._exec(client, "hostname")
            current_server = stdout.read().decode().strip()

            # Get active tmux sessions
            _stdin, stdout, _stderr = self._exec(
                client, "tmux ls -F '#{session_name}' 2>/dev/null"
            )
            active_sessions = set(stdout.read().decode().strip().splitlines())

            # Get all lock files with their contents
            list_cmd = (
                f'sh -c \'find {log_dir} -maxdepth 1 -name "*.lock" -type f 2>/dev/null | '
                'while read f; do echo "=== $f ==="; cat "$f"; echo ""; done\''
            )
            _stdin, stdout, _stderr = self._exec(client, list_cmd)
            output = stdout.read().decode().strip()

            if not output:
                print(info("No running commands found."))
                self._update_timestamp()
                client.close()
                return EXIT_COMPLETED

            # Parse lock files into blocks
            blocks = []
            current_block: dict[str, str] = {}
            for line in output.splitlines():
                if line.startswith("=== ") and line.endswith(" ==="):
                    if current_block:
                        blocks.append(current_block)
                    current_block = {"path": line[4:-4]}
                elif current_block:
                    if line.startswith("server:"):
                        current_block["server"] = line.split(":", 1)[1].strip()
                    elif line.startswith("session:"):
                        current_block["session"] = line.split(":", 1)[1].strip()
                    elif line.startswith("cmd:"):
                        current_block["cmd"] = line.split(":", 1)[1].strip()
                    elif line.startswith("started:"):
                        current_block["started"] = line.split(":", 1)[1].strip()
                    elif line.startswith("log:"):
                        current_block["log"] = line.split(":", 1)[1].strip()
            if current_block:
                blocks.append(current_block)

            running = []
            other_server = []
            stale = []

            for block in blocks:
                lock_server = block.get("server", "")
                session = block.get("session", "")

                if lock_server and lock_server != current_server:
                    other_server.append(block)
                elif session in active_sessions:
                    running.append(block)
                else:
                    stale.append(block)

            # Display running commands
            if running:
                print(info("Running commands:\n"))
                for block in running:
                    print(f"  Session:  {block.get('session', 'unknown')}")
                    print(f"  Command:  {block.get('cmd', 'unknown')}")
                    print(f"  Started:  {block.get('started', 'unknown')}")
                    print(f"  Server:   {block.get('server', 'unknown')}")
                    print(f"  Log:      {block.get('log', 'unknown')}")
                    print()

            # Display commands on other servers
            if other_server:
                print(info("On another server:\n"))
                for block in other_server:
                    server = block.get("server", "unknown")
                    print(
                        f"  Session:  {block.get('session', 'unknown')} "
                        f"(on {server})"
                    )
                    print(f"  Command:  {block.get('cmd', 'unknown')}")
                    print(f"  Started:  {block.get('started', 'unknown')}")
                    print(f"  Log:      {block.get('log', 'unknown')}")
                    print()

            # Auto-remove stale lock files
            if stale:
                print(warning("Stale lock files (auto-removing):\n"))
                for block in stale:
                    lock_path = block.get("path", "")
                    print(
                        f"  Session:  {block.get('session', 'unknown')} "
                        f"(stale - tmux session not found)"
                    )
                    print(f"  Command:  {block.get('cmd', 'unknown')}")
                    print(f"  Started:  {block.get('started', 'unknown')}")
                    if lock_path:
                        self._exec(client, f'rm -f "{lock_path}"')
                        print(f"  Removed:  {lock_path}")
                    print()

            if not running and not other_server and not stale:
                print(info("No running commands found."))

            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(error(f"Connection error: {e}"))
            return EXIT_ERROR

    def attach(self, session_name: str | None = None) -> int:
        """Attach to an existing session and resume streaming its log output.

        Args:
            session_name: Session to attach to (default: auto-detect from lock files)

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR, EXIT_STILL_RUNNING)
        """
        try:
            print(
                info(
                    f"Connecting to {self.config.hostname} "
                    f"as {self.config.username}..."
                )
            )
            client = self._connect()
            self._check_server_change(client)

            # If no session specified, try to auto-detect from lock files
            if not session_name:
                auto_session, all_sessions = self._find_running_session_from_locks(
                    client
                )

                if not all_sessions:
                    print(warning("No running commands found (no lock files)."))
                    client.close()
                    return EXIT_ERROR

                if len(all_sessions) == 1:
                    session_name = auto_session
                    assert session_name is not None  # Guaranteed when len == 1
                    print(info(f"Auto-detected session: {session_name}"))
                else:
                    print(
                        warning(
                            f"Multiple running sessions found: {', '.join(all_sessions)}"
                        )
                    )
                    print(
                        info(
                            "Please specify a session with: tmux-ssh --attach <session_name>"
                        )
                    )
                    print(info("Or use 'tmux-ssh --list' to see details."))
                    client.close()
                    return EXIT_ERROR

            print(info(f"Attaching to session: {session_name}"))

            # Verify tmux session actually exists on this server
            # (lock file may be visible via shared NFS but session is elsewhere)
            check_session_cmd = f'tmux has-session -t "{session_name}" 2>/dev/null && echo exists || echo missing'
            _stdin, stdout, _stderr = self._exec(client, check_session_cmd)
            session_status = stdout.read().decode().strip()

            if session_status != "exists":
                # Get lock file info to find actual server
                lock_file = self.get_lock_file(session_name, self.config.log_dir)
                get_lock_cmd = f'sh -c \'grep "^server:" "{lock_file}" 2>/dev/null\''
                _stdin, stdout, _stderr = self._exec(client, get_lock_cmd)
                server_line = stdout.read().decode().strip()
                lock_server = (
                    server_line.split(":", 1)[1].strip() if server_line else None
                )

                print(error(f"Tmux session '{session_name}' not found on this server!"))
                print(f"    Currently connected to: {self._current_server}")

                if lock_server and lock_server != self._current_server:
                    # Session is on a different server
                    print(f"    Session was created on: {lock_server}")
                    print(
                        info(
                            f"To attach, connect directly: "
                            f"tmux-ssh -H {lock_server} --attach {session_name}"
                        )
                    )
                elif lock_server and lock_server == self._current_server:
                    # Lock file says session is here but tmux says it doesn't exist
                    # This is a stale lock file
                    print(
                        warning(
                            "Lock file is stale - session was on this server but no longer exists."
                        )
                    )
                    print(info(f"Removing stale lock file: {lock_file}"))
                    self._exec(client, f'rm -f "{lock_file}"')
                else:
                    print(
                        warning(
                            "Lock file exists (possibly via shared NFS) but session is on another server."
                        )
                    )
                    print(
                        info(
                            "Check 'tmux-ssh --list' on each server to find where the session is running."
                        )
                    )
                client.close()
                return EXIT_ERROR

            # Check if command is running
            if not self._check_command_running(client, session_name):
                print(
                    warning(
                        f"No command currently running in session '{session_name}'."
                    )
                )
                log_symlink = self.get_log_symlink(session_name, self.config.log_dir)
                print(info(f"You can view the latest log at: {log_symlink}"))
                client.close()
                return EXIT_COMPLETED

            # Get the log file from lock file
            lock_file = self.get_lock_file(session_name, self.config.log_dir)
            get_log_cmd = (
                f'sh -c \'if [ -f "{lock_file}" ]; then cat "{lock_file}"; fi\''
            )
            _stdin, stdout, _stderr = self._exec(client, get_log_cmd)
            lock_info = stdout.read().decode().strip()
            print(info(f"Lock file info:\n{lock_info}\n"))

            # Stream from the latest symlink
            log_symlink = self.get_log_symlink(session_name, self.config.log_dir)
            print(info(f"Streaming from: {log_symlink}"))
            print(f"{CYAN}[*] Streaming output:{RESET}\n")

            tail_cmd = f'tail -n +1 -f "{log_symlink}"'
            _stdin, stdout, _stderr = self._exec(client, tail_cmd)

            channel = stdout.channel
            channel.setblocking(0)

            last_output_time = time.time()
            buffer = ""
            command_completed = False
            started = False
            start_marker = self.config.start_marker
            end_marker = self.config.end_marker

            while not command_completed:
                try:
                    if channel.recv_ready():
                        chunk = channel.recv(4096).decode("utf-8", errors="replace")
                        if chunk:
                            last_output_time = time.time()
                            buffer += chunk

                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)

                                if start_marker in line:
                                    started = True
                                    continue

                                if end_marker in line:
                                    command_completed = True
                                    break

                                if started:
                                    print(remote_output(line))
                                    sys.stdout.flush()
                    else:
                        time.sleep(0.1)

                    # Check if lock file still exists (command still running)
                    idle_time = time.time() - last_output_time
                    if idle_time > 30:  # Check every 30 seconds of idle
                        if not self._check_command_running(client, session_name):
                            print(f"\n{info('Command appears to have completed.')}")
                            command_completed = True
                            break
                        last_output_time = time.time()  # Reset to avoid repeated checks

                except Exception:
                    time.sleep(0.1)

            print(f"\n{success('Command completed.')}")
            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(error(f"Connection error: {e}"))
            return EXIT_ERROR

    def kill(self, session_name: str | None = None, force: bool = False) -> int:
        """Kill the running command in a tmux session.

        Args:
            session_name: Session to kill command in (default: auto-detect from lock files)
            force: Skip confirmation prompt

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR)
        """
        try:
            print(
                info(
                    f"Connecting to {self.config.hostname} "
                    f"as {self.config.username}..."
                )
            )
            client = self._connect()
            self._check_server_change(client)

            current_server = self._current_server

            # If no session specified, try to auto-detect from lock files
            if not session_name:
                auto_session, all_sessions = self._find_running_session_from_locks(
                    client
                )

                if not all_sessions:
                    print(warning("No running commands found (no lock files)."))
                    client.close()
                    return EXIT_ERROR

                if len(all_sessions) == 1:
                    session_name = auto_session
                    assert session_name is not None  # Guaranteed when len == 1
                    print(info(f"Auto-detected session: {session_name}"))
                else:
                    print(
                        warning(
                            f"Multiple running sessions found: {', '.join(all_sessions)}"
                        )
                    )
                    print(
                        info(
                            "Please specify a session with: tmux-ssh --kill <session_name>"
                        )
                    )
                    print(info("Or use 'tmux-ssh --list' to see details."))
                    client.close()
                    return EXIT_ERROR

            # Check if command is running
            if not self._check_command_running(client, session_name):
                print(
                    warning(
                        f"No command currently running in session '{session_name}'."
                    )
                )
                client.close()
                return EXIT_COMPLETED

            # Get lock file info before killing
            lock_file = self.get_lock_file(session_name, self.config.log_dir)
            get_lock_cmd = (
                f'sh -c \'if [ -f "{lock_file}" ]; then cat "{lock_file}"; fi\''
            )
            _stdin, stdout, _stderr = self._exec(client, get_lock_cmd)
            lock_info = stdout.read().decode().strip()

            # Parse lock file info
            lock_server = None
            lock_cmd = None
            if lock_info:
                for line in lock_info.split("\n"):
                    if line.startswith("server:"):
                        lock_server = line.split(":", 1)[1].strip()
                    elif line.startswith("cmd:"):
                        lock_cmd = line.split(":", 1)[1].strip()

            # Verify server matches
            if lock_server and lock_server != current_server:
                print(error("Server mismatch!"))
                print(f"    Lock file says session is on: {lock_server}")
                print(f"    Currently connected to:       {current_server}")
                print(warning("This session was created on a different server."))
                print(
                    info(
                        f"To kill it, connect directly: "
                        f"tmux-ssh -H {lock_server} --kill {session_name}"
                    )
                )
                client.close()
                return EXIT_ERROR

            # Verify tmux session actually exists on this server
            # (lock file may be visible via shared NFS but session is elsewhere)
            check_session_cmd = f'tmux has-session -t "{session_name}" 2>/dev/null && echo exists || echo missing'
            _stdin, stdout, _stderr = self._exec(client, check_session_cmd)
            session_status = stdout.read().decode().strip()

            if session_status != "exists":
                print(error(f"Tmux session '{session_name}' not found on this server!"))
                print(f"    Currently connected to: {current_server}")

                if lock_server and lock_server != current_server:
                    # Session is on a different server
                    print(f"    Session was created on: {lock_server}")
                    print(
                        info(
                            f"To kill it, connect directly: "
                            f"tmux-ssh -H {lock_server} --kill {session_name}"
                        )
                    )
                elif lock_server and lock_server == current_server:
                    # Lock file says session is here but tmux says it doesn't exist
                    # This is a stale lock file
                    print(
                        warning(
                            "Lock file is stale - session was on this server but no longer exists."
                        )
                    )
                    print(info(f"Removing stale lock file: {lock_file}"))
                    self._exec(client, f'rm -f "{lock_file}"')
                else:
                    print(
                        warning(
                            "Lock file exists (possibly via shared NFS) but session is on another server."
                        )
                    )
                    print(
                        info(
                            "Check 'tmux-ssh --list' on each server to find where the session is running."
                        )
                    )
                client.close()
                return EXIT_ERROR

            # Show what we're about to kill
            print(info(f"About to kill command in session '{session_name}':"))
            print(f"    Server:  {current_server}")
            if lock_cmd:
                print(
                    f"    Command: {lock_cmd[:80]}{'...' if len(lock_cmd) > 80 else ''}"
                )

            # Confirmation prompt (unless force)
            if not force:
                try:
                    response = input("\n[?] Kill this command? [y/N]: ").strip().lower()
                    if response not in {"y", "yes"}:
                        print(info("Cancelled."))
                        client.close()
                        return EXIT_COMPLETED
                except (EOFError, KeyboardInterrupt):
                    print("\n" + info("Cancelled."))
                    client.close()
                    return EXIT_COMPLETED

            # Send Ctrl+C to the tmux session
            kill_cmd = f'tmux send-keys -t "{session_name}" C-c'
            self._exec(client, kill_cmd)

            # Wait a moment for the signal to be processed
            time.sleep(0.5)

            # Remove the lock file
            rm_lock_cmd = f'rm -f "{lock_file}"'
            self._exec(client, rm_lock_cmd)

            print(success(f"Killed command in session '{session_name}'."))

            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(error(f"Connection error: {e}"))
            return EXIT_ERROR

    def execute(
        self,
        command: str,
        timeout: int | None = None,
        idle_timeout: int = 3600,
        new_session: bool = False,
        force: bool = False,
        auto: bool = True,
    ) -> int:
        """Execute a command in tmux and stream output in real-time.

        Args:
            command: Command to execute
            timeout: Max seconds to stream (None = unlimited)
            idle_timeout: Exit if no output for N seconds (default: 3600)
            new_session: Create a new unique session
            force: Force execution even if command is running
            auto: Auto-create new session if command already running (default: True)

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR, EXIT_STILL_RUNNING, EXIT_BLOCKED)
        """
        try:
            print(
                info(
                    f"Connecting to {self.config.hostname} "
                    f"as {self.config.username}..."
                )
            )
            client = self._connect()
            self._check_server_change(client)

            # Determine session name
            if new_session:
                session_name = f"task_{uuid.uuid4().hex[:8]}"
            else:
                session_name = self._find_existing_session(client)
                if not session_name:
                    session_name = self.config.default_session

                if not force and self._check_command_running(client, session_name):
                    if auto:
                        # Auto-create new session for concurrent execution
                        old_session = session_name
                        new_session = True
                        session_name = f"task_{uuid.uuid4().hex[:8]}"
                        print(
                            info(
                                f"Session '{old_session}' is busy, "
                                f"creating '{session_name}' for concurrent execution..."
                            )
                        )
                    else:
                        msg = f"Command already running in session '{session_name}'."
                        print(f"\n{warning(msg)}")
                        print(info("Options:"))
                        print("    --new   : Run in a new session (safe concurrency)")
                        print("    --force : Override and kill existing command")
                        print("    --auto  : Enable auto-create new session (default)")
                        client.close()
                        return EXIT_BLOCKED

            log_file = self.get_log_file(session_name, self.config.log_dir)
            log_symlink = self.get_log_symlink(session_name, self.config.log_dir)
            lock_file = self.get_lock_file(session_name, self.config.log_dir)
            log_dir = self.config.log_dir

            # Escape quotes for nested shell quoting
            safe_cmd = command.replace("'", "'\\''")
            safe_cmd = safe_cmd.replace('"', '\\"')

            start_marker = self.config.start_marker
            end_marker = self.config.end_marker

            # Build dispatch command with lock file
            # Creates log directory, timestamped log file, and symlink to latest
            if new_session:
                # Get current directory from default session to inherit
                default_cwd = self._get_session_cwd(client, self.config.default_session)
                cd_cmd = f'cd \\"{default_cwd}\\" 2>/dev/null; ' if default_cwd else ""

                # Create new session - NO exec /bin/bash so it auto-kills when done
                dispatch_cmd = (
                    f"sh -c '"
                    f"mkdir -p {log_dir}; "
                    f'touch "{log_file}"; '
                    f'ln -sf "{log_file}" "{log_symlink}"; '
                    f'echo "cmd: {safe_cmd}" > "{lock_file}"; '
                    f'echo "started: $(date)" >> "{lock_file}"; '
                    f'echo "server: $(hostname)" >> "{lock_file}"; '
                    f'echo "session: {session_name}" >> "{lock_file}"; '
                    f'echo "log: {log_file}" >> "{lock_file}"; '
                    f'tmux new-session -d -s "{session_name}" '
                    f'"/bin/bash -l -c \\"{cd_cmd}echo {start_marker} >> {log_file}; '
                    f"( {safe_cmd} ) 2>&1 | tee -a {log_file}; "
                    f"echo {end_marker} >> {log_file}; "
                    f'rm -f {lock_file}\\""; '
                    f'echo "{session_name}"\''
                )
                if default_cwd:
                    print(
                        info(
                            f"Inheriting directory from {self.config.default_session}: "
                            f"{default_cwd}"
                        )
                    )
            else:
                # Use existing session - keep alive with exec /bin/bash for default session
                force_cleanup = (
                    f'rm -f "{lock_file}"; '
                    f'tmux send-keys -t "{session_name}" C-c; sleep 0.3; '
                    if force
                    else ""
                )
                dispatch_cmd = (
                    f"sh -c '"
                    f"mkdir -p {log_dir}; "
                    f'touch "{log_file}"; '
                    f'ln -sf "{log_file}" "{log_symlink}"; '
                    f'echo "cmd: {safe_cmd}" > "{lock_file}"; '
                    f'echo "started: $(date)" >> "{lock_file}"; '
                    f'echo "server: $(hostname)" >> "{lock_file}"; '
                    f'echo "session: {session_name}" >> "{lock_file}"; '
                    f'echo "log: {log_file}" >> "{lock_file}"; '
                    f'if tmux has-session -t "{session_name}" 2>/dev/null; then '
                    f"  {force_cleanup}"
                    f'  tmux kill-session -t "{session_name}"; '
                    f"fi; "
                    f'tmux new-session -d -s "{session_name}" '
                    f'"/bin/bash -l -c \\"echo {start_marker} >> {log_file}; '
                    f"( {safe_cmd} ) 2>&1 | tee -a {log_file}; "
                    f"echo {end_marker} >> {log_file}; "
                    f'rm -f {lock_file}; exec /bin/bash\\""; '
                    f'echo "{session_name}"\''
                )

            _stdin, stdout, _stderr = self._exec(client, dispatch_cmd)
            # Read stdout to ensure command completes, but use session_name
            # which we already know (more reliable than parsing command output)
            stdout.read()

            if new_session:
                print(info(f"Created new session: {session_name}"))
            else:
                print(info(f"Using session: {session_name}"))

            if timeout:
                print(info(f"Timeout: {timeout}s, Idle timeout: {idle_timeout}s"))
            else:
                print(info(f"Idle timeout: {idle_timeout}s"))

            print(f"{CYAN}[*] Dispatching:{RESET} {command}")
            print(info(f"Log file: {log_file}"))
            time.sleep(0.5)
            print(f"{CYAN}[*] Streaming output:{RESET}\n")

            # Stream output using tail -f on the symlink
            tail_cmd = f'tail -n +1 -f "{log_symlink}"'
            _stdin, stdout, _stderr = self._exec(client, tail_cmd)

            channel = stdout.channel
            channel.setblocking(0)

            start_time = time.time()
            last_output_time = time.time()
            buffer = ""
            command_completed = False
            started = False

            while not command_completed:
                try:
                    if channel.recv_ready():
                        chunk = channel.recv(4096).decode("utf-8", errors="replace")
                        if chunk:
                            last_output_time = time.time()
                            buffer += chunk

                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)

                                if start_marker in line:
                                    started = True
                                    continue

                                if end_marker in line:
                                    command_completed = True
                                    break

                                if started:
                                    print(remote_output(line))
                                    sys.stdout.flush()
                    else:
                        time.sleep(0.1)

                    elapsed = time.time() - start_time
                    idle_time = time.time() - last_output_time

                    if timeout and elapsed > timeout:
                        print(
                            f"\n{info(f'Timeout ({timeout}s) reached. Command still running in tmux.')}"
                        )
                        print(
                            info(
                                "Use 'tmux-ssh --attach' to resume streaming the output."
                            )
                        )
                        print(info(f"Log file: {log_file}"))
                        self._update_timestamp()
                        client.close()
                        return EXIT_STILL_RUNNING

                    if idle_time > idle_timeout:
                        print(
                            f"\n{info(f'Idle timeout ({idle_timeout}s) reached. Command still running in tmux.')}"
                        )
                        print(
                            info(
                                "Use 'tmux-ssh --attach' to resume streaming the output."
                            )
                        )
                        print(info(f"Log file: {log_file}"))
                        self._update_timestamp()
                        client.close()
                        return EXIT_STILL_RUNNING

                except Exception:
                    time.sleep(0.1)

            print(f"\n{success('Command completed.')}")
            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(error(f"Connection error: {e}"))
            return EXIT_ERROR
