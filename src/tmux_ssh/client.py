"""SSH client for executing commands in remote tmux sessions."""

from __future__ import annotations

import os
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

import keyring
import paramiko

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
    app_name: str = "TmuxSSHManager"
    timestamp_file: str = os.path.expanduser("~/.tmux_ssh_last_login")
    expiry_days: int = 30
    default_session: str = "remote_task"
    start_marker: str = "___CMD_START_MARKER___"
    end_marker: str = "___CMD_COMPLETE_MARKER___"
    ssh_key_path: str = os.path.expanduser("~/.ssh/id_ed25519")
    log_dir: str = "~/tmux_ssh_logs"  # Remote server log directory


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
                import getpass

                print("[*] Credentials missing or expired.")
                prompt = (
                    f"[?] Enter passphrase/password for "
                    f"{self.config.username}@{self.config.hostname}: "
                )
                password = getpass.getpass(prompt)

            if password:
                keyring.set_password(self.config.app_name, keyring_key, password)
                self._update_timestamp()

        return password  # type: ignore[return-value]

    def _update_timestamp(self) -> None:
        """Mark login as successful."""
        with open(self.config.timestamp_file, "w") as f:
            f.write(datetime.now().isoformat())

    def clear_credentials(self) -> None:
        """Wipe credentials from keyring."""
        keyring_key = f"{self.config.username}@{self.config.hostname}"
        print(f"[*] Clearing stored credentials for {keyring_key}...")
        try:
            keyring.delete_password(self.config.app_name, keyring_key)
            print("[+] Keyring entry removed.")
        except Exception as e:
            print(f"[!] No keyring entry found or error occurred: {e}")

        if os.path.exists(self.config.timestamp_file):
            os.remove(self.config.timestamp_file)
            print("[+] Local timestamp file removed.")

    def _create_ssh_client(self, password: str) -> paramiko.SSHClient:
        """Create and authenticate SSH client."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        transport = paramiko.Transport((self.config.hostname, 22))
        transport.start_client()

        def interactive_handler(
            title: str, instructions: str, prompt_list: list
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

        client._transport = transport
        return client

    def _get_remote_hostname(self, client: paramiko.SSHClient) -> str:
        """Get the actual hostname of the remote server."""
        stdin, stdout, stderr = client.exec_command("hostname")
        return stdout.read().decode().strip()

    def _check_server_change(self, client: paramiko.SSHClient) -> None:
        """Check if connected to a different server than before and warn user."""
        self._current_server = self._get_remote_hostname(client)

        if self._last_server and self._current_server != self._last_server:
            print("\n[!] WARNING: Server changed!")
            print(f"    Previous server: {self._last_server}")
            print(f"    Current server:  {self._current_server}")
            print(
                f"[!] Your tmux sessions from '{self._last_server}' "
                f"are NOT available on '{self._current_server}'."
            )
            print(
                f"[*] To access previous sessions, connect directly to: "
                f"{self._last_server}"
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
        stdin, stdout, stderr = client.exec_command(check_cmd)
        return stdout.read().decode().strip()

    def _check_command_running(
        self, client: paramiko.SSHClient, session_name: str
    ) -> bool:
        """Check if a command is currently running by checking lock file."""
        lock_file = self.get_lock_file(session_name, self.config.log_dir)
        check_cmd = f"sh -c '[ -f \"{lock_file}\" ] && echo running || echo idle'"
        stdin, stdout, stderr = client.exec_command(check_cmd)
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
        list_cmd = f"sh -c 'ls {log_dir}/*.lock 2>/dev/null'"
        stdin, stdout, stderr = client.exec_command(list_cmd)
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
        stdin, stdout, stderr = client.exec_command(cmd)
        cwd = stdout.read().decode().strip()
        return cwd if cwd else None

    def cleanup(self) -> int:
        """
        Clean up idle tmux sessions created by tmux-ssh (task_* sessions).
        Keeps the default remote_task session.

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR)
        """
        password = self.get_credentials()

        try:
            print(
                f"[*] Connecting to {self.config.hostname} "
                f"as {self.config.username}..."
            )
            client = self._create_ssh_client(password)
            self._check_server_change(client)

            # Get list of all tmux sessions
            list_cmd = "tmux ls -F '#{session_name}' 2>/dev/null"
            stdin, stdout, stderr = client.exec_command(list_cmd)
            output = stdout.read().decode().strip()

            if not output:
                print("[*] No tmux sessions found.")
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
                    stdin, stdout, stderr = client.exec_command(check_cmd)
                    status = stdout.read().decode().strip()

                    if status == "idle":
                        kill_cmd = f'tmux kill-session -t "{session}" 2>/dev/null'
                        client.exec_command(kill_cmd)
                        killed.append(session)
                    else:
                        kept.append(f"{session} (running)")
                else:
                    kept.append(session)

            if killed:
                print(f"[+] Killed {len(killed)} idle session(s): {', '.join(killed)}")
            else:
                print("[*] No idle task_* sessions to clean up.")

            if kept:
                print(f"[*] Kept session(s): {', '.join(kept)}")

            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(f"[!] Connection error: {e}")
            return EXIT_ERROR

    def list_running(self) -> int:
        """
        List all sessions with active lock files (running commands).

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR)
        """
        password = self.get_credentials()

        try:
            print(
                f"[*] Connecting to {self.config.hostname} "
                f"as {self.config.username}..."
            )
            client = self._create_ssh_client(password)
            self._check_server_change(client)

            log_dir = self.config.log_dir
            list_cmd = (
                f"sh -c 'for f in {log_dir}/*.lock 2>/dev/null; do "
                f'if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; echo ""; fi; done\''
            )
            stdin, stdout, stderr = client.exec_command(list_cmd)
            output = stdout.read().decode().strip()

            if not output:
                print("[*] No running commands found.")
            else:
                print("[*] Running commands:\n")
                print(output)

            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(f"[!] Connection error: {e}")
            return EXIT_ERROR

    def attach(self, session_name: str | None = None) -> int:
        """Attach to an existing session and resume streaming its log output.

        Args:
            session_name: Session to attach to (default: auto-detect from lock files)

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR, EXIT_STILL_RUNNING)
        """
        password = self.get_credentials()

        try:
            print(
                f"[*] Connecting to {self.config.hostname} "
                f"as {self.config.username}..."
            )
            client = self._create_ssh_client(password)
            self._check_server_change(client)

            # If no session specified, try to auto-detect from lock files
            if not session_name:
                auto_session, all_sessions = self._find_running_session_from_locks(
                    client
                )

                if not all_sessions:
                    print("[!] No running commands found (no lock files).")
                    client.close()
                    return EXIT_ERROR

                if len(all_sessions) == 1:
                    session_name = auto_session
                    print(f"[*] Auto-detected session: {session_name}")
                else:
                    print(
                        f"[!] Multiple running sessions found: {', '.join(all_sessions)}"
                    )
                    print(
                        "[*] Please specify a session with: tmux-ssh --attach <session_name>"
                    )
                    print("[*] Or use 'tmux-ssh --list' to see details.")
                    client.close()
                    return EXIT_ERROR

            print(f"[*] Attaching to session: {session_name}")

            # Check if command is running
            if not self._check_command_running(client, session_name):
                print(f"[!] No command currently running in session '{session_name}'.")
                log_symlink = self.get_log_symlink(session_name, self.config.log_dir)
                print(f"[*] You can view the latest log at: {log_symlink}")
                client.close()
                return EXIT_COMPLETED

            # Get the log file from lock file
            lock_file = self.get_lock_file(session_name, self.config.log_dir)
            get_log_cmd = (
                f'sh -c \'if [ -f "{lock_file}" ]; then cat "{lock_file}"; fi\''
            )
            stdin, stdout, stderr = client.exec_command(get_log_cmd)
            lock_info = stdout.read().decode().strip()
            print(f"[*] Lock file info:\n{lock_info}\n")

            # Stream from the latest symlink
            log_symlink = self.get_log_symlink(session_name, self.config.log_dir)
            print(f"[*] Streaming from: {log_symlink}")
            print("[*] Streaming output:\n")

            tail_cmd = f'tail -n +1 -f "{log_symlink}"'
            stdin, stdout, stderr = client.exec_command(tail_cmd)

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
                                    print(line)
                                    sys.stdout.flush()
                    else:
                        time.sleep(0.1)

                    # Check if lock file still exists (command still running)
                    idle_time = time.time() - last_output_time
                    if idle_time > 30:  # Check every 30 seconds of idle
                        if not self._check_command_running(client, session_name):
                            print("\n[*] Command appears to have completed.")
                            command_completed = True
                            break
                        last_output_time = time.time()  # Reset to avoid repeated checks

                except Exception:
                    time.sleep(0.1)

            print("\n[+] Command completed.")
            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(f"[!] Connection error: {e}")
            return EXIT_ERROR

    def execute(
        self,
        command: str,
        timeout: int | None = None,
        idle_timeout: int = 3600,
        new_session: bool = False,
        force: bool = False,
    ) -> int:
        """Execute a command in tmux and stream output in real-time.

        Args:
            command: Command to execute
            timeout: Max seconds to stream (None = unlimited)
            idle_timeout: Exit if no output for N seconds (default: 3600)
            new_session: Create a new unique session
            force: Force execution even if command is running

        Returns:
            Exit code (EXIT_COMPLETED, EXIT_ERROR, EXIT_STILL_RUNNING, EXIT_BLOCKED)
        """
        password = self.get_credentials()

        try:
            print(
                f"[*] Connecting to {self.config.hostname} "
                f"as {self.config.username}..."
            )
            client = self._create_ssh_client(password)
            self._check_server_change(client)

            # Determine session name
            if new_session:
                session_name = f"task_{uuid.uuid4().hex[:8]}"
                print(f"[*] Creating new session: {session_name}")
            else:
                session_name = self._find_existing_session(client)
                if not session_name:
                    session_name = self.config.default_session
                print(f"[*] Using existing session: {session_name}")

                if not force and self._check_command_running(client, session_name):
                    print(f"\n[!] Command already running in session '{session_name}'.")
                    print("[*] Options:")
                    print("    --new   : Run in a new session (safe concurrency)")
                    print("    --force : Override and kill existing command")
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
                        f"[*] Inheriting directory from {self.config.default_session}: "
                        f"{default_cwd}"
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
                    f'echo "session: {session_name}" >> "{lock_file}"; '
                    f'echo "log: {log_file}" >> "{lock_file}"; '
                    f'if tmux has-session -t "{session_name}" 2>/dev/null; then '
                    f"  {force_cleanup}"
                    f'  tmux send-keys -t "{session_name}" '
                    f'"/bin/bash -l -c \\"echo {start_marker} >> {log_file}; '
                    f"( {safe_cmd} ) 2>&1 | tee -a {log_file}; "
                    f"echo {end_marker} >> {log_file}; "
                    f'rm -f {lock_file}\\"" ENTER; '
                    f"else "
                    f'  tmux new-session -d -s "{session_name}" '
                    f'"/bin/bash -l -c \\"echo {start_marker} >> {log_file}; '
                    f"( {safe_cmd} ) 2>&1 | tee -a {log_file}; "
                    f"echo {end_marker} >> {log_file}; "
                    f'rm -f {lock_file}; exec /bin/bash\\""; '
                    f"fi; "
                    f'echo "{session_name}"\''
                )

            stdin, stdout, stderr = client.exec_command(dispatch_cmd)
            target_session = stdout.read().decode().strip()
            print(f"[*] Running in tmux session: {target_session}")

            if timeout:
                print(f"[*] Timeout: {timeout}s, Idle timeout: {idle_timeout}s")
            else:
                print(f"[*] Idle timeout: {idle_timeout}s")

            print(f"[*] Dispatching: {command}")
            print(f"[*] Log file: {log_file}")
            time.sleep(0.5)
            print("[*] Streaming output:\n")

            # Stream output using tail -f on the symlink
            tail_cmd = f'tail -n +1 -f "{log_symlink}"'
            stdin, stdout, stderr = client.exec_command(tail_cmd)

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
                                    print(line)
                                    sys.stdout.flush()
                    else:
                        time.sleep(0.1)

                    elapsed = time.time() - start_time
                    idle_time = time.time() - last_output_time

                    if timeout and elapsed > timeout:
                        print(
                            f"\n[*] Timeout ({timeout}s) reached. "
                            "Command still running in tmux."
                        )
                        print(
                            "[*] Use 'tmux-ssh --attach' to resume streaming the output."
                        )
                        print(f"[*] Log file: {log_file}")
                        self._update_timestamp()
                        client.close()
                        return EXIT_STILL_RUNNING

                    if idle_time > idle_timeout:
                        print(
                            f"\n[*] Idle timeout ({idle_timeout}s) reached. "
                            "Command still running in tmux."
                        )
                        print(
                            "[*] Use 'tmux-ssh --attach' to resume streaming the output."
                        )
                        print(f"[*] Log file: {log_file}")
                        self._update_timestamp()
                        client.close()
                        return EXIT_STILL_RUNNING

                except Exception:
                    time.sleep(0.1)

            print("\n[+] Command completed.")
            self._update_timestamp()
            client.close()
            return EXIT_COMPLETED

        except Exception as e:
            print(f"[!] Connection error: {e}")
            return EXIT_ERROR
