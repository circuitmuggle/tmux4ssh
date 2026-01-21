import argparse
import getpass
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta

import keyring
import paramiko

# ================= Configuration Defaults =================
APP_NAME = "TmuxSSHManager"
CONFIG_FILE = os.path.expanduser("~/.tmux_ssh_config")
TIMESTAMP_FILE = os.path.expanduser("~/.tmux_ssh_last_login")
EXPIRY_DAYS = 30
TMUX_SESSION = "remote_task"
START_MARKER = "___CMD_START_MARKER___"
END_MARKER = "___CMD_COMPLETE_MARKER___"
LOG_DIR = "~/tmux_ssh_logs"  # Remote server log directory
# ==========================================================


def load_saved_config():
    """Load saved host/user from config file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(host, user, last_server=None):
    """Save host/user/last_server to config file for future use."""
    config = {"host": host, "user": user}
    if last_server:
        config["last_server"] = last_server
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
    except OSError:
        pass  # Silently fail if we can't write


# Exit codes
EXIT_COMPLETED = 0
EXIT_ERROR = 1
EXIT_STILL_RUNNING = 2
EXIT_BLOCKED = 3  # Command blocked due to running command in session


def get_credentials(hostname, username):
    """Retrieve credentials from keyring or prompt user securely."""
    keyring_key = f"{username}@{hostname}"
    password = keyring.get_password(APP_NAME, keyring_key)

    expired = True
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE) as f:
            try:
                last_login_str = f.read().strip()
                last_login = datetime.fromisoformat(last_login_str)
                if datetime.now() - last_login < timedelta(days=EXPIRY_DAYS):
                    expired = False
            except ValueError:
                pass

    if not password or expired:
        print("[*] Credentials missing or expired.")
        prompt_msg = f"[?] Enter passphrase/password for {username}@{hostname}: "
        password = getpass.getpass(prompt_msg)
        if password:
            keyring.set_password(APP_NAME, keyring_key, password)
            update_timestamp()

    return password


def update_timestamp():
    """Mark login as successful."""
    with open(TIMESTAMP_FILE, "w") as f:
        f.write(datetime.now().isoformat())


def clear_credentials(hostname, username):
    """Wipe credentials on failure."""
    keyring_key = f"{username}@{hostname}"
    print(f"[*] Clearing stored credentials for {keyring_key}...")
    try:
        keyring.delete_password(APP_NAME, keyring_key)
        print("[+] Keyring entry removed.")
    except Exception as e:
        print(f"[!] No keyring entry found to delete or error occurred: {e}")

    if os.path.exists(TIMESTAMP_FILE):
        os.remove(TIMESTAMP_FILE)
        print("[+] Local timestamp file removed.")


def create_ssh_client(hostname, username, password):
    """Create and authenticate SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    transport = paramiko.Transport((hostname, 22))
    transport.start_client()

    def interactive_handler(title, instructions, prompt_list):
        return [password]

    # Auth logic
    pkey_path = os.path.expanduser("~/.ssh/id_ed25519")
    authenticated = False
    if os.path.exists(pkey_path):
        try:
            pkey = paramiko.Ed25519Key.from_private_key_file(
                pkey_path, password=password
            )
            transport.auth_publickey(username, pkey)
            authenticated = True
        except:
            pass

    if not authenticated:
        try:
            transport.auth_interactive(username, interactive_handler)
            authenticated = True
        except:
            transport.auth_password(username, password)
            authenticated = True

    client._transport = transport
    return client


def get_remote_hostname(client):
    """Get the actual hostname of the remote server."""
    stdin, stdout, stderr = client.exec_command("hostname")
    return stdout.read().decode().strip()


def check_server_change(client, last_server):
    """Check if connected to a different server than before and warn user.

    Returns the current server hostname.
    """
    current_server = get_remote_hostname(client)

    if last_server and current_server != last_server:
        print("\n[!] WARNING: Server changed!")
        print(f"    Previous server: {last_server}")
        print(f"    Current server:  {current_server}")
        print(
            f"[!] Your tmux sessions from '{last_server}' are NOT available on '{current_server}'."
        )
        print(f"[*] To access previous sessions, connect directly to: {last_server}")
        print()

    return current_server


def get_log_file(session_name, timestamp=None):
    """Get session-specific log file path with timestamp."""
    safe_name = session_name.replace("/", "_").replace(" ", "_")
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{LOG_DIR}/{safe_name}_{timestamp}.log"


def get_log_symlink(session_name):
    """Get path to the 'latest' symlink for a session."""
    safe_name = session_name.replace("/", "_").replace(" ", "_")
    return f"{LOG_DIR}/{safe_name}_latest.log"


def get_lock_file(session_name):
    """Get session-specific lock file path."""
    safe_name = session_name.replace("/", "_").replace(" ", "_")
    return f"{LOG_DIR}/{safe_name}.lock"


def find_existing_session(client):
    """Find an existing tmux session to use."""
    check_cmd = (
        f'sh -c \'T_SESS="{TMUX_SESSION}"; '
        f'if tmux has-session -t "$T_SESS" 2>/dev/null; then '
        f'  echo "$T_SESS"; '
        f"else "
        f'  DEF_S=$(tmux ls -F "#S" 2>/dev/null | head -n 1); '
        f'  if [ -n "$DEF_S" ]; then echo "$DEF_S"; fi; '
        f"fi'"
    )
    stdin, stdout, stderr = client.exec_command(check_cmd)
    return stdout.read().decode().strip()


def check_command_running(client, session_name):
    """Check if a command is currently running by checking lock file."""
    lock_file = get_lock_file(session_name)
    check_cmd = f"sh -c '[ -f \"{lock_file}\" ] && echo running || echo idle'"
    stdin, stdout, stderr = client.exec_command(check_cmd)
    result = stdout.read().decode().strip()
    return result == "running"


def list_running_sessions(hostname, username, last_server=None):
    """
    List all sessions with active lock files (running commands).

    Returns:
        (EXIT_COMPLETED (0): Success, current_server) or (EXIT_ERROR (1): Connection error, None)
    """
    password = get_credentials(hostname, username)

    try:
        print(f"[*] Connecting to {hostname} as {username}...")
        client = create_ssh_client(hostname, username, password)
        current_server = check_server_change(client, last_server)

        # Find all lock files and read their contents
        list_cmd = f'sh -c \'for f in {LOG_DIR}/*.lock 2>/dev/null; do if [ -f "$f" ]; then echo "=== $f ==="; cat "$f"; echo ""; fi; done\''
        stdin, stdout, stderr = client.exec_command(list_cmd)
        output = stdout.read().decode().strip()

        if not output:
            print("[*] No running commands found.")
        else:
            print("[*] Running commands:\n")
            print(output)

        update_timestamp()
        client.close()
        return EXIT_COMPLETED, current_server

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return EXIT_ERROR, None


def find_running_session_from_locks(client):
    """
    Find session name by scanning lock files.
    Returns session name if exactly one lock file exists, None otherwise.
    Also returns list of all sessions with locks.
    """
    # List all lock files
    list_cmd = f"sh -c 'ls {LOG_DIR}/*.lock 2>/dev/null'"
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


def get_session_cwd(client, session_name):
    """Get the current working directory of a tmux session."""
    # Get the pane's current path
    cmd = f"tmux display-message -t \"{session_name}\" -p '#{{pane_current_path}}' 2>/dev/null"
    stdin, stdout, stderr = client.exec_command(cmd)
    cwd = stdout.read().decode().strip()
    return cwd if cwd else None


def cleanup_sessions(hostname, username, last_server=None):
    """
    Clean up idle tmux sessions created by tmux-ssh (task_* sessions).
    Keeps the default remote_task session.

    Returns:
        (EXIT_COMPLETED (0): Success, current_server) or (EXIT_ERROR (1): Connection error, None)
    """
    password = get_credentials(hostname, username)

    try:
        print(f"[*] Connecting to {hostname} as {username}...")
        client = create_ssh_client(hostname, username, password)
        current_server = check_server_change(client, last_server)

        # Get list of all tmux sessions
        list_cmd = "tmux ls -F '#{session_name}' 2>/dev/null"
        stdin, stdout, stderr = client.exec_command(list_cmd)
        output = stdout.read().decode().strip()

        if not output:
            print("[*] No tmux sessions found.")
            client.close()
            return EXIT_COMPLETED, current_server

        sessions = output.split("\n")
        killed = []
        kept = []

        for session in sessions:
            # Skip the default session
            if session == TMUX_SESSION:
                kept.append(session)
                continue

            # Kill task_* sessions (created by --new)
            if session.startswith("task_"):
                # Check if it has an active lock file
                lock_file = get_lock_file(session)
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

        update_timestamp()
        client.close()
        return EXIT_COMPLETED, current_server

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return EXIT_ERROR, None


def attach_to_session(hostname, username, session_name=None, last_server=None):
    """
    Attach to an existing session and resume streaming its log output.

    Args:
        hostname: Remote host
        username: SSH username
        session_name: Session to attach to (default: auto-detect from lock files)
        last_server: Previously connected server (for change detection)

    Returns:
        (EXIT_COMPLETED (0): Command finished, current_server)
        (EXIT_ERROR (1): Connection or no session found, None)
        (EXIT_STILL_RUNNING (2): Timeout, command still running, current_server)
    """
    password = get_credentials(hostname, username)

    try:
        print(f"[*] Connecting to {hostname} as {username}...")
        client = create_ssh_client(hostname, username, password)
        current_server = check_server_change(client, last_server)

        # If no session specified, try to auto-detect from lock files
        if not session_name:
            auto_session, all_sessions = find_running_session_from_locks(client)

            if not all_sessions:
                print("[!] No running commands found (no lock files).")
                client.close()
                return EXIT_ERROR, None

            if len(all_sessions) == 1:
                session_name = auto_session
                print(f"[*] Auto-detected session: {session_name}")
            else:
                print(f"[!] Multiple running sessions found: {', '.join(all_sessions)}")
                print(
                    "[*] Please specify a session with: tmux-ssh --attach <session_name>"
                )
                print("[*] Or use 'tmux-ssh --list' to see details.")
                client.close()
                return EXIT_ERROR, None

        print(f"[*] Attaching to session: {session_name}")

        # Check if command is running
        if not check_command_running(client, session_name):
            print(f"[!] No command currently running in session '{session_name}'.")
            # Show the latest log file
            log_symlink = get_log_symlink(session_name)
            print(f"[*] You can view the latest log at: {log_symlink}")
            client.close()
            return EXIT_COMPLETED, current_server

        # Get the log file from lock file
        lock_file = get_lock_file(session_name)
        get_log_cmd = f'sh -c \'if [ -f "{lock_file}" ]; then cat "{lock_file}"; fi\''
        stdin, stdout, stderr = client.exec_command(get_log_cmd)
        lock_info = stdout.read().decode().strip()
        print(f"[*] Lock file info:\n{lock_info}\n")

        # Stream from the latest symlink
        log_symlink = get_log_symlink(session_name)
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

        while not command_completed:
            try:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="replace")
                    if chunk:
                        last_output_time = time.time()
                        buffer += chunk

                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)

                            if START_MARKER in line:
                                started = True
                                continue

                            if END_MARKER in line:
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
                    if not check_command_running(client, session_name):
                        print("\n[*] Command appears to have completed.")
                        command_completed = True
                        break
                    last_output_time = time.time()  # Reset to avoid repeated checks

            except Exception:
                time.sleep(0.1)

        print("\n[+] Command completed.")
        update_timestamp()
        client.close()
        return EXIT_COMPLETED, current_server

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return EXIT_ERROR, None


def execute_remote_cmd(
    hostname,
    username,
    command,
    timeout=None,
    idle_timeout=3600,
    new_session=False,
    force=False,
    last_server=None,
):
    """
    Execute a command in tmux and stream output in real-time.

    Args:
        hostname: Remote host
        username: SSH username
        command: Command to execute
        timeout: Max seconds to stream (None = unlimited)
        idle_timeout: Exit if no output for N seconds (default: 3600)
        new_session: Create a new unique session
        force: Force execution even if command is running
        last_server: Previously connected server (for change detection)

    Returns:
        (EXIT_COMPLETED (0): Command finished, current_server)
        (EXIT_ERROR (1): Connection or execution error, None)
        (EXIT_STILL_RUNNING (2): Timeout/idle-timeout, current_server)
        (EXIT_BLOCKED (3): Blocked due to running command, None)
    """
    password = get_credentials(hostname, username)

    try:
        print(f"[*] Connecting to {hostname} as {username}...")
        client = create_ssh_client(hostname, username, password)
        current_server = check_server_change(client, last_server)

        # Determine session name
        if new_session:
            session_name = f"task_{uuid.uuid4().hex[:8]}"
            print(f"[*] Creating new session: {session_name}")
        else:
            session_name = find_existing_session(client)
            if not session_name:
                session_name = TMUX_SESSION
            print(f"[*] Using existing session: {session_name}")

            # Check if command is already running in this session
            if not force and check_command_running(client, session_name):
                print(f"\n[!] Command already running in session '{session_name}'.")
                print("[*] Options:")
                print("    --new   : Run in a new session (safe concurrency)")
                print("    --force : Override and kill existing command")
                client.close()
                return EXIT_BLOCKED, None

        log_file = get_log_file(session_name)
        log_symlink = get_log_symlink(session_name)
        lock_file = get_lock_file(session_name)

        # Escape quotes for nested shell quoting
        safe_cmd = command.replace("'", "'\\''")
        safe_cmd = safe_cmd.replace('"', '\\"')

        # Build dispatch command with lock file for running detection
        # Creates log directory, timestamped log file, and symlink to latest
        if new_session:
            # Get current directory from default session to inherit
            default_cwd = get_session_cwd(client, TMUX_SESSION)
            cd_cmd = f'cd \\"{default_cwd}\\" 2>/dev/null; ' if default_cwd else ""

            # Create new session - NO exec /bin/bash so it auto-kills when done
            dispatch_cmd = (
                f"sh -c '"
                f"mkdir -p {LOG_DIR}; "
                f'touch "{log_file}"; '
                f'ln -sf "{log_file}" "{log_symlink}"; '
                f'echo "cmd: {safe_cmd}" > "{lock_file}"; '
                f'echo "started: $(date)" >> "{lock_file}"; '
                f'echo "session: {session_name}" >> "{lock_file}"; '
                f'echo "log: {log_file}" >> "{lock_file}"; '
                f'tmux new-session -d -s "{session_name}" '
                f'"/bin/bash -l -c \\"{cd_cmd}echo {START_MARKER} >> {log_file}; ( {safe_cmd} ) 2>&1 | tee -a {log_file}; echo {END_MARKER} >> {log_file}; rm -f {lock_file}\\""; '
                f'echo "{session_name}"\''
            )
            if default_cwd:
                print(f"[*] Inheriting directory from {TMUX_SESSION}: {default_cwd}")
        else:
            # Use existing session - keep alive with exec /bin/bash for default session
            force_cleanup = (
                f'rm -f "{lock_file}"; tmux send-keys -t "{session_name}" C-c; sleep 0.3; '
                if force
                else ""
            )
            dispatch_cmd = (
                f"sh -c '"
                f"mkdir -p {LOG_DIR}; "
                f'touch "{log_file}"; '
                f'ln -sf "{log_file}" "{log_symlink}"; '
                f'echo "cmd: {safe_cmd}" > "{lock_file}"; '
                f'echo "started: $(date)" >> "{lock_file}"; '
                f'echo "session: {session_name}" >> "{lock_file}"; '
                f'echo "log: {log_file}" >> "{lock_file}"; '
                f'if tmux has-session -t "{session_name}" 2>/dev/null; then '
                f"  {force_cleanup}"
                f'  tmux send-keys -t "{session_name}" "/bin/bash -l -c \\"echo {START_MARKER} >> {log_file}; ( {safe_cmd} ) 2>&1 | tee -a {log_file}; echo {END_MARKER} >> {log_file}; rm -f {lock_file}\\"" ENTER; '
                f"else "
                f'  tmux new-session -d -s "{session_name}" '
                f'"/bin/bash -l -c \\"echo {START_MARKER} >> {log_file}; ( {safe_cmd} ) 2>&1 | tee -a {log_file}; echo {END_MARKER} >> {log_file}; rm -f {lock_file}; exec /bin/bash\\""; '
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

        # Wait for tmux to start executing the command
        time.sleep(0.5)

        print("[*] Streaming output:\n")

        # Stream output using tail -f on the symlink (read from beginning with -n +1)
        tail_cmd = f'tail -n +1 -f "{log_symlink}"'
        stdin, stdout, stderr = client.exec_command(tail_cmd)

        # Set channel to non-blocking
        channel = stdout.channel
        channel.setblocking(0)

        start_time = time.time()
        last_output_time = time.time()
        buffer = ""
        command_completed = False
        started = False  # Track if we've seen START_MARKER

        while not command_completed:
            try:
                # Check if data is available (non-blocking)
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="replace")
                    if chunk:
                        last_output_time = time.time()
                        buffer += chunk

                        # Process complete lines
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)

                            # Wait for START_MARKER before showing output
                            if START_MARKER in line:
                                started = True
                                continue

                            # Check for END_MARKER
                            if END_MARKER in line:
                                command_completed = True
                                break

                            # Only print lines after we've seen START_MARKER
                            if started:
                                print(line)
                                sys.stdout.flush()
                else:
                    # No data available, sleep briefly
                    time.sleep(0.1)

                # Check timeouts
                elapsed = time.time() - start_time
                idle_time = time.time() - last_output_time

                if timeout and elapsed > timeout:
                    print(
                        f"\n[*] Timeout ({timeout}s) reached. Command still running in tmux."
                    )
                    print("[*] Use 'tmux-ssh --attach' to resume streaming the output.")
                    print(f"[*] Log file: {log_file}")
                    update_timestamp()
                    client.close()
                    return EXIT_STILL_RUNNING, current_server

                if idle_time > idle_timeout:
                    print(
                        f"\n[*] Idle timeout ({idle_timeout}s) reached. Command still running in tmux."
                    )
                    print("[*] Use 'tmux-ssh --attach' to resume streaming the output.")
                    print(f"[*] Log file: {log_file}")
                    update_timestamp()
                    client.close()
                    return EXIT_STILL_RUNNING, current_server

            except Exception:
                time.sleep(0.1)

        print("\n[+] Command completed.")
        update_timestamp()
        client.close()
        return EXIT_COMPLETED, current_server

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return EXIT_ERROR, None


if __name__ == "__main__":
    saved = load_saved_config()

    parser = argparse.ArgumentParser(
        description="Run remote commands in a tmux session via SSH (batch mode)."
    )
    parser.add_argument("-H", "--host", default=None, help="Remote hostname")
    parser.add_argument("-U", "--user", default=None, help="Remote username")
    parser.add_argument(
        "-C", "--clear", action="store_true", help="Clear stored credentials"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Max seconds to stream output (default: unlimited)",
    )
    parser.add_argument(
        "-i",
        "--idle-timeout",
        type=int,
        default=3600,
        help="Exit if no output for N seconds (default: 3600)",
    )
    parser.add_argument(
        "-n",
        "--new",
        action="store_true",
        help="Create a new unique tmux session (for concurrent commands)",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force execution, kill any running command in session",
    )
    parser.add_argument(
        "-a",
        "--attach",
        nargs="?",
        const="",
        default=None,
        metavar="SESSION",
        help="Attach to session and resume streaming (auto-detect if no session specified)",
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List all running commands/sessions"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up idle task_* sessions (keeps remote_task)",
    )
    parser.add_argument("command", nargs="*", help="The command to execute remotely")

    args = parser.parse_args()

    # Resolve host: CLI arg > saved config > prompt
    host = args.host or saved.get("host")
    if not host:
        host = input("[?] Enter remote hostname: ").strip()
        if not host:
            print("[!] Hostname is required.")
            sys.exit(EXIT_ERROR)

    # Resolve user: CLI arg > saved config > prompt
    user = args.user or saved.get("user")
    if not user:
        user = input("[?] Enter remote username: ").strip()
        if not user:
            print("[!] Username is required.")
            sys.exit(EXIT_ERROR)

    # Save for future use (preserve last_server until we connect)
    last_server = saved.get("last_server")
    save_config(host, user, last_server)

    if args.clear:
        clear_credentials(host, user)
        sys.exit(EXIT_COMPLETED)

    if args.list:
        exit_code, current_server = list_running_sessions(host, user, last_server)
        if current_server:
            save_config(host, user, current_server)
        sys.exit(exit_code)

    if args.cleanup:
        exit_code, current_server = cleanup_sessions(host, user, last_server)
        if current_server:
            save_config(host, user, current_server)
        sys.exit(exit_code)

    if args.attach is not None:
        # args.attach is "" if --attach with no value, or the session name if provided
        session = args.attach if args.attach else None
        exit_code, current_server = attach_to_session(host, user, session, last_server)
        if current_server:
            save_config(host, user, current_server)
        sys.exit(exit_code)

    user_cmd = " ".join(args.command)
    if not user_cmd:
        user_cmd = input("[?] Enter the command to run on server: ")

    exit_code, current_server = execute_remote_cmd(
        host,
        user,
        user_cmd,
        timeout=args.timeout,
        idle_timeout=args.idle_timeout,
        new_session=args.new,
        force=args.force,
        last_server=last_server,
    )
    if current_server:
        save_config(host, user, current_server)
    sys.exit(exit_code)
