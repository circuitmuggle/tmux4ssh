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


def save_config(host, user):
    """Save host/user to config file for future use."""
    config = {"host": host, "user": user}
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


def get_log_file(session_name):
    """Get session-specific log file path."""
    # Sanitize session name for use in filename
    safe_name = session_name.replace("/", "_").replace(" ", "_")
    return f"/tmp/cmd_output_{safe_name}.log"


def get_lock_file(session_name):
    """Get session-specific lock file path."""
    safe_name = session_name.replace("/", "_").replace(" ", "_")
    return f"/tmp/cmd_running_{safe_name}.lock"


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


def execute_remote_cmd(
    hostname,
    username,
    command,
    timeout=None,
    idle_timeout=300,
    new_session=False,
    force=False,
):
    """
    Execute a command in tmux and stream output in real-time.

    Args:
        hostname: Remote host
        username: SSH username
        command: Command to execute
        timeout: Max seconds to stream (None = unlimited)
        idle_timeout: Exit if no output for N seconds
        new_session: Create a new unique session
        force: Force execution even if command is running

    Returns:
        EXIT_COMPLETED (0): Command finished (END_MARKER seen)
        EXIT_ERROR (1): Connection or execution error
        EXIT_STILL_RUNNING (2): Timeout/idle-timeout, command still running in tmux
        EXIT_BLOCKED (3): Blocked due to running command (use --force or --new)
    """
    password = get_credentials(hostname, username)

    try:
        print(f"[*] Connecting to {hostname} as {username}...")
        client = create_ssh_client(hostname, username, password)

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
                return EXIT_BLOCKED

        log_file = get_log_file(session_name)
        lock_file = get_lock_file(session_name)

        # Escape quotes for nested shell quoting
        safe_cmd = command.replace("'", "'\\''")
        safe_cmd = safe_cmd.replace('"', '\\"')

        # Build dispatch command with lock file for running detection
        if new_session:
            # Create new session
            dispatch_cmd = (
                f"sh -c '"
                f'rm -f "{log_file}"; '
                f'touch "{log_file}" "{lock_file}"; '
                f'tmux new-session -d -s "{session_name}" '
                f'"/bin/bash -l -c \\"echo {START_MARKER} >> {log_file}; ( {safe_cmd} ) 2>&1 | tee -a {log_file}; echo {END_MARKER} >> {log_file}; rm -f {lock_file}; exec /bin/bash\\""; '
                f'echo "{session_name}"\''
            )
        else:
            # Use existing session
            force_cleanup = (
                f'rm -f "{lock_file}"; tmux send-keys -t "{session_name}" C-c; sleep 0.3; '
                if force
                else ""
            )
            dispatch_cmd = (
                f"sh -c '"
                f'rm -f "{log_file}"; '
                f'touch "{log_file}" "{lock_file}"; '
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

        # Wait for tmux to start executing the command
        time.sleep(0.5)

        print("[*] Streaming output:\n")

        # Stream output using tail -f (read from beginning with -n +1)
        tail_cmd = f'tail -n +1 -f "{log_file}"'
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
                    update_timestamp()
                    client.close()
                    return EXIT_STILL_RUNNING

                if idle_time > idle_timeout:
                    print(
                        f"\n[*] Idle timeout ({idle_timeout}s) reached. Command still running in tmux."
                    )
                    update_timestamp()
                    client.close()
                    return EXIT_STILL_RUNNING

            except Exception:
                time.sleep(0.1)

        print("\n[+] Command completed.")
        update_timestamp()
        client.close()
        return EXIT_COMPLETED

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run remote commands in a tmux session via SSH (batch mode)."
    )
    parser.add_argument(
        "-H", "--host", default=DEFAULT_SSH_HOST, help="Remote hostname"
    )
    parser.add_argument(
        "-U", "--user", default=DEFAULT_SSH_USER, help="Remote username"
    )
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
        default=300,
        help="Exit if no output for N seconds (default: 300)",
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
    parser.add_argument("command", nargs="*", help="The command to execute remotely")

    args = parser.parse_args()

    if args.clear:
        clear_credentials(args.host, args.user)
        sys.exit(EXIT_COMPLETED)

    user_cmd = " ".join(args.command)
    if not user_cmd:
        user_cmd = input("[?] Enter the command to run on server: ")

    exit_code = execute_remote_cmd(
        args.host,
        args.user,
        user_cmd,
        timeout=args.timeout,
        idle_timeout=args.idle_timeout,
        new_session=args.new,
        force=args.force,
    )
    sys.exit(exit_code)
