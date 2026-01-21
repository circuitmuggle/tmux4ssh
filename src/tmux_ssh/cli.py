"""Command-line interface for tmux_ssh."""

from __future__ import annotations

import argparse
import json
import os
import sys

from tmux_ssh.client import (
    EXIT_COMPLETED,
    Config,
    TmuxSSHClient,
)

# Config file for persisting host/user
CONFIG_FILE = os.path.expanduser("~/.tmux_ssh_config")


def load_saved_config() -> dict[str, str]:
    """Load saved host/user from config file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(host: str, user: str, last_server: str | None = None) -> None:
    """Save host/user/last_server to config file for future use."""
    config: dict[str, str] = {"host": host, "user": user}
    if last_server:
        config["last_server"] = last_server
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f)
    except OSError:
        pass  # Silently fail if we can't write


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
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
        "-l",
        "--list",
        action="store_true",
        help="List all running commands/sessions",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up idle task_* sessions (keeps remote_task)",
    )
    parser.add_argument("command", nargs="*", help="The command to execute remotely")

    parsed_args = parser.parse_args(args)

    # Resolve host: CLI arg > saved config > prompt
    host = parsed_args.host or saved.get("host")
    if not host:
        host = input("[?] Enter remote hostname: ").strip()
        if not host:
            print("[!] Hostname is required.")
            return 1

    # Resolve user: CLI arg > saved config > prompt
    user = parsed_args.user or saved.get("user")
    if not user:
        user = input("[?] Enter remote username: ").strip()
        if not user:
            print("[!] Username is required.")
            return 1

    # Save for future use (without last_server yet, will update after connection)
    save_config(host, user, saved.get("last_server"))

    config = Config(hostname=host, username=user)
    last_server = saved.get("last_server")
    client = TmuxSSHClient(config, last_server=last_server)

    if parsed_args.clear:
        client.clear_credentials()
        return EXIT_COMPLETED

    if parsed_args.list:
        result = client.list_running()
        # Save current server for next time
        if client.current_server:
            save_config(host, user, client.current_server)
        return result

    if parsed_args.cleanup:
        result = client.cleanup()
        if client.current_server:
            save_config(host, user, client.current_server)
        return result

    if parsed_args.attach is not None:
        # parsed_args.attach is "" if --attach with no value, or the session name
        session = parsed_args.attach if parsed_args.attach else None
        result = client.attach(session)
        if client.current_server:
            save_config(host, user, client.current_server)
        return result

    user_cmd = " ".join(parsed_args.command)
    if not user_cmd:
        user_cmd = input("[?] Enter the command to run on server: ").strip()

    result = client.execute(
        user_cmd,
        timeout=parsed_args.timeout,
        idle_timeout=parsed_args.idle_timeout,
        new_session=parsed_args.new,
        force=parsed_args.force,
    )
    if client.current_server:
        save_config(host, user, client.current_server)
    return result


if __name__ == "__main__":
    sys.exit(main())
