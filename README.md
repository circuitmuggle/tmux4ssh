# tmux4ssh

Execute remote commands via SSH in tmux sessions with real-time output streaming and batch mode.

The purpose of this project is to facilitate long-running simulations, such as Spectre, on a remote Linux server under unstable internet connections, when the user does not have root access to the server and relies on specialized CAD software such as Cadence Spectre.

## Features

- **Real-time output streaming** - See command output as it happens
- **Tmux-based execution** - Commands run in persistent tmux sessions
- **Concurrent execution** - Run multiple commands in parallel with `--new`
- **Auto-new session** - Automatically creates new session if command already running (default: on)
- **Directory inheritance** - `--new` sessions inherit current directory from default session
- **Auto-cleanup** - `--new` sessions automatically terminate when commands complete
- **Running command detection** - Prevents accidental command conflicts
- **Session management** - List running commands, attach/reattach to sessions, cleanup idle sessions
- **Permanent log storage** - Timestamped logs preserved in `~/tmux_ssh_logs/`
- **Credential management** - Securely stores SSH credentials in system keyring
- **Timeout support** - Configurable idle (default: 1 hour) and total timeouts
- **Server change detection** - Warns when load-balanced hostname resolves to different server

## Why tmux4ssh?

Standard SSH has limitations for long-running or critical remote tasks:

| Scenario | Standard SSH | tmux4ssh |
|----------|--------------|----------|
| Internet drops mid-command | Command killed (SIGHUP) | Command keeps running in tmux |
| Check progress after disconnect | Not possible | `tmux4ssh --attach` |
| Run concurrent commands | Manual session management | `tmux4ssh --new` |
| Stream output to local terminal | Works, but lost on disconnect | Persistent logs + reattach |

**The manual workaround** without tmux4ssh:
```bash
ssh -t user@host           # Interactive login
tmux new -s mysession      # Create tmux session
./long_running_script.sh   # Run command
# Ctrl+B, D to detach
# ... later, after reconnecting ...
ssh -t user@host
tmux attach -t mysession   # Hope you remember the session name
```

**With tmux4ssh:**
```bash
tmux4ssh "./long_running_script.sh"   # Just run it
# ... connection drops, reconnect later ...
tmux4ssh --attach                      # Resume output streaming
```

## Installation

### Option 1: Install as Package (Recommended)

```bash
# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

**Requirements:** Python 3.10 or higher

### Option 2: Use Prototype Without Installation

If you want to test without installing the package, use the standalone prototype script:

```bash
# Navigate to prototype directory
cd prototype

# Run directly with Python
python3 tmux_ssh.py -H myserver.com -U myuser "hostname"
```

See `prototype/README.md` for more details.

### Uninstall

```bash
pip uninstall tmux4ssh
```

## Usage

### Basic Commands

```bash
# SSH-compatible syntax (recommended)
tmux4ssh user@host "command"
tmux4ssh user@host:2222 "command"       # With custom port
tmux4ssh host "command"                  # Uses saved username

# Flag-based syntax (also supported)
tmux4ssh -H myserver.com -U myuser "hostname"
tmux4ssh -p 2222 -H myserver.com -U myuser "hostname"

# Subsequent runs: host/user are remembered automatically
tmux4ssh "ls -la"
tmux4ssh "pwd"

# Override saved settings when needed
tmux4ssh -H otherserver.com "hostname"

# Set idle timeout (exit if no output for N seconds, default: 3600)
tmux4ssh -i 7200 "long_running_command"

# Set total timeout
tmux4ssh -t 3600 -i 1800 "very_long_command"
```

### Command Quoting

**When are quotes required?** Use quotes when your command contains:

- **Shell operators**: `&&`, `||`, `;`, `|`, `>`, `<`, `>>`, `2>&1`
- **Variable expansion**: `$VAR`, `$(command)`, backticks
- **Wildcards**: `*`, `?`, `[...]`
- **Spaces in arguments**: paths or strings with spaces

```bash
# REQUIRED: Commands with shell operators
tmux4ssh user@host "cmd1 && cmd2"              # Chain commands
tmux4ssh user@host "cmd1 || cmd2"              # OR operator
tmux4ssh user@host "cmd1; cmd2"                # Sequential
tmux4ssh user@host "cat file | grep pattern"   # Pipe
tmux4ssh user@host "echo hello > output.txt"   # Redirect

# REQUIRED: Commands with special characters
tmux4ssh user@host 'echo $HOME'                # Preserve $HOME for remote
tmux4ssh user@host "ls *.txt"                  # Wildcards
tmux4ssh user@host "cd '/path with spaces'"    # Paths with spaces

# OPTIONAL: Simple commands (quotes work but optional)
tmux4ssh user@host hostname                    # Single word - OK
tmux4ssh user@host "hostname"                  # Also OK
tmux4ssh user@host ls -la /tmp                 # May fail (see note below)
tmux4ssh user@host "ls -la /tmp"               # Safer with quotes
```

**Note on flags starting with `-`**: Arguments like `-la` may be interpreted as tmux4ssh flags. Always quote commands with such arguments:

```bash
# Problematic: -la might be parsed as a flag
tmux4ssh user@host ls -la

# Safe: Quote the entire command
tmux4ssh user@host "ls -la"
```

**Best practice**: Always quote your command string to avoid surprises.

### Saved Settings

tmux4ssh automatically saves your connection settings to `~/.tmux_ssh_config`:

- **Host** (`-H`): Remote hostname
- **User** (`-U`): SSH username
- **Port** (`-p`): SSH port (default: 22)
- **Last server**: Actual server hostname (for load-balancer detection)
- **Auto-new setting**: Whether to auto-create sessions

This means you only need to specify connection details once. All subsequent commands will use the saved settings automatically.

### Concurrent Execution

By default, tmux4ssh automatically creates a new session when you run a command while another is already running:

```bash
# First command runs in default session
tmux4ssh "command1"

# Second command auto-creates new session for concurrent execution
tmux4ssh "command2"
# Output: [*] Session 'remote_task' is busy, creating 'task_a1b2c3d4' for concurrent execution...
```

You can also explicitly control this behavior:

```bash
# Explicitly create new session (always creates fresh session)
tmux4ssh --new "command"

# Disable auto-new, block if session is busy
tmux4ssh --no-auto "command"

# Force execution (kills any running command in session)
tmux4ssh --force "command"
```

### Session Management

```bash
# List all running commands/sessions
tmux4ssh --list

# Attach to a running session (auto-detect if only one)
tmux4ssh --attach

# Attach to a specific session
tmux4ssh --attach task_a1b2c3d4

# Clean up idle task_* sessions (keeps remote_task)
tmux4ssh --cleanup
```

When a command times out, you can resume streaming its output:
```bash
# After timeout message:
# [*] Idle timeout (3600s) reached. Command still running in tmux.
# [*] Use 'tmux4ssh --attach' to resume streaming the output.

tmux4ssh --attach
```

### Load-Balanced Hostnames

If your hostname resolves to multiple backend servers (DNS round-robin or load balancer), tmux4ssh will warn you when you connect to a different server than before:

```
[!] WARNING: Server changed!
    Previous server: node01.cluster.example.com
    Current server:  node02.cluster.example.com
[!] Your tmux sessions from 'node01.cluster.example.com' are NOT available on 'node02.cluster.example.com'.
[*] To access previous sessions, connect directly to: node01.cluster.example.com
```

**Recommendation**: For consistent tmux session access, use specific server hostnames instead of load-balanced hostnames:
```bash
# Instead of this (may connect to different servers):
tmux4ssh -H cluster.example.com "command"

# Use this (always same server):
tmux4ssh -H node01.cluster.example.com "command"
```

### Credential Management

```bash
# Clear stored credentials
tmux4ssh --clear
```

**Tip: SSH Key Authentication**

Setting up SSH keys eliminates password prompts for every command:

```bash
# Generate key (if you don't have one)
ssh-keygen -t ed25519

# Copy public key to remote server
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@hostname
```

After setup, SSH/SCP commands authenticate automatically without passwords.

**Tip: File Transfer with SCP**

Copy files between local and remote servers:

```bash
# Remote to local
scp user@hostname:/remote/path/file.txt .

# Local to remote
scp file.txt user@hostname:/remote/path/

# Copy directory recursively
scp -r user@hostname:/remote/folder ./local/
```

## Log Files

Logs are stored on the remote server in `~/tmux_ssh_logs/`:

```
~/tmux_ssh_logs/
├── remote_task_20260120_100000.log      # Timestamped log
├── remote_task_20260120_143022.log      # Another run
├── remote_task_latest.log               # Symlink to latest
├── remote_task.lock                     # Lock file (while running)
└── task_a1b2c3d4_20260120_110000.log    # Log from --new session
```

The lock file contains information about the running command:
```
cmd: spectre simulation.scs
started: Mon Jan 20 10:00:00 UTC 2026
session: remote_task
log: ~/tmux_ssh_logs/remote_task_20260120_100000.log
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-H, --host` | Remote hostname |
| `-U, --user` | Remote username |
| `-p, --port` | SSH port (default: 22) |
| `-t, --timeout` | Max seconds to stream (default: unlimited) |
| `-i, --idle-timeout` | Exit if no output for N seconds (default: 3600) |
| `-n, --new` | Create a new unique tmux session (inherits cwd, auto-terminates) |
| `-f, --force` | Force execution, kill any running command |
| `-k, --kill [SESSION]` | Kill running command (auto-detect if not specified) |
| `-y, --yes` | Skip confirmation prompt (for --kill) |
| `-a, --attach [SESSION]` | Attach to session (auto-detect if not specified) |
| `-l, --list` | List all running commands/sessions |
| `--cleanup` | Clean up idle task_* sessions (keeps remote_task) |
| `--auto` | Auto-create new session if command already running (default: true) |
| `--no-auto` | Disable auto-create, block if command already running |
| `-C, --clear` | Clear stored credentials |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command completed successfully |
| 1 | Connection or execution error |
| 2 | Timeout reached, command still running |
| 3 | Blocked by running command |

## FAQ

### Will closing my laptop or losing internet kill my remote task?

**No.** Your remote command continues running safely in the tmux session on the server.

```
┌─────────────────┐         ┌─────────────────────────────────────┐
│  Your Laptop    │   SSH   │        Remote Server                │
│                 │ ──────► │                                     │
│  tmux4ssh       │         │   tmux session (remote_task)        │
│  (streaming     │ ◄────── │     └── your command running        │
│   output only)  │  tail   │     └── output → log file           │
└─────────────────┘         └─────────────────────────────────────┘
```

When you close your laptop or lose connection:
1. The SSH connection drops
2. The local `tmux4ssh` process terminates
3. **The remote command keeps running** inside the tmux session
4. Output continues to be written to the log file

When you reconnect later, use `tmux4ssh --attach` to resume streaming.

### What happens if I press Ctrl+C locally?

**Ctrl+C only stops the local streaming process.** The remote command continues running.

This is safe and expected behavior — you can press Ctrl+C anytime to stop watching the output without affecting the remote task. To resume streaming later:

```bash
tmux4ssh --attach
```

### How do I actually terminate a running remote command?

Use the `--kill` option:

```bash
# Kill command in auto-detected session
tmux4ssh --kill

# Kill command in a specific session
tmux4ssh --kill task_a1b2c3d4
```

Alternative options:

```bash
# Use --force to kill and run a new command
tmux4ssh --force "new_command"

# SSH directly and kill the process
ssh user@host
pkill -f "your_command_pattern"

# SSH directly and attach to tmux, then Ctrl+C
ssh user@host
tmux attach -t remote_task
# Now Ctrl+C will kill the command inside tmux
```

## Development

### Running Tests

```bash
# Run all tests (unit tests only by default)
pytest

# Run unit tests only
pytest -m unit

# Run integration tests (requires live SSH connection)
pytest -m integration

# Run with coverage report
pytest --cov=tmux_ssh --cov-report=html
```

### Code Quality

```bash
# Run linter
ruff check src tests

# Run type checker
mypy src tests

# Run all pre-commit hooks
pre-commit run --all-files
```

## Project Structure

```
tmux_ssh/
├── src/
│   └── tmux_ssh/
│       ├── __init__.py
│       ├── client.py      # Main TmuxSSHClient class
│       └── cli.py         # Command-line interface
├── tests/
│   ├── conftest.py        # Test fixtures
│   ├── test_unit.py       # Unit tests (mocked)
│   └── test_integration.py # Integration tests (live SSH)
├── pyproject.toml
├── .pre-commit-config.yaml
└── README.md
```

## License

Apache 2.0

---

*Spectre® is a registered trademark of Cadence Design Systems, Inc. All other trademarks are the property of their respective owners.*
