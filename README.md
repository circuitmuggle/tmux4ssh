# tmux-ssh

Execute remote commands via SSH in tmux sessions with real-time output streaming and batch mode.

## Features

- **Real-time output streaming** - See command output as it happens
- **Tmux-based execution** - Commands run in persistent tmux sessions
- **Concurrent execution** - Run multiple commands in parallel with `--new`
- **Directory inheritance** - `--new` sessions inherit current directory from default session
- **Auto-cleanup** - `--new` sessions automatically terminate when commands complete
- **Running command detection** - Prevents accidental command conflicts
- **Session management** - List running commands, attach/reattach to sessions, cleanup idle sessions
- **Permanent log storage** - Timestamped logs preserved in `~/tmux_ssh_logs/`
- **Credential management** - Securely stores SSH credentials in system keyring
- **Timeout support** - Configurable idle (default: 1 hour) and total timeouts
- **Server change detection** - Warns when load-balanced hostname resolves to different server

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
pip uninstall tmux-ssh
```

## Usage

### Basic Commands

```bash
# Run a command on remote server
tmux-ssh "hostname"

# Run with custom host/user
tmux-ssh -H myserver.com -U myuser "ls -la"

# Set idle timeout (exit if no output for N seconds, default: 3600)
tmux-ssh -i 7200 "long_running_command"

# Set total timeout
tmux-ssh -t 3600 -i 1800 "very_long_command"
```

### Concurrent Execution

```bash
# Run in a new unique session (safe for concurrent execution)
# Inherits current directory from remote_task session
# Auto-terminates when command completes
tmux-ssh --new "command1"
tmux-ssh --new "command2"  # Runs in parallel

# Force execution (kills any running command)
tmux-ssh --force "command"
```

### Session Management

```bash
# List all running commands/sessions
tmux-ssh --list

# Attach to a running session (auto-detect if only one)
tmux-ssh --attach

# Attach to a specific session
tmux-ssh --attach task_a1b2c3d4

# Clean up idle task_* sessions (keeps remote_task)
tmux-ssh --cleanup
```

When a command times out, you can resume streaming its output:
```bash
# After timeout message:
# [*] Idle timeout (3600s) reached. Command still running in tmux.
# [*] Use 'tmux-ssh --attach' to resume streaming the output.

tmux-ssh --attach
```

### Load-Balanced Hostnames

If your hostname resolves to multiple backend servers (DNS round-robin or load balancer), tmux-ssh will warn you when you connect to a different server than before:

```
[!] WARNING: Server changed!
    Previous server: ees-lin32.ecs.apple.com
    Current server:  ees-lin24.ecs.apple.com
[!] Your tmux sessions from 'ees-lin32.ecs.apple.com' are NOT available on 'ees-lin24.ecs.apple.com'.
[*] To access previous sessions, connect directly to: ees-lin32.ecs.apple.com
```

**Recommendation**: For consistent tmux session access, use specific server hostnames instead of load-balanced hostnames:
```bash
# Instead of this (may connect to different servers):
tmux-ssh -H cluster.example.com "command"

# Use this (always same server):
tmux-ssh -H node01.cluster.example.com "command"
```

### Credential Management

```bash
# Clear stored credentials
tmux-ssh --clear
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
| `-t, --timeout` | Max seconds to stream (default: unlimited) |
| `-i, --idle-timeout` | Exit if no output for N seconds (default: 3600) |
| `-n, --new` | Create a new unique tmux session (inherits cwd, auto-terminates) |
| `-f, --force` | Force execution, kill any running command |
| `-a, --attach [SESSION]` | Attach to session (auto-detect if not specified) |
| `-l, --list` | List all running commands/sessions |
| `--cleanup` | Clean up idle task_* sessions (keeps remote_task) |
| `-C, --clear` | Clear stored credentials |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command completed successfully |
| 1 | Connection or execution error |
| 2 | Timeout reached, command still running |
| 3 | Blocked by running command |

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

MIT
