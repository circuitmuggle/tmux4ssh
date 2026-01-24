# Prototype Files

This directory contains early prototype versions of the tmux-ssh tool before it was refactored into a proper Python package.

## Usage

```bash
python3 tmux_ssh.py [arguments]
```

## Test Scripts

### datetime_loop.py

A utility script to test the stability of remote server connections. It outputs a datetime tag every 60 minutes, useful for verifying that:

- tmux-ssh sessions remain active during long-running tasks
- The connection can survive network interruptions
- The idle timeout behavior works as expected

**Usage:**
```bash
# Run on remote server via tmux-ssh
tmux-ssh "python3 datetime_loop.py"

# Or copy to server and run directly
scp prototype/datetime_loop.py user@host:~/
tmux-ssh "python3 ~/datetime_loop.py"
```

**Output:**
```
Starting datetime monitoring loop...
Output interval: 60 minutes
--------------------------------------------------
[Iteration 1] 2026-01-24 10:00:00 PST
[Iteration 2] 2026-01-24 11:00:00 PST
...
```

## Note

These files are kept for reference only. For the current implementation, use the packaged version:

```bash
pip install -e .
tmux-ssh [arguments]
```
