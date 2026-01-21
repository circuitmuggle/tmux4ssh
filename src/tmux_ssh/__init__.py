"""tmux_ssh - Execute remote commands via SSH in tmux sessions."""

from tmux_ssh.client import (
    EXIT_BLOCKED,
    EXIT_COMPLETED,
    EXIT_ERROR,
    EXIT_STILL_RUNNING,
    TmuxSSHClient,
)

__version__ = "0.1.0"
__all__ = [
    "TmuxSSHClient",
    "EXIT_COMPLETED",
    "EXIT_ERROR",
    "EXIT_STILL_RUNNING",
    "EXIT_BLOCKED",
]
