"""Type definitions for mcptrust-core."""

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class LogConfig:
    """Structured logging config."""
    format: Literal["pretty", "jsonl"] = "pretty"
    level: Literal["debug", "info", "warn", "error"] = "info"
    output: str = "stderr"


@dataclass
class ReceiptConfig:
    """Receipt artifact config."""
    path: str
    mode: Literal["overwrite", "append"] = "overwrite"


@dataclass
class LockResult:
    """lock command result."""
    lockfile_path: str
    stdout: str
    stderr: str


@dataclass
class CheckResult:
    """check command result."""
    passed: bool
    diff_stdout: str = ""
    diff_stderr: str = ""
    policy_stdout: str = ""
    policy_stderr: str = ""


@dataclass
class RunResult:
    """run command result."""
    exit_code: int
    stdout: str = ""
    stderr: str = ""
