"""Exception classes for mcptrust-core."""


class MCPTrustError(Exception):
    """Base exception for all mcptrust-core errors."""
    pass


class MCPTrustNotInstalled(MCPTrustError):
    """Raised when mcptrust binary missing."""
    
    def __init__(self, message: str | None = None):
        if message is None:
            message = (
                "mcptrust binary not found. "
                "Install with: go install github.com/mcptrust/mcptrust/cmd/mcptrust@latest "
                "or set MCPTRUST_BIN environment variable."
            )
        super().__init__(message)


class MCPTrustCommandError(MCPTrustError):
    """Raised on non-zero exit code."""
    
    def __init__(
        self,
        message: str,
        *,
        exit_code: int,
        argv: list[str],
        stdout: str = "",
        stderr: str = "",
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.argv = argv
        self.stdout = stdout
        self.stderr = stderr
    
    def __str__(self) -> str:
        base = super().__str__()
        parts = [base, f"exit_code={self.exit_code}"]
        if self.stderr:
            # Truncate long stderr for readability
            stderr_preview = self.stderr[:200] + "..." if len(self.stderr) > 200 else self.stderr
            parts.append(f"stderr={stderr_preview!r}")
        return " | ".join(parts)
