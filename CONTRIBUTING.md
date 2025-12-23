# Contributing to MCPTrust

Thank you for your interest in contributing to MCPTrust! This document provides guidelines for contributing.

## Getting Started

1. **Fork the repository** and clone locally
2. **Install Go 1.24+** (check with `go version`)
3. **Run tests** to verify your setup:
   ```bash
   go test ./...
   ```

## Development Workflow

### Running Tests

```bash
# Unit tests
go test ./...

# Integration suite
bash tests/gauntlet.sh

# Smoke test
MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh
```

### Code Quality

Before submitting, ensure:

```bash
# Format code
gofmt -w .

# Run vet
go vet ./...

# Run linter (optional but recommended)
golangci-lint run
```

## Submitting Changes

1. **Create a branch** for your feature/fix
2. **Write tests** for any new functionality
3. **Update documentation** if applicable
4. **Submit a pull request** with a clear description

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add new policy preset`
- `fix: correct signature verification edge case`
- `docs: update CLI reference`

## Reporting Issues

- **Bugs**: Include steps to reproduce, expected vs actual behavior
- **Features**: Describe the use case and proposed solution

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Please report via [private security advisory](https://github.com/mcptrust/mcptrust/security/advisories/new) or email security@mcptrust.dev.

## Code of Conduct

Be respectful and constructive. We welcome contributors of all experience levels.

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).
