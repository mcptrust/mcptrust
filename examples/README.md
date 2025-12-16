# Examples

This directory contains example artifacts for MCPTrust.

## Policies

You can use these policies with the `mcptrust policy check` command.

*   **[policy.basic.yaml](policy.basic.yaml)**: A simple policy that ensures tools exist and bans common "delete" keywords.
*   **[policy.strict.yaml](policy.strict.yaml)**: A harsh policy for high-security environments, allowing only `LOW` risk tools and enforcing description tags.

## CI/CD Example (GitHub Actions)

To run MCPTrust in your pipeline:

```yaml
name: MCP Security Check
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      
      # Pinned install (recommended). Use @latest for bleeding edge.
      - name: Install MCPTrust
        run: go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.0
      
      - name: Verify Lockfile
        run: mcptrust verify --key public.key
      
      - name: Check for Drift
        run: mcptrust diff -- "npx -y @modelcontextprotocol/server-filesystem ."
```
