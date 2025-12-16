# Integrations

MCPTrust integrates with CI/CD systems to enforce capability controls on every pull request.

## GitHub Actions

Add MCPTrust to your CI pipeline to automatically verify lockfile signatures and detect capability drift.

### Quick Start

1. Copy the workflow template to your repo:
   ```bash
   cp .github/workflows/mcptrust.yml.example .github/workflows/mcptrust.yml
   ```

2. Edit the `MCP_SERVER_COMMAND` env variable to match your server:
   ```yaml
   env:
     MCP_SERVER_COMMAND: "npx -y @modelcontextprotocol/server-filesystem /tmp"
   ```

3. Commit your lockfile, signature, and public key:
   ```bash
   mcptrust lock -- "your-mcp-server-command"
   mcptrust sign
   git add mcp-lock.json mcp-lock.json.sig public.key
   git commit -m "Add MCPTrust artifacts"
   ```

### Workflow Template

Copy this to `.github/workflows/mcptrust.yml`:

```yaml
name: MCPTrust

on:
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write

env:
  # REQUIRED: Replace with your MCP server command
  MCP_SERVER_COMMAND: "npx -y @modelcontextprotocol/server-filesystem /tmp"
  
  # Optional: Customize paths if needed
  LOCKFILE_PATH: "mcp-lock.json"
  SIG_PATH: "mcp-lock.json.sig"
  PUBLIC_KEY_PATH: "public.key"

jobs:
  mcptrust:
    name: MCPTrust Security Check
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
          cache: false

      - name: Install mcptrust
        run: go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.0

      - name: Verify lockfile signature
        run: |
          mcptrust verify \
            --key "${{ env.PUBLIC_KEY_PATH }}" \
            --lockfile "${{ env.LOCKFILE_PATH }}" \
            --signature "${{ env.SIG_PATH }}"

      - name: Detect drift
        id: diff
        run: |
          set +e
          mcptrust diff \
            --lockfile "${{ env.LOCKFILE_PATH }}" \
            -- ${{ env.MCP_SERVER_COMMAND }} > diff_output.txt 2>&1
          EXIT_CODE=$?
          echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT
          if [ $EXIT_CODE -ne 0 ]; then
            echo "::error::MCPTrust detected capability drift"
            cat diff_output.txt
          fi
          exit $EXIT_CODE

      - name: Post PR comment on drift
        if: failure() && steps.diff.outputs.exit_code != '0'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let diffOutput = fs.readFileSync('diff_output.txt', 'utf8');
            if (diffOutput.length > 60000) {
              diffOutput = diffOutput.substring(0, 60000) + '\n... (truncated)';
            }
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## ⚠️ MCPTrust detected capability drift\n\n\`\`\`\n${diffOutput}\n\`\`\`\n\n[MCPTrust Docs](https://github.com/mcptrust/mcptrust)`
            });
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_SERVER_COMMAND` | *(required)* | Command to start your MCP server |
| `LOCKFILE_PATH` | `mcp-lock.json` | Path to lockfile |
| `SIG_PATH` | `mcp-lock.json.sig` | Path to signature |
| `PUBLIC_KEY_PATH` | `public.key` | Path to public key |
| `POLICY_PATH` | `policy.yaml` | Path to policy file (optional) |

### No-Network Fallback

If your MCP server can't run in CI (requires external services, credentials, etc.), you have two options:

1. **Verify-only mode**: Remove the "Detect drift" step and only run signature verification. This ensures lockfiles aren't tampered with, but won't catch drift.

2. **Fixture mode for local testing**: Use `MCPTRUST_FORCE_FIXTURE=1` to test with mock data locally, but this won't work for real drift detection in CI.

### What Happens on Drift?

When `mcptrust diff` detects changes:
1. The job fails with a non-zero exit code
2. A PR comment is posted showing exactly what changed
3. Reviewers can see the diff and decide whether to approve

### Re-locking

If drift is intentional (e.g., you added a new tool), update your artifacts:

```bash
mcptrust lock -- "your-mcp-server-command"
mcptrust sign
git add mcp-lock.json mcp-lock.json.sig
git commit -m "Update MCPTrust lockfile"
```
