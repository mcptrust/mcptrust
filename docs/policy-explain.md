# Policy Explain Command

The `mcptrust policy explain` command outputs policy rules with their associated compliance metadata in human-readable Markdown or machine-readable JSON.

## Usage

```bash
# Explain baseline preset (default)
mcptrust policy explain

# Explain strict preset
mcptrust policy explain --preset strict

# JSON output for automation
mcptrust policy explain --preset strict --json

# From custom policy file
mcptrust policy explain --policy ./my-policy.yaml

# Write to file
mcptrust policy explain --preset strict --output report.md
```

## Flags

| Flag | Description |
|------|-------------|
| `--preset` | Use built-in preset: `baseline` or `strict` |
| `--policy` | Path to custom policy YAML file |
| `--json` | Output JSON instead of Markdown (default: false) |
| `--output` | Write to file instead of stdout |

> [!NOTE]
> `--preset` and `--policy` are mutually exclusive. If neither is provided, defaults to `--preset baseline`.

## Output Formats

### Markdown (Default)

```bash
mcptrust policy explain --preset strict
```

Outputs a table with columns:
- **Rule**: Rule name
- **Severity**: `warn` or `error`
- **Control Refs**: Compliance framework references (e.g., NIST AI RMF, SOC2)
- **Evidence**: What MCPTrust produces as evidence
- **Evidence Commands**: CLI commands to generate evidence
- **Expr**: CEL expression (truncated for readability)

### JSON

```bash
mcptrust policy explain --preset strict --json
```

```json
{
  "schema_version": "1.0",
  "source": { "type": "preset", "name": "strict" },
  "generated_at": "2025-12-20T18:30:00.000000000Z",
  "rules": [
    {
      "name": "artifact_pinned_required",
      "severity": "error",
      "expr": "has(input.artifact) && input.artifact.integrity != \"\"",
      "failure_msg": "✗ Artifact MUST be pinned with integrity hash",
      "control_refs": ["NIST AI RMF: GOVERN 1.1", "SOC2: CC7.2"],
      "evidence": ["Signed mcp-lock.json with integrity hash"],
      "evidence_commands": ["mcptrust verify --lockfile mcp-lock.json"]
    }
  ]
}
```

## CI Integration

### Generate Compliance Report

```yaml
- name: Generate policy explain report
  run: mcptrust policy explain --preset strict --json > policy-report.json

- name: Upload as artifact
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.0
  with:
    name: policy-report
    path: policy-report.json
```

### Combine with Policy Check

```yaml
- name: Run policy check
  run: |
    mcptrust policy check --preset strict --lockfile mcp-lock.json -- "$SERVER_CMD"
    mcptrust policy explain --preset strict --output policy-explain.md
```

## Related Documentation

- [Policy Guide](POLICY.md) - CEL policy syntax and examples
- [GitHub Action](github-action.md) - Automated CI integration
- [Compliance: NIST AI RMF](compliance/nist-rmf.md)
- [Compliance: ISO/IEC 42001](compliance/iso-42001.md)
- [Compliance: EU AI Act](compliance/eu-ai-act.md)
