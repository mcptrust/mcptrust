# Structured Logging

mcptrust supports SIEM-friendly JSONL logging for security observability.

## CLI Flags

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--log-format` | `pretty`, `jsonl` | `pretty` | Log format |
| `--log-level` | `debug`, `info`, `warn`, `error` | `info` | Minimum log level |
| `--log-output` | `stderr`, `<path>` | `stderr` | Log destination |

## JSONL Schema (v1.0)

Each log line is a JSON object with these fields:

```json
{
  "ts": "2024-12-20T12:17:43.123456789-05:00",
  "level": "info",
  "event": "mcptrust.lock.complete",
  "component": "cli",
  "op_id": "550e8400-e29b-41d4-a716-446655440000",
  "schema_version": "1.0",
  "mcptrust_version": "v0.1.1",
  "go_version": "go1.24.0",
  "fields": {
    "duration_ms": 1234,
    "result": "success"
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string | RFC3339Nano timestamp |
| `level` | string | Log level (debug/info/warn/error) |
| `event` | string | Event name with `mcptrust.` prefix (e.g., `mcptrust.lock.start`) |
| `component` | string | Component name (always `cli` for CLI events) |
| `op_id` | string | UUID v4, unique per CLI invocation |
| `schema_version` | string | Always `"1.0"` for forward compatibility |
| `mcptrust_version` | string | mcptrust binary version (e.g., `v0.1.1` or `dev`) |
| `go_version` | string | Go runtime version (e.g., `go1.24.0`) |
| `fields` | object | Event-specific fields |

### Common Event Fields

For `*.complete` events:
- `duration_ms` (int): Command execution time in milliseconds
- `result` (string): `"success"` or `"fail"`

## Event Reference

| Event | Description |
|-------|-------------|
| `mcptrust.scan.start` / `mcptrust.scan.complete` | MCP server scan |
| `mcptrust.lock.start` / `mcptrust.lock.complete` | Lockfile creation |
| `mcptrust.diff.start` / `mcptrust.diff.complete` | Drift detection |
| `mcptrust.sign.start` / `mcptrust.sign.complete` | Lockfile signing |
| `mcptrust.verify.start` / `mcptrust.verify.complete` | Signature verification |
| `mcptrust.policy_check.start` / `mcptrust.policy_check.complete` | Policy evaluation |
| `mcptrust.artifact_verify.start` / `mcptrust.artifact_verify.complete` | Artifact integrity |
| `mcptrust.artifact_provenance.start` / `mcptrust.artifact_provenance.complete` | Provenance attestation |
| `mcptrust.run.start` / `mcptrust.run.complete` | Enforced execution |
| `mcptrust.bundle_export.start` / `mcptrust.bundle_export.complete` | Bundle creation |

## Examples

```bash
# Log to stderr in JSONL format
mcptrust lock --log-format=jsonl -- "npx -y @example/pkg"

# Log to file
mcptrust run --log-format=jsonl --log-output=/var/log/mcptrust.log --lock mcp-lock.json

# Debug level logging
mcptrust scan --log-format=jsonl --log-level=debug -- "npx -y @example/pkg"
```

## SIEM Integration

The JSONL format is designed for ingestion by SIEM tools:

- **Splunk**: Use `INDEXED_EXTRACTIONS=json`
- **Elasticsearch**: Parse with `json` processor
- **Datadog**: Auto-parses JSON logs
- **CloudWatch Logs**: Use JSON metric filters

### Sample Splunk Query

```spl
index=mcptrust sourcetype=jsonl
| spath
| search event="*.complete" result="fail"
| stats count by event, op_id
```
