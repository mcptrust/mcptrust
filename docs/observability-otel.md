# OpenTelemetry Tracing

MCPTrust supports optional OpenTelemetry (OTel) tracing for observability in production deployments. Tracing is **disabled by default** and must be explicitly enabled.

## Enabling OTel Tracing

Use the `--otel` flag to enable tracing:

```bash
# Basic usage with defaults (endpoint: localhost:4318, protocol: otlphttp)
mcptrust lock --otel -- "npx -y @modelcontextprotocol/server-filesystem /tmp"

# Custom endpoint and insecure mode for local development
mcptrust lock --otel --otel-endpoint localhost:4318 --otel-insecure -- "..."

# gRPC protocol
mcptrust lock --otel --otel-protocol otlpgrpc --otel-endpoint localhost:4317 -- "..."

# Custom service name and sampling
mcptrust lock --otel --otel-service-name my-mcptrust --otel-sample-ratio 0.5 -- "..."
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--otel` | `false` | Enable OpenTelemetry tracing |
| `--otel-endpoint` | `$OTEL_EXPORTER_OTLP_ENDPOINT` or `localhost:4318` | OTLP exporter endpoint |
| `--otel-protocol` | `otlphttp` | Protocol: `otlphttp` or `otlpgrpc` |
| `--otel-insecure` | `false` | Allow insecure connections (no TLS) |
| `--otel-service-name` | `mcptrust` | Service name for traces |
| `--otel-sample-ratio` | `1.0` | Sampling ratio (0.0-1.0) |

## Span Attributes

Each command creates a span with these attributes:

- `mcptrust.command` - Command name (e.g., `lock`, `run`, `scan`)
- `mcptrust.op_id` - Unique operation ID for correlation with JSONL logs
- Context-specific attributes (lockfile path, preset, etc.)

## Environment Variables

OTel respects standard environment variables when specific flags aren't set:

- `OTEL_EXPORTER_OTLP_ENDPOINT` - Default endpoint when `--otel-endpoint` is empty

## Graceful Degradation

- Commands complete successfully even if the OTel collector is unreachable
- Spans are silently dropped on connection failures
- Initialization failures log a warning but don't prevent command execution

## Trace Correlation with JSONL Logs

When both OTel and JSONL logging are enabled, consider using the `op_id` field in JSONL events to correlate with trace spans.

## Safety

- **Disabled by default** - No behavior change unless `--otel` is true
- **No enforcement changes** - Tracing is purely observational
- **No network calls** unless explicitly enabled
