# EU AI Act

> [!IMPORTANT]
> MCPTrust provides **evidence and supports controls**—it is **not a certification** or formal compliance attestation.

## Overview

The [EU AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) establishes legal requirements for AI systems. MCPTrust helps collect evidence for technical documentation and traceability requirements.

## Control Mapping

| Requirement | What MCPTrust Helps With | Evidence | How to Validate |
|-------------|--------------------------|----------|-----------------|
| **Article 11** – Technical documentation | Provenance attestation, build traceability | SLSA provenance in lockfile | `mcptrust artifact provenance mcp-lock.json` |
| **Article 12** – Record-keeping | Audit trail via receipts and JSONL logs | `receipt.json`, JSONL logs | Review `--receipt-path` output |
| **Article 14** – Human oversight | Policy controls enable review gates | Policy explain output | `mcptrust policy explain --preset strict` |

## Generating Evidence

```bash
# Generate comprehensive report
mcptrust policy explain --preset strict --json > eu-ai-act-evidence.json

# Capture audit receipt
mcptrust policy check --preset strict \
  --lockfile mcp-lock.json \
  --receipt-path receipt.json \
  -- "<server command>"

# Verify provenance
mcptrust artifact provenance mcp-lock.json
```

## Related Documentation

- [Policy Explain](../policy-explain.md) - Output policy metadata
- [GitHub Action](../github-action.md) - CI integration
