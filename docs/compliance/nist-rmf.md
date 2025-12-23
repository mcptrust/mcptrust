# NIST AI Risk Management Framework

> [!IMPORTANT]
> MCPTrust provides **evidence and supports controls**—it is **not a certification** or formal compliance attestation.

## Overview

The [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) provides voluntary guidance for managing AI risks. MCPTrust helps organizations collect evidence for several control areas.

## Control Mapping

| Control Area | What MCPTrust Helps With | Evidence | How to Validate |
|--------------|--------------------------|----------|-----------------|
| **GOVERN 1.1** – Policies and accountability | Artifact pinning enforces supply chain policy | `mcp-lock.json` with integrity hash | `mcptrust verify --lockfile mcp-lock.json` |
| **GOVERN 2.1** – Documented processes | Policy explain outputs document controls | `mcptrust policy explain --json` | Review generated report |
| **MAP 1.1** – AI system documentation | Provenance attestation traces software origin | SLSA provenance in lockfile | `mcptrust artifact provenance mcp-lock.json` |
| **MEASURE 2.3** – Risk assessment | Automated tool risk classification | Scan output with risk levels | `mcptrust scan -- <server command>` |

## Generating Evidence

```bash
# Generate policy explain report
mcptrust policy explain --preset strict --json > nist-evidence.json

# Verify artifact integrity
mcptrust verify --lockfile mcp-lock.json

# Check provenance
mcptrust artifact provenance mcp-lock.json
```

## Related Documentation

- [Policy Explain](../policy-explain.md) - Output policy metadata
- [GitHub Action](../github-action.md) - CI integration
