# MCPTrust Architecture

**MCPTrust** is a Go CLI for securing AI-agent tool supply chains. It verifies Model Context Protocol (MCP) servers before agents use them.

## High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MCPTrust Data Flow                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────┐      ┌──────────────┐      ┌──────────────┐                   │
│   │   MCP   │─────▶│   SCANNER    │─────▶│  ScanReport  │                   │
│   │ Server  │ STDIO│   (engine)   │      │    (JSON)    │                   │
│   └─────────┘      └──────────────┘      └──────┬───────┘                   │
│                                                 │                           │
│          ┌──────────────────────────────────────┴──────────────┐            │
│          │                       │                             │            │
│          ▼                       ▼                             ▼            │
│   ┌──────────────┐        ┌──────────────┐              ┌─────────────┐     │
│   │    POLICY    │        │    LOCKER    │              │   DIFFER    │     │
│   │   (engine)   │        │   (manager)  │              │  (engine)   │     │
│   │   CEL rules  │        │   SHA-256    │              │  jsondiff   │     │
│   └──────┬───────┘        └──────┬───────┘              └──────┬──────┘     │
│          │                       │                             │            │
│          ▼                       ▼                             ▼            │
│   ┌──────────────┐        ┌──────────────┐              ┌──────────────┐    │
│   │ PolicyResult │        │   Lockfile   │              │  DiffResult  │    │
│   │ (pass/fail)  │        │ mcp-lock.json│              │  (patches)   │    │
│   └──────────────┘        └──────┬───────┘              └──────────────┘    │
│                                  │                                          │
│                                  ▼                                          │
│                           ┌──────────────┐                                  │
│                           │    CRYPTO    │                                  │
│                           │   Ed25519    │                                  │
│                           └──────┬───────┘                                  │
│                                  │                                          │
│                                  ▼                                          │
│                           ┌──────────────┐                                  │
│                           │  Signature   │                                  │
│                           │  (.sig file) │                                  │
│                           └──────┬───────┘                                  │
│                                  │                                          │
│                                  ▼                                          │
│                           ┌──────────────┐                                  │
│                           │   BUNDLER    │                                  │
│                           │   (writer)   │                                  │
│                           └──────┬───────┘                                  │
│                                  │                                          │
│                                  ▼                                          │
│                           ┌──────────────┐                                  │
│                           │    .zip      │                                  │
│                           │   Bundle     │                                  │
│                           └──────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

### 1. Scanner (`internal/scanner/engine.go`)

**Purpose**: Interrogates MCP servers via stdio JSON-RPC to enumerate capabilities.

**Key Types**:
| Type | Description |
|------|-------------|
| `Engine` | Manages MCP server connection, request IDs, and mutex |
| `RiskAnalyzer` | Assesses risk based on dangerous keyword patterns |

**Key Functions**:
| Function | Description |
|----------|-------------|
| `NewEngine(timeout)` | Creates scanner engine |
| `Connect(ctx, command)` | Starts MCP server process, attaches to stdio |
| `Initialize(ctx)` | Performs MCP handshake (protocol v2024-11-05) |
| `ListTools(ctx)` | Sends `tools/list` JSON-RPC request |
| `ListResources(ctx)` | Sends `resources/list` JSON-RPC request |
| `Scan(ctx, command, timeout)` | High-level scan orchestrator |
| `AnalyzeTools(mcpTools)` | Assigns LOW/MEDIUM/HIGH risk levels |

**Inputs/Outputs**:
- **Input**: Shell command string (e.g., `npx -y @modelcontextprotocol/server-filesystem /tmp`)
- **Output**: `models.ScanReport` (JSON)

**Dependencies**: `os/exec`, `encoding/json`, `bufio`

---

### 2. Locker (`internal/locker/`)

**Purpose**: Creates immutable lockfiles with cryptographic hashes for drift detection.

**Key Types**:
| Type | Description |
|------|-------------|
| `Manager` | Handles lockfile CRUD operations |
| `DriftType` | Enum: `tool_added`, `tool_removed`, `description_changed`, `schema_changed`, `risk_level_changed` |
| `DriftItem` | Represents a single detected drift |
| `orderedMap` | Custom type for deterministic JSON key ordering |

**Key Functions**:
| Function | Location | Description |
|----------|----------|-------------|
| `CreateLockfile(report)` | manager.go | Converts ScanReport → Lockfile |
| `Save(lockfile, path)` | manager.go | Writes formatted JSON |
| `Load(path)` | manager.go | Reads lockfile from disk |
| `DetectDrift(existing, new)` | manager.go | Compares two lockfiles |
| `HashString(s)` | hasher.go | SHA-256 hash of string |
| `HashJSON(v)` | hasher.go | Canonical SHA-256 hash of JSON |
| `CanonicalizeJSON(v)` | hasher.go | Deterministic key-sorted JSON |

**Inputs/Outputs**:
- **Input**: `models.ScanReport`
- **Output**: `mcp-lock.json` file
  ```json
  {
    "version": "1.0",
    "server_command": "...",
    "tools": {
      "tool_name": {
        "description_hash": "sha256:...",
        "input_schema_hash": "sha256:...",
        "risk_level": "HIGH"
      }
    }
  }
  ```

**Dependencies**: `crypto/sha256`, `encoding/json`, `sort`

---

### 3. Differ (`internal/differ/`)

**Purpose**: Detects and translates changes between locked and live server state.

**Key Types**:
| Type | Description |
|------|-------------|
| `Engine` | Orchestrates diff computation |
| `DiffType` | Enum: `added`, `removed`, `changed`, `no_change` |
| `ToolDiff` | Contains tool name, type, JSON patches, and translations |
| `DiffResult` | Aggregates all tool diffs |
| `SeverityLevel` | Enum: `SeveritySafe`, `SeverityModerate`, `SeverityCritical` |

**Key Functions**:
| Function | Location | Description |
|----------|----------|-------------|
| `ComputeDiff(ctx, lockfilePath, command)` | engine.go | Loads lockfile, performs fresh scan, computes patches |
| `compareSchemas(locked, current)` | engine.go | Compares hashes and generates patches |
| `Translate(patches)` | translator.go | Converts JSON patches to human sentences |
| `GetSeverity(translation)` | translator.go | Returns color-coded severity |

**Inputs/Outputs**:
- **Input**: `mcp-lock.json` path + MCP server command
- **Output**: `DiffResult` with human-readable translations

**Dependencies**: `github.com/wI2L/jsondiff`

---

### 4. Policy (`internal/policy/engine.go`)

**Purpose**: Evaluates security rules written in CEL against scan reports.

**Key Types**:
| Type | Description |
|------|-------------|
| `Engine` | Contains CEL environment |

**Key Functions**:
| Function | Description |
|----------|-------------|
| `NewEngine()` | Creates CEL environment with `input` variable |
| `Evaluate(config, report)` | Runs all rules against ScanReport |
| `evaluateRule(rule, input)` | Compiles and evaluates single CEL expression |
| `CompileAndValidate(config)` | Validates all CEL expressions |

**Inputs/Outputs**:
- **Input**: `policy.yaml` file:
  ```yaml
  name: "Security Policy"
  rules:
    - name: "no_high_risk"
      expr: 'input.tools.all(t, t.risk_level != "HIGH")'
      failure_msg: "High-risk tools detected"
  ```
- **Output**: `[]models.PolicyResult` (pass/fail per rule)

**Dependencies**: `github.com/google/cel-go/cel`, `gopkg.in/yaml.v3`

---

### 5. Crypto (`internal/crypto/signer.go`)

**Purpose**: Ed25519 key generation, signing, and verification.

**Key Functions**:
| Function | Description |
|----------|-------------|
| `GenerateKeys(privateKeyPath, publicKeyPath)` | Creates Ed25519 keypair, saves as PEM |
| `Sign(data, privateKeyPath)` | Signs data with private key |
| `Verify(data, signature, publicKeyPath)` | Verifies signature with public key |

**Inputs/Outputs**:
- **Input**: Canonical lockfile bytes
- **Output**: 
  - `private.key` (PEM, keep secret)
  - `public.key` (PEM, distribute)
  - `mcp-lock.json.sig` (hex-encoded signature)

**Dependencies**: `crypto/ed25519`, `crypto/rand`, `encoding/pem`

---

### 6. Bundler (`internal/bundler/writer.go`)

**Purpose**: Packages security artifacts into distributable ZIP archive.

**Key Types**:
| Type | Description |
|------|-------------|
| `BundleOptions` | Paths for lockfile, signature, public key, policy, output |

**Key Functions**:
| Function | Description |
|----------|-------------|
| `CreateBundle(opts, readmeContent)` | Creates ZIP with all artifacts |

**Inputs/Outputs**:
- **Input**: `mcp-lock.json`, `mcp-lock.json.sig`, optional `public.key`, `policy.yaml`
- **Output**: `.zip` bundle containing:
  - `mcp-lock.json` (required)
  - `mcp-lock.json.sig` (required)
  - `public.key` (optional)
  - `policy.yaml` (optional)
  - `README.txt` (generated)

**Dependencies**: `archive/zip`

---

### 7. Models (`internal/models/`)

**Key Structs**:
| Struct | File | Description |
|--------|------|-------------|
| `ScanReport` | report.go | Complete scan result with timestamp, tools, resources |
| `Tool` | report.go | Tool with name, description, inputSchema, riskLevel |
| `Resource` | report.go | MCP resource with URI, name, mimeType |
| `ServerInfo` | report.go | Server name, version, protocol version |
| `Lockfile` | lockfile.go | Version, server_command, tools map |
| `ToolLock` | lockfile.go | description_hash, input_schema_hash, risk_level |
| `PolicyConfig` | policy.go | name, rules array |
| `PolicyRule` | policy.go | name, expr (CEL), failure_msg |
| `PolicyResult` | policy.go | RuleName, Passed, FailureMsg |
| `MCP*` structs | report.go | JSON-RPC message types for MCP protocol |

---

### 8. CLI (`internal/cli/`)

| Command | File | Description |
|---------|------|-------------|
| `scan` | scan.go | Interrogate MCP server, output JSON report |
| `lock` | lock.go | Create/update mcp-lock.json with drift detection |
| `diff` | diff.go | Compare lockfile vs live server |
| `policy check` | policy.go | Evaluate CEL rules against scan |
| `keygen` | keys.go | Generate Ed25519 keypair |
| `sign` | keys.go | Sign mcp-lock.json |
| `verify` | keys.go | Verify signature (exit 0=valid, 1=tampered) |
| `bundle export` | bundle.go | Create distributable ZIP |

---

## Command Lifecycle

```
1. DISCOVERY     mcptrust scan -- "npx server"      → JSON report
2. GOVERNANCE    mcptrust policy check -- "npx server" → pass/fail
3. PERSISTENCE   mcptrust lock -- "npx server"     → mcp-lock.json
4. IDENTITY      mcptrust keygen && mcptrust sign  → .key + .sig
5. VERIFICATION  mcptrust verify                   → exit 0 or 1
6. DISTRIBUTION  mcptrust bundle export            → .zip
7. DRIFT CHECK   mcptrust diff -- "npx server"     → change report
```

---

## Testing Strategy
 
 ### Gauntlet (`tests/gauntlet.sh`)
 To ensure "diligence-grade" reliability, the repo includes a comprehensive integration test suite called "The Gauntlet". It runs in CI and verifies:
 1. **Build**: Compiles binaries and mock servers.
 2. **Lifecycle**: Scan → Policy → Lock → Keygen → Sign → Bundle.
 3. **Tamper Detection**: Cryptographically proves that `verify` detects bit-flip corruption in the lockfile or signature.
 4. **Determinism**: Proves that `bundle export` produces bit-for-bit identical ZIPs for the same inputs.
 5. **Negative Testing**: Validates failure paths (wrong key, corrupted pubkey, policy violation).
 
 ---
 
 ## External Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `github.com/spf13/cobra` | v1.10.2 | CLI framework |
| `github.com/google/cel-go` | v0.26.1 | Policy expression language |
| `github.com/wI2L/jsondiff` | v0.7.0 | JSON patch generation |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML parsing for policies |
| `crypto/ed25519` | stdlib | Digital signatures |
| `crypto/sha256` | stdlib | Content hashing |
| `archive/zip` | stdlib | Bundle creation |
