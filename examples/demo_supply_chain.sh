#!/usr/bin/env bash
#
# MCPTrust Supply Chain Demo
#
# Flow:
# 1. Lock (pin + provenance)
# 2. Check (integrity)
# 3. Verify (provenance)
# 4. Policy (enforce)
# 5. Run (guardrails)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEMO_DIR=$(mktemp -d)
trap "rm -rf ${DEMO_DIR}" EXIT

echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  MCPTrust Supply Chain Verification Demo${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Demo directory: ${DEMO_DIR}"
echo ""

echo -e "${YELLOW}▶ Checking prerequisites...${NC}"

if ! command -v mcptrust &> /dev/null; then
    echo -e "${RED}✗ mcptrust not found. Install with:${NC}"
    echo "  go install github.com/mcptrust/mcptrust/cmd/mcptrust@v0.1.1"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} mcptrust $(mcptrust --version 2>/dev/null || echo 'installed')"

if ! command -v jq &> /dev/null; then
    echo -e "${RED}✗ jq not found. Install with:${NC}"
    echo "  brew install jq  # macOS"
    echo "  apt install jq   # Ubuntu"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} jq $(jq --version)"

HAS_COSIGN=false
HAS_NPM=false

if command -v cosign &> /dev/null; then
    HAS_COSIGN=true
    echo -e "  ${GREEN}✓${NC} cosign available (primary provenance verification)"
fi

if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    HAS_NPM=true
    echo -e "  ${GREEN}✓${NC} npm ${NPM_VERSION} (fallback provenance verification)"
fi

if [[ "${HAS_COSIGN}" != "true" ]] && [[ "${HAS_NPM}" != "true" ]]; then
    echo -e "${RED}✗ Neither cosign nor npm found. Install one:${NC}"
    echo "  brew install cosign  # recommended"
    echo "  brew install node    # fallback"
    exit 1
fi

echo ""

echo -e "${YELLOW}▶ Step 1: Lock MCP server with artifact pinning + provenance${NC}"
echo ""

SERVER_CMD="npx -y @modelcontextprotocol/server-filesystem /tmp"
echo "  Server command: ${SERVER_CMD}"
echo ""

cd "${DEMO_DIR}"

echo "  Running: mcptrust lock --pin --verify-provenance -- \"${SERVER_CMD}\""
echo ""

if mcptrust lock --pin --verify-provenance -- "${SERVER_CMD}"; then
    echo ""
    echo -e "  ${GREEN}✓ Lockfile created with artifact pin and verified provenance${NC}"
else
    echo ""
    echo -e "  ${YELLOW}⚠ Provenance verification may have failed (package may lack attestations)${NC}"
    echo "  Retrying without provenance verification..."
    mcptrust lock --pin -- "${SERVER_CMD}"
    echo -e "  ${GREEN}✓ Lockfile created with artifact pin (no provenance)${NC}"
fi

echo ""
echo "  Lockfile preview:"
head -20 mcp-lock.json | sed 's/^/    /'
echo ""

echo -e "${YELLOW}▶ Step 2: Verify artifact integrity${NC}"
echo ""

echo "  Running: mcptrust artifact verify mcp-lock.json"
echo ""

if mcptrust artifact verify mcp-lock.json; then
    echo ""
    echo -e "  ${GREEN}✓ Artifact integrity verified${NC}"
else
    echo ""
    echo -e "  ${RED}✗ Integrity verification failed!${NC}"
fi
echo ""

echo -e "${YELLOW}▶ Step 3: Verify provenance attestations${NC}"
echo ""

echo "  Running: mcptrust artifact provenance mcp-lock.json"
echo ""

if mcptrust artifact provenance mcp-lock.json 2>/dev/null; then
    echo ""
    echo -e "  ${GREEN}✓ Provenance verified${NC}"
else
    echo ""
    echo -e "  ${YELLOW}⚠ Provenance verification skipped or failed${NC}"
    echo "  (Package may not have SLSA attestations)"
fi
echo ""

echo -e "${YELLOW}▶ Step 4: Policy checks${NC}"
echo ""

# Create a custom policy for demonstration
cat > "${DEMO_DIR}/custom_policy.yaml" << 'EOF'
name: "Demo Supply Chain Policy"
rules:
  # Trusted source repository allowlist
  - name: "trusted_source"
    expr: |
      !has(input.provenance) ||
      input.provenance.source_repo.matches("^https://github.com/(modelcontextprotocol|anthropics)/.*")
    failure_msg: "Artifact must come from a trusted GitHub organization"
    severity: warn

  # Approved workflow allowlist
  - name: "approved_workflow"
    expr: |
      !has(input.provenance) ||
      input.provenance.workflow_uri in [
        ".github/workflows/release.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/ci.yml"
      ]
    failure_msg: "Artifact must be built by an approved workflow"
    severity: warn

  # No high-risk tools
  - name: "no_high_risk"
    expr: '!input.tools.exists(t, t.risk_level == "HIGH")'
    failure_msg: "High-risk tools are not allowed"
    severity: error
EOF

echo "  Created custom policy: custom_policy.yaml"
echo ""

echo "  Baseline preset (warn-only):"
echo "  mcptrust policy check --preset baseline --lockfile mcp-lock.json -- \"${SERVER_CMD}\""
echo ""

set +e
mcptrust policy check --preset baseline --lockfile mcp-lock.json -- "${SERVER_CMD}" 2>&1 | sed 's/^/    /'
BASELINE_EXIT=$?
set -e

echo ""
if [[ ${BASELINE_EXIT} -eq 0 ]]; then
    echo -e "  ${GREEN}✓ Baseline preset passed (exit 0)${NC}"
else
    echo -e "  ${YELLOW}⚠ Baseline preset returned warnings${NC}"
fi
echo ""

echo "  Strict preset (fail-closed):"
echo "  mcptrust policy check --preset strict --lockfile mcp-lock.json -- \"${SERVER_CMD}\""
echo ""

set +e
mcptrust policy check --preset strict --lockfile mcp-lock.json -- "${SERVER_CMD}" 2>&1 | sed 's/^/    /'
STRICT_EXIT=$?
set -e

echo ""
if [[ ${STRICT_EXIT} -eq 0 ]]; then
    echo -e "  ${GREEN}✓ Strict preset passed (exit 0)${NC}"
else
    echo -e "  ${YELLOW}⚠ Strict preset failed (exit ${STRICT_EXIT})${NC}"
    echo "  This is expected if artifact lacks provenance or has high-risk tools."
fi
echo ""

echo -e "${YELLOW}▶ Step 5: Enforced execution (dry-run)${NC}"
echo ""

echo "  Running: mcptrust run --dry-run --lock mcp-lock.json"
echo ""

set +e
mcptrust run --dry-run --lock mcp-lock.json 2>&1 | sed 's/^/    /'
RUN_EXIT=$?
set -e

echo ""
if [[ ${RUN_EXIT} -eq 0 ]]; then
    echo -e "  ${GREEN}✓ Dry run succeeded - ready for enforced execution${NC}"
else
    echo -e "  ${YELLOW}⚠ Dry run failed (exit ${RUN_EXIT})${NC}"
    echo "  This may require --require-provenance=false for packages without attestations."
fi
echo ""

echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Demo Complete${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Key commands demonstrated:"
echo "  1. mcptrust lock --pin --verify-provenance -- <cmd>"
echo "  2. mcptrust artifact verify <lockfile>"
echo "  3. mcptrust artifact provenance <lockfile>"
echo "  4. mcptrust policy check --preset baseline|strict --lockfile <lockfile> -- <cmd>"
echo "  5. mcptrust run --dry-run --lock <lockfile>"
echo ""
echo "For production use, combine with CI/CD:"
echo "  See: examples/github-actions/lock-and-check.yml"
echo ""
echo -e "${GREEN}✓ Demo artifacts cleaned up automatically${NC}"
