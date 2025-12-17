#!/usr/bin/env bash
#
# MCPTrust Smoke Test
# ===================
# Quick keygen/sign/verify check.
# No repo modifications.
#
# Requirements:
#   - mcptrust binary
#   - Node.js + npx
#
# Usage:
#   MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh
#
# Ed25519 only (no cosign).

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Find binary and convert to absolute path (before we cd)
MCPTRUST="${MCPTRUST_BIN:-mcptrust}"
if [[ "${MCPTRUST}" == "./"* ]] || [[ "${MCPTRUST}" != "/"* ]]; then
    # abspath
    if [[ -f "${MCPTRUST}" ]]; then
        MCPTRUST="$(cd "$(dirname "${MCPTRUST}")" && pwd)/$(basename "${MCPTRUST}")"
    fi
fi
if ! [[ -x "${MCPTRUST}" ]] && ! command -v "${MCPTRUST}" &> /dev/null; then
    echo -e "${RED}❌ mcptrust not found. Set MCPTRUST_BIN or add to PATH.${NC}"
    exit 1
fi

# temp dir
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

echo "MCPTrust Smoke Test"
echo "==================="
echo "Binary: ${MCPTRUST}"
echo "Temp dir: ${TEMP_DIR}"
echo ""

cd "${TEMP_DIR}"

# check npx
if ! command -v npx &> /dev/null; then
    echo -e "${RED}❌ npx not found. Install Node.js to run this test.${NC}"
    exit 1
fi

# 1. Lock
echo "1. Creating lockfile..."
if "${MCPTRUST}" lock -- "npx -y @modelcontextprotocol/server-filesystem /tmp" > lock_output.txt 2>&1; then
    echo -e "   ${GREEN}✅ Lock succeeded${NC}"
else
    echo -e "   ${RED}❌ Lock failed${NC}"
    cat lock_output.txt
    exit 1
fi

# check lockfile
if [[ ! -f "mcp-lock.json" ]]; then
    echo -e "   ${RED}❌ mcp-lock.json not created${NC}"
    exit 1
fi

# 2. Keygen
echo "2. Generating Ed25519 keypair..."
if "${MCPTRUST}" keygen --private private.key --public public.key > keygen_output.txt 2>&1; then
    echo -e "   ${GREEN}✅ Keygen succeeded${NC}"
else
    echo -e "   ${RED}❌ Keygen failed${NC}"
    cat keygen_output.txt
    exit 1
fi

# 3. Sign
echo "3. Signing lockfile..."
if "${MCPTRUST}" sign --key private.key --lockfile mcp-lock.json > sign_output.txt 2>&1; then
    echo -e "   ${GREEN}✅ Sign succeeded${NC}"
else
    echo -e "   ${RED}❌ Sign failed${NC}"
    cat sign_output.txt
    exit 1
fi

# check signature
if [[ ! -f "mcp-lock.json.sig" ]]; then
    echo -e "   ${RED}❌ Signature file not created${NC}"
    exit 1
fi

# 4. Verify
echo "4. Verifying signature..."
if "${MCPTRUST}" verify --key public.key --lockfile mcp-lock.json > verify_output.txt 2>&1; then
    echo -e "   ${GREEN}✅ Verify succeeded${NC}"
else
    echo -e "   ${RED}❌ Verify failed${NC}"
    cat verify_output.txt
    exit 1
fi

echo ""
echo -e "${GREEN}✅ All smoke tests passed!${NC}"
exit 0
