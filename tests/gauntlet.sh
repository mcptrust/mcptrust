#!/usr/bin/env bash
#
# MCPTrust Gauntlet
# =================
# Integration tests for mcptrust lifecycle.
#
# Exit codes:
#   0 = Pass
#   1 = Fail
#
# Features:
#   - Portable (macOS/Linux)
#   - Deterministic (mock server fallback)
#   - Negative tests included

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR=$(mktemp -d)
BINARY="${TEST_DIR}/mcptrust"
MOCK_SERVER_DIR="${SCRIPT_DIR}/fixtures/mock_mcp_server"
MOCK_SERVER_BINARY="${TEST_DIR}/mock_mcp_server"

# Test file paths
LOCKFILE="${TEST_DIR}/mcp-lock.json"
SIGNATURE="${TEST_DIR}/mcp-lock.json.sig"
PRIVATE_KEY="${TEST_DIR}/private.key"
PUBLIC_KEY="${TEST_DIR}/public.key"
POLICY_FILE="${TEST_DIR}/policy.yaml"
BUNDLE_FILE="${TEST_DIR}/bundle.zip"

# For negative tests
PRIVATE_KEY_B="${TEST_DIR}/private_b.key"
PUBLIC_KEY_B="${TEST_DIR}/public_b.key"

# Consistent server command used across ALL phases
# Will be updated to mock server if live fails
SERVER_CMD=""
USING_MOCK_SERVER=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# Portability
# ============================================================================

# sha256 hash (portable)
hash_file() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

# in-place sed (portable)
inplace_sed() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# flip byte (portable, for corruption tests)
flip_byte_file() {
    local file="$1"
    python3 -c "
import sys
with open('$file', 'rb') as f:
    data = f.read()
if len(data) > 0:
    flipped = bytes([data[0] ^ 0x01]) + data[1:]
    with open('$file', 'wb') as f:
        f.write(flipped)
"
}

# ============================================================================
# Prerequisite Checks
# ============================================================================

check_prereqs() {
    echo "Checking prerequisites..."
    local missing=()
    
    # go
    if ! command -v go &> /dev/null; then
        missing+=("go")
    else
        echo "  ✓ go $(go version | awk '{print $3}')"
    fi
    
    # zip
    if ! command -v zip &> /dev/null; then
        missing+=("zip")
    else
        echo "  ✓ zip available"
    fi
    
    # unzip
    if ! command -v unzip &> /dev/null; then
        missing+=("unzip")
    else
        echo "  ✓ unzip available"
    fi
    
    # jq or python (need at least one)
    if command -v jq &> /dev/null; then
        echo "  ✓ jq $(jq --version)"
    elif command -v python3 &> /dev/null; then
        echo "  ✓ python3 $(python3 --version 2>&1 | awk '{print $2}')"
    else
        missing+=("jq or python3")
    fi

    # node (optional)
    if command -v npx &> /dev/null; then
        echo "  ✓ npx $(npx --version) (optional - live MCP server available)"
    else
        echo "  ⚠ npx not found (will use mock MCP server)"
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}ERROR: Missing required tools: ${missing[*]}${NC}"
        exit 1
    fi
    
    echo "All prerequisites satisfied."
}

# ============================================================================
# Utility
# ============================================================================

log_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
}

log_phase() {
    echo ""
    echo -e "${YELLOW}▶ Phase $1: $2${NC}"
    echo "───────────────────────────────────────────────────────────────────"
}

log_test() {
    echo -e "  Testing: $1"
}

pass() {
    echo -e "  ${GREEN}✅ PASS: $1${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "  ${RED}❌ FAIL: $1${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

cleanup() {
    log_header "Cleanup"
    echo "Removing test artifacts from: ${TEST_DIR}"
    rm -rf "${TEST_DIR}"
    echo "Done."
}

# ============================================================================
# Setup
# ============================================================================

setup() {
    log_header "MCPTrust Gauntlet Test Suite"
    echo "Project Root: ${PROJECT_ROOT}"
    echo "Binary Path:  ${BINARY}"
    echo "Test Dir:     ${TEST_DIR}"
    
    # test dir
    mkdir -p "${TEST_DIR}"
    
    # test policy
    cat > "${POLICY_FILE}" << 'EOF'
name: "Gauntlet Test Policy"
rules:
  - name: "Has tools"
    expr: "size(input.tools) > 0"
    failure_msg: "Server must expose at least one tool"
  - name: "No high risk tools"
    expr: "!input.tools.exists(t, t.risk_level == 'HIGH')"
    failure_msg: "High risk tools are not allowed"
EOF
    
    check_prereqs
    
    log_phase "0" "Build"
    echo "Building mcptrust binary..."
    
    if (cd "${PROJECT_ROOT}" && go build -o "${BINARY}" ./cmd/mcptrust/main.go); then
        pass "Binary built successfully"
    else
        fail "Binary build failed"
        exit 1
    fi
    
    # check binary
    if [[ -x "${BINARY}" ]]; then
        pass "Binary is executable"
    else
        fail "Binary not found or not executable"
        exit 1
    fi

    # mock server
    echo "Building mock MCP server..."
    if [[ -d "${MOCK_SERVER_DIR}" ]]; then
        if (cd "${MOCK_SERVER_DIR}" && go build -o "${MOCK_SERVER_BINARY}" .); then
            pass "Mock MCP server built"
        else
            fail "Mock MCP server build failed"
            exit 1
        fi
    else
        echo -e "  ${YELLOW}⚠ Mock server directory not found, skipping build${NC}"
    fi
}

# ============================================================================
# Phase 1: Discovery
# ============================================================================

phase_discovery() {
    log_phase "1" "Discovery (scan with fallback)"
    
    local scan_success=false
    
    # try live server first
    if [[ "${MCPTRUST_FORCE_FIXTURE:-}" != "1" ]] && command -v npx &> /dev/null; then
        log_test "Attempting scan with live MCP server"
        SERVER_CMD="npx -y @modelcontextprotocol/server-filesystem /tmp"
        
        if "${BINARY}" scan -p -- "${SERVER_CMD}" > "${TEST_DIR}/scan_output.json" 2>&1; then
            # check output
            if jq empty "${TEST_DIR}/scan_output.json" 2>/dev/null; then
                local tools_count
                tools_count=$(jq '.tools | length' "${TEST_DIR}/scan_output.json" 2>/dev/null || echo "0")
                if [[ "${tools_count}" -gt 0 ]]; then
                    pass "Live MCP server scan succeeded (${tools_count} tools)"
                    scan_success=true
                    USING_MOCK_SERVER=false
                fi
            fi
        fi
        
        if [[ "${scan_success}" != "true" ]]; then
            echo -e "  ${YELLOW}⚠ Live MCP server failed, falling back to mock server${NC}"
        fi
    else
        if [[ "${MCPTRUST_FORCE_FIXTURE:-}" == "1" ]]; then
            echo -e "  ${BLUE}ℹ Fixture mode enabled (MCPTRUST_FORCE_FIXTURE=1) — skipping live MCP server${NC}"
        fi
    fi
    
    # fallback
    if [[ "${scan_success}" != "true" ]]; then
        log_test "Using mock MCP server"
        
        if [[ ! -x "${MOCK_SERVER_BINARY}" ]]; then
            fail "Mock server binary not found at ${MOCK_SERVER_BINARY}"
            return 1
        fi
        
        SERVER_CMD="${MOCK_SERVER_BINARY}"
        USING_MOCK_SERVER=true
        
        if "${BINARY}" scan -p -- "${SERVER_CMD}" > "${TEST_DIR}/scan_output.json" 2>&1; then
            scan_success=true
        else
            fail "Mock MCP server scan failed"
            echo "  Error output:"
            sed 's/^/    /' "${TEST_DIR}/scan_output.json"
            return 1
        fi
    fi
    
    # check: valid json
    log_test "Validating scan output is valid JSON"
    if ! jq empty "${TEST_DIR}/scan_output.json" 2>/dev/null; then
        fail "Scan output is not valid JSON"
        echo "  Output:"
        sed 's/^/    /' "${TEST_DIR}/scan_output.json"
        return 1
    fi
    pass "Scan output is valid JSON"
    
    # check: no error
    log_test "Checking scan has no error"
    local scan_error
    scan_error=$(jq -r '.error // ""' "${TEST_DIR}/scan_output.json")
    if [[ -n "${scan_error}" && "${scan_error}" != "null" ]]; then
        fail "Scan returned error: ${scan_error}"
        echo "  Full output:"
        sed 's/^/    /' "${TEST_DIR}/scan_output.json"
        return 1
    fi
    pass "Scan has no error"
    
    # check: tools > 0
    log_test "Checking scan found tools"
    local tools_count
    tools_count=$(jq '.tools | length' "${TEST_DIR}/scan_output.json")
    if [[ "${tools_count}" -eq 0 ]]; then
        fail "Scan returned 0 tools (server may have failed to start)"
        echo "  Full output:"
        sed 's/^/    /' "${TEST_DIR}/scan_output.json"
        return 1
    fi
    pass "Scan found ${tools_count} tools"
    
    # show server type
    if [[ "${USING_MOCK_SERVER}" == "true" ]]; then
        echo -e "  ${BLUE}ℹ Using deterministic mock server for remaining tests${NC}"
    else
        echo -e "  ${BLUE}ℹ Using live MCP server for remaining tests${NC}"
    fi
    
    echo "  Scan output preview:"
    head -20 "${TEST_DIR}/scan_output.json" | sed 's/^/    /'
}

# ============================================================================
# Phase 2: Governance
# ============================================================================

phase_governance() {
    log_phase "2" "Governance (policy check)"
    
    log_test "Running policy check against MCP server"
    
    if "${BINARY}" policy check --policy "${POLICY_FILE}" -- "${SERVER_CMD}" > "${TEST_DIR}/policy_output.txt" 2>&1; then
        pass "Policy check passed (exit code 0)"
        echo "  Policy output:"
        sed 's/^/    /' "${TEST_DIR}/policy_output.txt"
    else
        # expected: high risk tools fail policy
        local exit_code=$?
        if [[ ${exit_code} -eq 1 ]]; then
            echo -e "  ${YELLOW}⚠ Policy check returned exit 1 (policy violation detected)${NC}"
            echo "  This is expected if the server has high-risk tools."
            pass "Policy engine executed correctly (detected violations)"
        else
            fail "Policy check failed unexpectedly"
        fi
        sed 's/^/    /' "${TEST_DIR}/policy_output.txt"
    fi
}

# ============================================================================
# Phase 3: Persistence
# ============================================================================

phase_persistence() {
    log_phase "3" "Persistence (lock)"
    
    log_test "Creating lockfile from MCP server scan"
    
    # cd to test dir
    pushd "${TEST_DIR}" > /dev/null
    
    if "${BINARY}" lock -- "${SERVER_CMD}" > lock_output.txt 2>&1; then
        pass "Lock command executed successfully"
    else
        fail "Lock command failed"
        sed 's/^/    /' lock_output.txt
    fi
    
    popd > /dev/null
    
    # check lockfile
    log_test "Verifying mcp-lock.json exists"
    if [[ -f "${LOCKFILE}" ]]; then
        pass "mcp-lock.json created"
        echo "  Lockfile preview:"
        head -30 "${LOCKFILE}" | sed 's/^/    /'
    else
        fail "mcp-lock.json not found"
    fi
}

# ============================================================================
# Phase 4: Identity
# ============================================================================

phase_identity() {
    log_phase "4" "Identity (keygen + sign)"
    
    # cd
    pushd "${TEST_DIR}" > /dev/null
    
    log_test "Generating Ed25519 keypair A (primary)"
    if "${BINARY}" keygen --private "${PRIVATE_KEY}" --public "${PUBLIC_KEY}" > keygen_output.txt 2>&1; then
        pass "Keypair A generated"
    else
        fail "Keygen A failed"
        sed 's/^/    /' keygen_output.txt
    fi
    
    # second keypair for negative tests
    log_test "Generating Ed25519 keypair B (for negative tests)"
    if "${BINARY}" keygen --private "${PRIVATE_KEY_B}" --public "${PUBLIC_KEY_B}" > keygen_output_b.txt 2>&1; then
        pass "Keypair B generated"
    else
        fail "Keygen B failed"
        sed 's/^/    /' keygen_output_b.txt
    fi
    
    # check keys
    if [[ -f "${PRIVATE_KEY}" ]] && [[ -f "${PUBLIC_KEY}" ]]; then
        pass "Keypair A files exist"
    else
        fail "Keypair A files not created"
    fi
    
    if [[ -f "${PRIVATE_KEY_B}" ]] && [[ -f "${PUBLIC_KEY_B}" ]]; then
        pass "Keypair B files exist"
    else
        fail "Keypair B files not created"
    fi
    
    log_test "Signing lockfile with keypair A"
    if "${BINARY}" sign --lockfile "${LOCKFILE}" --key "${PRIVATE_KEY}" --output "${SIGNATURE}" > sign_output.txt 2>&1; then
        pass "Lockfile signed"
    else
        fail "Sign command failed"
        sed 's/^/    /' sign_output.txt
    fi
    
    # check sig file
    log_test "Verifying signature file exists"
    if [[ -f "${SIGNATURE}" ]]; then
        pass "mcp-lock.json.sig created"
        echo "  Signature (first 64 chars): $(head -c 64 "${SIGNATURE}")..."
    else
        fail "Signature file not found"
    fi
    
    log_test "Verifying signature is valid with correct key"
    if "${BINARY}" verify --lockfile "${LOCKFILE}" --signature "${SIGNATURE}" --key "${PUBLIC_KEY}" > verify_output.txt 2>&1; then
        pass "Signature verified successfully"
    else
        fail "Initial signature verification failed"
        sed 's/^/    /' verify_output.txt
    fi
    
    popd > /dev/null
}

# ============================================================================
# Phase 5: Distribution
# ============================================================================

phase_distribution() {
    log_phase "5" "Distribution (bundle export)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # copy required files
    cp "${PUBLIC_KEY}" "public.key" 2>/dev/null || true
    cp "${POLICY_FILE}" "policy.yaml" 2>/dev/null || true
    
    log_test "Creating distribution bundle"
    if "${BINARY}" bundle export \
        --lockfile "${LOCKFILE}" \
        --signature "${SIGNATURE}" \
        --output "${BUNDLE_FILE}" > bundle_output.txt 2>&1; then
        pass "Bundle created"
    else
        fail "Bundle export failed"
        sed 's/^/    /' bundle_output.txt
    fi
    
    log_test "Verifying bundle.zip exists"
    if [[ -f "${BUNDLE_FILE}" ]]; then
        pass "bundle.zip created"
        echo "  Bundle contents:"
        unzip -l "${BUNDLE_FILE}" | sed 's/^/    /'
    else
        fail "bundle.zip not found"
    fi
    
    
    popd > /dev/null
}

# ============================================================================
# Phase 5b: Determinism
# ============================================================================

phase_bundle_determinism() {
    log_phase "5b" "Bundle Determinism (Reproducibility)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # rename first bundle
    mv "${BUNDLE_FILE}" "${TEST_DIR}/bundle_run1.zip"
    
    # wait (for clock)
    sleep 2
    
    log_test "Creating second bundle (same inputs)"
    if "${BINARY}" bundle export \
        --lockfile "${LOCKFILE}" \
        --signature "${SIGNATURE}" \
        --output "${TEST_DIR}/bundle_run2.zip" > bundle_run2_output.txt 2>&1; then
        pass "Second bundle created"
    else
        fail "Second bundle export failed"
        sed 's/^/    /' bundle_run2_output.txt
        popd > /dev/null
        return 1
    fi
    
    # compare
    log_test "Comparing bundle hashes"
    local hash1
    hash1=$(hash_file "${TEST_DIR}/bundle_run1.zip")
    local hash2
    hash2=$(hash_file "${TEST_DIR}/bundle_run2.zip")
    
    echo "  Run 1 hash: ${hash1}"
    echo "  Run 2 hash: ${hash2}"
    
    if [[ "${hash1}" == "${hash2}" ]]; then
        pass "Bundles are identical (deterministic)"
        # restore bundle
        cp "${TEST_DIR}/bundle_run1.zip" "${BUNDLE_FILE}"
    else
        fail "Bundles Differ! (Non-deterministic build)"
        # Restore bundle.zip anyway
        cp "${TEST_DIR}/bundle_run1.zip" "${BUNDLE_FILE}"
        popd > /dev/null
        return 1
    fi

    popd > /dev/null
}

# ============================================================================
# Phase 6: Tamper Detection
# ============================================================================

phase_tamper_detection() {
    log_phase "6" "Tamper Detection (THE CRITICAL TEST)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # hash before tamper
    log_test "Computing lockfile hash before tamper"
    local hash_before
    hash_before=$(hash_file "${LOCKFILE}")
    echo "  Hash before tamper: ${hash_before:0:16}..."
    
    # backup
    cp "${LOCKFILE}" "${LOCKFILE}.backup"
    
    # tamper
    log_test "Tampering with mcp-lock.json (modifying a hash)"
    
    python3 - <<'PY'
import json

p = "mcp-lock.json"
with open(p, "r") as f:
    d = json.load(f)

tools = d.get("tools", {})
if not isinstance(tools, dict) or not tools:
    raise SystemExit("no tools found in lockfile to tamper")

tool = sorted(tools.keys())[0]
entry = tools[tool]

h = entry.get("description_hash") or entry.get("input_schema_hash")
if not h or "sha256:" not in h:
    raise SystemExit("no sha256 hash field found to tamper")

prefix = "sha256:"
i = h.index(prefix) + len(prefix)
ch = h[i]
new_ch = "0" if ch != "0" else "1"
new_h = h[:i] + new_ch + h[i+1:]

if "description_hash" in entry:
    entry["description_hash"] = new_h
else:
    entry["input_schema_hash"] = new_h

with open(p, "w") as f:
    json.dump(d, f, indent=2, sort_keys=True)
    f.write("\n")

print(f"tampered tool: {tool} ({ch}->{new_ch})")
PY
    
    # STRICT ASSERTION 2: Compute hash AFTER tamper and verify it changed
    log_test "Verifying file was actually modified"
    local hash_after
    hash_after=$(hash_file "${LOCKFILE}")
    echo "  Hash after tamper:  ${hash_after:0:16}..."
    
    if [[ "${hash_before}" == "${hash_after}" ]]; then
        fail "Tamper did NOT modify the file (hashes are identical)"
        # Restore and return
        mv "${LOCKFILE}.backup" "${LOCKFILE}"
        popd > /dev/null
        return 1
    fi
    pass "File was modified (hashes differ)"
    
    # STRICT ASSERTION 3: Verify MUST fail with exit code 1
    log_test "Running verify on tampered lockfile (MUST FAIL with exit 1)"
    
    set +e  # Temporarily allow failures
    "${BINARY}" verify --lockfile "${LOCKFILE}" --signature "${SIGNATURE}" --key "${PUBLIC_KEY}" > verify_tamper_output.txt 2>&1
    local verify_exit_code=$?
    set -e
    
    echo "  Verify output:"
    sed 's/^/    /' verify_tamper_output.txt
    
    if [[ ${verify_exit_code} -eq 1 ]]; then
        pass "Verify correctly detected tampering (exit code 1)"
    else
        fail "Verify did NOT detect tampering (exit code was ${verify_exit_code}, expected 1)"
        # Restore and return
        mv "${LOCKFILE}.backup" "${LOCKFILE}"
        popd > /dev/null
        return 1
    fi
    
    # STRICT ASSERTION 4: Diff must detect drift (NOT say "No changes detected")
    log_test "Running diff to detect drift"
    
    set +e
    "${BINARY}" diff --lockfile "${LOCKFILE}" -- "${SERVER_CMD}" > diff_output.txt 2>&1
    local diff_exit_code=$?
    set -e
    
    echo "  Diff output:"
    sed 's/^/    /' diff_output.txt
    
    # The diff compares LIVE server vs TAMPERED lockfile
    # Since we only changed hashes (not the actual server), diff should detect schema/description mismatch
    # STRICT: Must NOT contain "No changes detected"
    if grep -q "No changes detected" diff_output.txt; then
        fail "Diff FAILED to detect drift (output contains 'No changes detected')"
        # Restore and return
        mv "${LOCKFILE}.backup" "${LOCKFILE}"
        popd > /dev/null
        return 1
    fi
    
    # STRICT: Diff must exit 1 for drift (canonical exit codes)
    # Exit 0 = no drift, Exit 1 = drift detected, Exit 2+ = runtime error
    if [[ ${diff_exit_code} -eq 1 ]]; then
        pass "Diff correctly detected drift (exit code 1)"
    elif [[ ${diff_exit_code} -eq 2 ]]; then
        fail "Diff returned runtime error (exit code 2) instead of drift"
    else
        fail "Diff did not detect drift (exit code ${diff_exit_code}, expected 1)"
    fi
    
    # Restore original lockfile from backup
    mv "${LOCKFILE}.backup" "${LOCKFILE}"
    echo "  Restored original lockfile"
    
    popd > /dev/null
}

# ============================================================================
# Phase 7: Wrong Key
# ============================================================================

phase_wrong_key_verify() {
    log_phase "7" "NEGATIVE: Wrong Public Key Verify (Identity Failure)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    log_test "Verifying signature with WRONG public key (keypair B)"
    echo "  Lockfile signed with keypair A private key"
    echo "  Attempting verify with keypair B public key"
    
    set +e
    "${BINARY}" verify --lockfile "${LOCKFILE}" --signature "${SIGNATURE}" --key "${PUBLIC_KEY_B}" > verify_wrong_key.txt 2>&1
    local exit_code=$?
    set -e
    
    echo "  Verify output:"
    sed 's/^/    /' verify_wrong_key.txt
    
    if [[ ${exit_code} -eq 1 ]]; then
        pass "Correctly rejected wrong public key (exit code 1)"
    else
        fail "SECURITY ISSUE: Accepted wrong public key! (exit code ${exit_code}, expected 1)"
    fi
    
    popd > /dev/null
}

# ============================================================================
# Phase 8: Corrupted Signature
# ============================================================================

phase_corrupted_signature() {
    log_phase "8" "NEGATIVE: Corrupted Signature File (Integrity Failure)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # backup
    cp "${SIGNATURE}" "${SIGNATURE}.backup"
    
    # corrupt
    log_test "Corrupting signature file (flipping first hex nibble)"
    
    python3 -c "
import sys
path = '${SIGNATURE}'
with open(path, 'r') as f:
    content = f.read().strip()

if not content:
    sys.exit(1)

# Flip first char
first = content[0]
if first == '0':
    new_first = '1'
elif first == 'a':
    new_first = 'b'
else:
    new_first = '0'

new_content = new_first + content[1:]

with open(path, 'w') as f:
    f.write(new_content)
print(f'  Flip: {first} -> {new_first}')
"

    local sig_prefix
    sig_prefix=$(head -c 16 "${SIGNATURE}")
    echo "  Corrupted sig prefix: ${sig_prefix}..."
    
    set +e
    "${BINARY}" verify --lockfile "${LOCKFILE}" --signature "${SIGNATURE}" --key "${PUBLIC_KEY}" > verify_bad_sig.txt 2>&1
    local exit_code=$?
    set -e
    
    echo "  Verify output:"
    sed 's/^/    /' verify_bad_sig.txt
    
    if [[ ${exit_code} -eq 1 ]]; then
        pass "Correctly rejected corrupted signature (exit code 1)"
    else
        fail "SECURITY ISSUE: Accepted corrupted signature! (exit code ${exit_code}, expected 1)"
    fi
    
    # restore
    mv "${SIGNATURE}.backup" "${SIGNATURE}"
    echo "  Restored original signature"
    
    popd > /dev/null
}

# ============================================================================
# Phase 9: Corrupted Key
# ============================================================================

phase_corrupted_pubkey() {
    log_phase "9" "NEGATIVE: Corrupted Public Key File (Format Failure)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # backup
    cp "${PUBLIC_KEY}" "${PUBLIC_KEY}.backup"
    
    # truncate
    log_test "Corrupting public key file (truncating)"
    head -c 10 "${PUBLIC_KEY}.backup" > "${PUBLIC_KEY}"
    
    echo "  Original key size: $(wc -c < "${PUBLIC_KEY}.backup") bytes"
    echo "  Corrupted key size: $(wc -c < "${PUBLIC_KEY}") bytes"
    
    set +e
    "${BINARY}" verify --lockfile "${LOCKFILE}" --signature "${SIGNATURE}" --key "${PUBLIC_KEY}" > verify_bad_pubkey.txt 2>&1
    local exit_code=$?
    set -e
    
    echo "  Verify output:"
    sed 's/^/    /' verify_bad_pubkey.txt
    
    if [[ ${exit_code} -ne 0 ]]; then
        pass "Correctly rejected corrupted public key (exit code ${exit_code})"
    else
        fail "SECURITY ISSUE: Accepted corrupted public key! (exit code 0)"
    fi
    
    # restore
    mv "${PUBLIC_KEY}.backup" "${PUBLIC_KEY}"
    echo "  Restored original public key"
    
    popd > /dev/null
}

# ============================================================================
# Phase 10: Policy Fail
# ============================================================================

phase_policy_fail() {
    log_phase "10" "NEGATIVE: Policy Fail Path (Governance Failure)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # impossible policy
    log_test "Creating impossible policy (size(input.tools) > 9999)"
    cat > "${TEST_DIR}/impossible_policy.yaml" << 'EOF'
name: "Impossible Policy"
rules:
  - name: "Impossible tool count"
    expr: "size(input.tools) > 9999"
    failure_msg: "Server must have more than 9999 tools (impossible)"
EOF
    
    set +e
    "${BINARY}" policy check --policy "${TEST_DIR}/impossible_policy.yaml" -- "${SERVER_CMD}" > policy_fail_output.txt 2>&1
    local exit_code=$?
    set -e
    
    echo "  Policy output:"
    sed 's/^/    /' policy_fail_output.txt
    
    if [[ ${exit_code} -eq 1 ]]; then
        pass "Policy correctly failed for impossible condition (exit code 1)"
    else
        fail "Policy did not fail as expected (exit code ${exit_code}, expected 1)"
    fi
    
    # check for failure msg
    if grep -q -i "fail\|impossible\|9999" policy_fail_output.txt; then
        pass "Failure message contains expected keywords"
    else
        echo -e "  ${YELLOW}⚠ Failure message may not clearly indicate the issue${NC}"
    fi
    
    popd > /dev/null
}

# ============================================================================
# Phase 11: Bundle Integrity
# ============================================================================

phase_bundle_integrity() {
    log_phase "11" "Bundle Integrity Verification (Distribution Assurance)"
    
    pushd "${TEST_DIR}" > /dev/null
    
    # extract dir
    local extract_dir="${TEST_DIR}/bundle_extract"
    mkdir -p "${extract_dir}"
    
    log_test "Extracting bundle.zip"
    if unzip -o "${BUNDLE_FILE}" -d "${extract_dir}" > /dev/null 2>&1; then
        pass "Bundle extracted successfully"
        echo "  Extracted contents:"
        find "${extract_dir}" -maxdepth 1 -mindepth 1 -exec ls -ld {} + | sed 's/^/    /'
    else
        fail "Bundle extraction failed"
        popd > /dev/null
        return 1
    fi
    
    # verify
    log_test "Verifying integrity of extracted bundle (should PASS)"
    
    local extracted_lockfile="${extract_dir}/mcp-lock.json"
    local extracted_sig="${extract_dir}/mcp-lock.json.sig"
    local extracted_pubkey="${extract_dir}/public.key"
    
    # check files
    if [[ ! -f "${extracted_lockfile}" ]]; then
        fail "Extracted lockfile not found"
        popd > /dev/null
        return 1
    fi
    
    if [[ ! -f "${extracted_sig}" ]]; then
        fail "Extracted signature not found"
        popd > /dev/null
        return 1
    fi
    
    if [[ -f "${extracted_pubkey}" ]]; then
        set +e
        "${BINARY}" verify --lockfile "${extracted_lockfile}" --signature "${extracted_sig}" --key "${extracted_pubkey}" > bundle_verify_pass.txt 2>&1
        local exit_code=$?
        set -e
        
        echo "  Verify output:"
        sed 's/^/    /' bundle_verify_pass.txt
        
        if [[ ${exit_code} -eq 0 ]]; then
            pass "Intact bundle verified successfully"
        else
            fail "Intact bundle verification failed unexpectedly (exit code ${exit_code})"
        fi
    else
        echo -e "  ${YELLOW}⚠ No public.key in bundle, skipping positive verification${NC}"
        # Use the original public key for verification
        set +e
        "${BINARY}" verify --lockfile "${extracted_lockfile}" --signature "${extracted_sig}" --key "${PUBLIC_KEY}" > bundle_verify_pass.txt 2>&1
        local exit_code=$?
        set -e
        
        if [[ ${exit_code} -eq 0 ]]; then
            pass "Intact bundle verified with original public key"
        else
            fail "Intact bundle verification failed"
        fi
    fi
    
    # Now tamper with extracted lockfile and verify it fails
    log_test "Tampering with extracted lockfile (should FAIL verify)"
    
    local hash_before
    hash_before=$(hash_file "${extracted_lockfile}")
    
    # tamper lockfile
    python3 -c "
import json
import sys

p = '${extracted_lockfile}'
try:
    with open(p, 'r') as f:
        d = json.load(f)
    
    tools = d.get('tools', {})
    if not isinstance(tools, dict) or not tools:
        print('INTERNAL: no tools found')
        sys.exit(0)
        
    tool = sorted(tools.keys())[0]
    entry = tools[tool]
    
    key = 'description_hash'
    if key not in entry:
        key = 'input_schema_hash'
    
    if key in entry:
        h = entry[key]
        if 'sha256:' in h:
            prefix = 'sha256:'
            idx = h.index(prefix) + len(prefix)
            orig_char = h[idx]
            new_char = '0' if orig_char != '0' else '1'
            new_h = h[:idx] + new_char + h[idx+1:]
            entry[key] = new_h
            
            with open(p, 'w') as f:
                json.dump(d, f, indent=2, sort_keys=True)
                f.write('\n')
            print(f'Tampered {key} for {tool}')
except Exception as e:
    print(f'Error: {e}')
    sys.exit(1)
"

    local hash_after
    hash_after=$(hash_file "${extracted_lockfile}")
    
    echo "  Hash before tamper: ${hash_before:0:16}..."
    echo "  Hash after tamper:  ${hash_after:0:16}..."
    
    local verify_key="${extracted_pubkey}"
    if [[ ! -f "${verify_key}" ]]; then
        verify_key="${PUBLIC_KEY}"
    fi
    
    set +e
    "${BINARY}" verify --lockfile "${extracted_lockfile}" --signature "${extracted_sig}" --key "${verify_key}" > bundle_verify_fail.txt 2>&1
    local tamper_exit_code=$?
    set -e
    
    echo "  Verify output after tamper:"
    sed 's/^/    /' bundle_verify_fail.txt
    
    if [[ ${tamper_exit_code} -eq 1 ]]; then
        pass "Tampered bundle correctly rejected (exit code 1)"
    else
        fail "SECURITY ISSUE: Tampered bundle accepted! (exit code ${tamper_exit_code}, expected 1)"
    fi
    
    popd > /dev/null
}

# ============================================================================
# Summary
# ============================================================================

summary() {
    log_header "Test Summary"
    
    local total=$((TESTS_PASSED + TESTS_FAILED))
    
    echo "  Total Tests:  ${total}"
    echo -e "  ${GREEN}Passed:${NC}       ${TESTS_PASSED}"
    echo -e "  ${RED}Failed:${NC}       ${TESTS_FAILED}"
    echo ""
    
    if [[ "${USING_MOCK_SERVER}" == "true" ]]; then
        echo -e "  ${BLUE}ℹ Tests ran with mock MCP server (deterministic)${NC}"
    else
        echo -e "  ${BLUE}ℹ Tests ran with live MCP server${NC}"
    fi
    echo ""
    
    if [[ ${TESTS_FAILED} -eq 0 ]]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    ALL TESTS PASSED! 🎉                           ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        return 0
    else
        echo -e "${RED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                    SOME TESTS FAILED! ⚠️                           ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    trap cleanup EXIT
    
    setup
    
    # Core lifecycle tests
    phase_discovery
    phase_governance
    phase_persistence
    phase_identity
    phase_distribution
    phase_bundle_determinism
    phase_tamper_detection
    
    # Negative tests (security validation)
    phase_wrong_key_verify
    phase_corrupted_signature
    phase_corrupted_pubkey
    phase_policy_fail
    phase_bundle_integrity
    
    summary
}

main "$@"
