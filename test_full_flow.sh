#!/usr/bin/env bash
#
# test_full_flow.sh — End-to-end test: register then login
#
# Generates a unique username so the test is idempotent.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate a unique username
USERNAME="testuser_$(date +%s)_$$"

echo "============================================"
echo "  WebAuthn.io Full Flow Test"
echo "  Username: ${USERNAME}"
echo "============================================"
echo ""

# Clean keystore for a fresh test
export WEBAUTHN_KEYSTORE="${SCRIPT_DIR}/keystore_test_$$"
mkdir -p "$WEBAUTHN_KEYSTORE"

cleanup() {
    rm -rf "$WEBAUTHN_KEYSTORE"
}
trap cleanup EXIT

echo "=== PHASE 1: REGISTRATION ==="
echo ""
"${SCRIPT_DIR}/webauthn_client.sh" register "$USERNAME"

echo ""
echo "=== PHASE 2: AUTHENTICATION ==="
echo ""
"${SCRIPT_DIR}/webauthn_client.sh" login "$USERNAME"

echo ""
echo "============================================"
echo "  ALL TESTS PASSED ✓"
echo "============================================"
