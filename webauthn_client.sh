#!/usr/bin/env bash
#
# webauthn_client.sh — Register and log in to /fwd?q=aHR0cHM6Ly93ZWJhdXRobi5pbw==
#                      using curl + a Python software authenticator
#
# Usage:
#   ./webauthn_client.sh register <username>
#   ./webauthn_client.sh login <username>
#
# Requirements:
#   - curl
#   - python3 with: cryptography, cbor2
#   - jq (for pretty-printing; optional but helpful)
#
# The 4 endpoints:
#   Registration:
#     1. POST /registration/options   → get challenge + creation options
#     2. POST /registration/verification → send credential back
#   Authentication:
#     3. POST /authentication/options  → get challenge + request options
#     4. POST /authentication/verification → send assertion back
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_URL="https://webauthn.io"
#COOKIE_JAR="$(mktemp)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_AUTH="${SCRIPT_DIR}/soft_authenticator.py"
COOKIE_JAR="${SCRIPT_DIR}/cookiejar"

# Cleanup on exit
#trap 'rm -f "$COOKIE_JAR"' EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_err() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

pretty_json() {
    if command -v jq &>/dev/null; then
        jq '.'
    else
        cat
    fi
}

# Check dependencies
check_deps() {
    local missing=()
    command -v curl &>/dev/null   || missing+=("curl")
    command -v python3 &>/dev/null || missing+=("python3")

    if [ ${#missing[@]} -ne 0 ]; then
        log_err "Missing dependencies: ${missing[*]}"
        exit 1
    fi

    # Check Python packages
    python3 -c "import cryptography, cbor2" 2>/dev/null || {
        log_err "Missing Python packages. Run: pip install cryptography cbor2"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Registration flow
# ---------------------------------------------------------------------------

do_register() {
    local username="$1"
    log_step "Starting registration for user: ${username}"

    # ------------------------------------------------------------------
    # Step 1: POST /registration/options
    #   Request body (JSON):
    #     { "username": "<username>",
    #       "userVerification": "preferred",
    #       "attestationType": "none",
    #       "attachment": "platform" }
    #
    #   Response: PublicKeyCredentialCreationOptions (JSON)
    #     Contains: challenge, rp, user, pubKeyCredParams, timeout, etc.
    # ------------------------------------------------------------------
    log_step "1/2: Requesting registration options from server..."

    local reg_options_request
    reg_options_request=$(cat <<EOF
{
    "username": "${username}",
    "user_verification": "preferred",
    "attestation": "none",
    "attachment": "all",
    "algorithms": [
        "ed25519",
        "es256",
        "rs256"
    ],
    "discoverable_credential": "preferred",
    "hints": []
}
EOF
    )

    log_info "Request body:"
    echo "$reg_options_request" | pretty_json

    local reg_options_response
    reg_options_response=$(curl -s -X POST \
        "${BASE_URL}/registration/options" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -b "$COOKIE_JAR" \
        -d "$reg_options_request")

    local http_status
    # Check if we got a valid JSON response
    if ! echo "$reg_options_response" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_err "Server returned invalid JSON:"
        echo "$reg_options_response"
        exit 1
    fi

    log_ok "Received registration options from server"
    log_info "Server response (options):"
    echo "$reg_options_response" | pretty_json

    # Extract some info for display
    local challenge
    challenge=$(echo "$reg_options_response" | python3 -c "
import sys, json
opts = json.load(sys.stdin)
pub = opts.get('publicKey', opts)
print(pub.get('challenge', 'N/A'))
" 2>/dev/null || echo "N/A")
    log_info "Challenge: ${challenge}"

    # ------------------------------------------------------------------
    # Step 2: Run software authenticator to create credential
    #   The Python script:
    #     - Parses the creation options
    #     - Generates an EC P-256 key pair
    #     - Creates a credential ID
    #     - Builds authenticatorData + attestationObject
    #     - Builds clientDataJSON
    #     - Stores the private key in ./keystore/
    #     - Returns the credential response JSON
    # ------------------------------------------------------------------
    log_step "Running software authenticator (makeCredential)..."

    local credential_response
    credential_response=$(python3 "$PYTHON_AUTH" make_credential "$reg_options_response")

    if [ -z "$credential_response" ]; then
        log_err "Software authenticator failed to produce a response"
        exit 1
    fi

    log_ok "Software authenticator created credential"
    log_info "Credential response:"
    echo "$credential_response" | pretty_json

    # ------------------------------------------------------------------
    # Step 3: POST /registration/verification
    #   Request body: the credential response JSON from the authenticator
    #   Response: { "verified": true/false }
    # ------------------------------------------------------------------
    log_step "2/2: Sending credential to server for verification..."

    local verify_response
    verify_response=$(curl -s -X POST \
        "${BASE_URL}/registration/verification" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -b "$COOKIE_JAR" \
        -d "$credential_response")

    log_info "Server verification response:"
    echo "$verify_response" | pretty_json

    # Check result
    local verified
    verified=$(echo "$verify_response" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
# The go-webauthn library may return different structures
# Commonly: {\"verified\": true} or just check for error
if 'verified' in resp:
    print('true' if resp['verified'] else 'false')
elif 'error' in resp:
    print('false')
else:
    # If we got here without error, likely success
    print('maybe')
" 2>/dev/null || echo "unknown")

    if [ "$verified" = "true" ]; then
        log_ok "Registration successful! ✓"
    elif [ "$verified" = "false" ]; then
        log_err "Registration FAILED. Server rejected our credential."
        exit 1
    else
        log_info "Server response (check manually if registration succeeded):"
        echo "$verify_response" | pretty_json
    fi
}

# ---------------------------------------------------------------------------
# Authentication flow
# ---------------------------------------------------------------------------

do_login() {
    local username="$1"
    log_step "Starting authentication for user: ${username}"

    # ------------------------------------------------------------------
    # Step 1: POST /authentication/options
    #   Request body:
    #     { "username": "<username>",
    #       "userVerification": "preferred" }
    #
    #   Response: PublicKeyCredentialRequestOptions (JSON)
    #     Contains: challenge, rpId, allowCredentials, timeout, etc.
    # ------------------------------------------------------------------
    log_step "1/2: Requesting authentication options from server..."

    local auth_options_request
    auth_options_request=$(cat <<EOF
{
    "hints": [],
    "user_verification": "preferred",
    "username": "${username}"
}
EOF
    )

    log_info "Request body:"
    echo "$auth_options_request" | pretty_json

    local auth_options_response
    auth_options_response=$(curl -s -X POST \
        "${BASE_URL}/authentication/options" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -b "$COOKIE_JAR" \
        -d "$auth_options_request")

    # Validate
    if ! echo "$auth_options_response" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        log_err "Server returned invalid JSON:"
        echo "$auth_options_response"
        exit 1
    fi

    log_ok "Received authentication options from server"
    log_info "Server response (options):"
    echo "$auth_options_response" | pretty_json

    # Check for errors (e.g., user not found)
    local has_error
    has_error=$(echo "$auth_options_response" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
if 'error' in resp or 'message' in resp:
    print(resp.get('error', resp.get('message', '')))
else:
    print('')
" 2>/dev/null || echo "")

    if [ -n "$has_error" ]; then
        log_err "Server error: ${has_error}"
        exit 1
    fi

    # ------------------------------------------------------------------
    # Step 2: Run software authenticator to create assertion
    #   The Python script:
    #     - Parses the request options
    #     - Finds the matching stored credential
    #     - Builds authenticatorData
    #     - Builds clientDataJSON
    #     - Signs (authData || hash(clientDataJSON))
    #     - Returns the assertion response JSON
    # ------------------------------------------------------------------
    log_step "Running software authenticator (getAssertion)..."

    local assertion_response
    assertion_response=$(python3 "$PYTHON_AUTH" get_assertion "$auth_options_response")

    if [ -z "$assertion_response" ]; then
        log_err "Software authenticator failed to produce a response"
        exit 1
    fi

    log_ok "Software authenticator created assertion"
    log_info "Assertion response:"
    echo "$assertion_response" | pretty_json

    # ------------------------------------------------------------------
    # Step 3: POST /authentication/verification
    #   Request body: the assertion response JSON from the authenticator
    #   Response: { "verified": true/false }
    # ------------------------------------------------------------------
    log_step "2/2: Sending assertion to server for verification..."

    local verify_response
    verify_response=$(curl -s -X POST \
        "${BASE_URL}/authentication/verification" \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        -b "$COOKIE_JAR" \
        -d "$assertion_response")

    log_info "Server verification response:"
    echo "$verify_response" | pretty_json

    # Check result
    local verified
    verified=$(echo "$verify_response" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
if 'verified' in resp:
    print('true' if resp['verified'] else 'false')
elif 'error' in resp:
    print('false')
else:
    print('maybe')
" 2>/dev/null || echo "unknown")

    if [ "$verified" = "true" ]; then
        log_ok "Authentication successful! ✓"
    elif [ "$verified" = "false" ]; then
        log_err "Authentication FAILED. Server rejected our assertion."
        exit 1
    else
        log_info "Server response (check manually if auth succeeded):"
        echo "$verify_response" | pretty_json
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    check_deps

    if [ $# -lt 2 ]; then
        echo "Usage: $0 <register|login> <username>"
        echo ""
        echo "Examples:"
        echo "  $0 register testuser123"
        echo "  $0 login testuser123"
        echo ""
        echo "Environment variables:"
        echo "  WEBAUTHN_KEYSTORE  Directory for key storage (default: ./keystore)"
        exit 1
    fi

    local command="$1"
    local username="$2"

    case "$command" in
        register)
            do_register "$username"
            ;;
        login)
            do_login "$username"
            ;;
        *)
            log_err "Unknown command: $command"
            echo "Use 'register' or 'login'"
            exit 1
            ;;
    esac
}

main "$@"
