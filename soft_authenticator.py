#!/usr/bin/env python3
"""
Software FIDO2/WebAuthn Authenticator

Implements a minimal CTAP2-like authenticator in software.
Private keys are stored in plaintext JSON files.

Supports:
  - makeCredential (registration)
  - getAssertion (authentication)

Key concepts:
  - Each credential has an EC P-256 key pair
  - Attestation is "none" (self-attestation / surrogate)
  - Credential IDs are random 32-byte identifiers
  - The authenticator data (authData) is constructed per the WebAuthn spec
"""

import json
import sys
import os
import hashlib
import struct
import secrets
import base64
import hmac
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import cbor2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

KEYSTORE_DIR = Path(os.environ.get("WEBAUTHN_KEYSTORE", "./keystore"))


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encode_public_key_cose(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Encode an EC P-256 public key in COSE_Key format (CBOR map).
    
    COSE Key parameters for EC2:
      1 (kty):  2  (EC2)
      3 (alg): -7  (ES256)
     -1 (crv):  1  (P-256)
     -2 (x):   x-coordinate bytes (32 bytes)
     -3 (y):   y-coordinate bytes (32 bytes)
    """
    numbers = public_key.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    cose_key = {
        1: 2,      # kty: EC2
        3: -7,     # alg: ES256
        -1: 1,     # crv: P-256
        -2: x,     # x
        -3: y,     # y
    }
    return cbor2.dumps(cose_key)


# ---------------------------------------------------------------------------
# Authenticator Data construction
# See: /fwd?q=aHR0cHM6Ly93d3cudzMub3JnL1RSL3dlYmF1dGhuLTIvI3NjdG4tYXV0aGVudGljYXRvci1kYXRh
# ---------------------------------------------------------------------------

def build_auth_data_register(
    rp_id_hash: bytes,
    credential_id: bytes,
    public_key: ec.EllipticCurvePublicKey,
    sign_count: int = 0,
) -> bytes:
    """
    Build authenticatorData for a registration (makeCredential) response.

    Layout:
      rpIdHash (32) | flags (1) | signCount (4) | attestedCredentialData (variable)

    attestedCredentialData:
      aaguid (16) | credIdLen (2) | credentialId (credIdLen) | credentialPublicKey (CBOR)

    Flags:
      bit 0 (UP) = 1   (user present)
      bit 2 (UV) = 1   (user verified — we're a software token, we say yes)
      bit 6 (AT) = 1   (attested credential data included)
      => 0b01000101 = 0x45
    """
    flags = 0x45  # UP + UV + AT
    sign_count_bytes = struct.pack(">I", sign_count)

    # AAGUID: 16 zero bytes for a non-certified authenticator
    aaguid = b"\x00" * 16

    cred_id_len = struct.pack(">H", len(credential_id))
    cose_pub = encode_public_key_cose(public_key)

    attested_cred_data = aaguid + cred_id_len + credential_id + cose_pub

    auth_data = rp_id_hash + bytes([flags]) + sign_count_bytes + attested_cred_data
    return auth_data


def build_auth_data_authenticate(
    rp_id_hash: bytes,
    sign_count: int = 1,
) -> bytes:
    """
    Build authenticatorData for an authentication (getAssertion) response.

    Layout:
      rpIdHash (32) | flags (1) | signCount (4)

    Flags:
      bit 0 (UP) = 1
      bit 2 (UV) = 1
      => 0b00000101 = 0x05
    """
    flags = 0x05  # UP + UV
    sign_count_bytes = struct.pack(">I", sign_count)
    return rp_id_hash + bytes([flags]) + sign_count_bytes


# ---------------------------------------------------------------------------
# Attestation Object (for registration)
# See: /fwd?q=aHR0cHM6Ly93d3cudzMub3JnL1RSL3dlYmF1dGhuLQ==2/#sctn-attestation
# ---------------------------------------------------------------------------

def build_attestation_object_none(auth_data: bytes) -> bytes:
    """
    Build an attestation object with fmt="none".
    
    This is the simplest attestation format — the relying party
    doesn't get a cryptographic proof of the authenticator's identity,
    just the credential public key.
    
    Structure (CBOR map):
      "fmt":      "none"
      "attStmt":  {}  (empty map)
      "authData": <raw bytes>
    """
    att_obj = {
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    }
    return cbor2.dumps(att_obj)


# ---------------------------------------------------------------------------
# Key storage (plaintext JSON + PEM)
# ---------------------------------------------------------------------------

def _ensure_keystore():
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)


def _cred_path(cred_id_b64: str) -> Path:
    """Path for storing credential metadata."""
    # Use a safe filename derived from the credential ID
    safe = cred_id_b64.replace("/", "_").replace("+", "-")
    return KEYSTORE_DIR / f"{safe}.json"


def _key_path(cred_id_b64: str) -> Path:
    safe = cred_id_b64.replace("/", "_").replace("+", "-")
    return KEYSTORE_DIR / f"{safe}.pem"


def store_credential(
    rp_id: str,
    user_id: str,
    username: str,
    credential_id: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    sign_count: int = 0,
):
    """Save a credential to the keystore in plaintext."""
    _ensure_keystore()
    cred_id_b64 = b64url_encode(credential_id)

    meta = {
        "rp_id": rp_id,
        "user_id": user_id,
        "username": username,
        "credential_id_b64url": cred_id_b64,
        "sign_count": sign_count,
    }
    with open(_cred_path(cred_id_b64), "w") as f:
        json.dump(meta, f, indent=2)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(_key_path(cred_id_b64), "wb") as f:
        f.write(pem)

    # Also maintain an index by (rp_id, username) for easy lookup
    index_path = KEYSTORE_DIR / "index.json"
    index = {}
    if index_path.exists():
        with open(index_path) as f:
            index = json.load(f)
    key = f"{rp_id}:{username}"
    if key not in index:
        index[key] = []
    if cred_id_b64 not in index[key]:
        index[key].append(cred_id_b64)
    with open(index_path, "w") as f:
        json.dump(index, f, indent=2)


def load_credential(cred_id_b64: str):
    """Load credential metadata and private key."""
    meta_path = _cred_path(cred_id_b64)
    key_path = _key_path(cred_id_b64)
    if not meta_path.exists():
        raise FileNotFoundError(f"No credential found: {cred_id_b64}")

    with open(meta_path) as f:
        meta = json.load(f)
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    return meta, private_key


def find_credentials(rp_id: str, allow_credentials=None):
    """
    Find stored credentials for a given RP.
    If allow_credentials is provided (list of b64url cred IDs), filter to those.
    """
    _ensure_keystore()
    index_path = KEYSTORE_DIR / "index.json"
    if not index_path.exists():
        return []

    with open(index_path) as f:
        index = json.load(f)

    results = []
    for key, cred_ids in index.items():
        stored_rp_id = key.split(":", 1)[0]
        if stored_rp_id == rp_id:
            for cid in cred_ids:
                if allow_credentials is None or cid in allow_credentials:
                    try:
                        meta, pk = load_credential(cid)
                        results.append((meta, pk))
                    except FileNotFoundError:
                        pass
    return results


def increment_sign_count(cred_id_b64: str) -> int:
    """Increment and return the new sign count."""
    meta_path = _cred_path(cred_id_b64)
    with open(meta_path) as f:
        meta = json.load(f)
    meta["sign_count"] = meta.get("sign_count", 0) + 1
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return meta["sign_count"]


# ---------------------------------------------------------------------------
# makeCredential — called during registration
# ---------------------------------------------------------------------------

def make_credential(options_json: str) -> str:
    """
    Process a WebAuthn registration options JSON (from the server) and produce
    a registration response JSON suitable for posting to /registration/verification.

    Input: JSON string containing the PublicKeyCredentialCreationOptions
    Output: JSON string containing the credential response

    Steps:
      1. Parse the options (challenge, rp, user, pubKeyCredParams, etc.)
      2. Generate a new EC P-256 key pair
      3. Generate a random credential ID
      4. Build authenticator data (with attested credential data)
      5. Build attestation object (fmt=none)
      6. Construct the response in the format the server expects
      7. Store the private key in plaintext
    """
    options = json.loads(options_json)

    # The server may wrap the actual options in a key like "publicKey"
    if "publicKey" in options:
        opts = options["publicKey"]
    else:
        opts = options

    rp_id = opts["rp"]["id"]
    rp_name = opts["rp"].get("name", rp_id)

    user = opts["user"]
    user_id_b64 = user["id"]  # already base64url
    user_name = user.get("name", "unknown")
    user_display = user.get("displayName", user_name)

    challenge_b64 = opts["challenge"]
    challenge = b64url_decode(challenge_b64)

    # Check that ES256 (alg=-7) is in the allowed algorithms
    supported = False
    for param in opts.get("pubKeyCredParams", []):
        if param.get("alg") == -7 and param.get("type") == "public-key":
            supported = True
            break
    if not supported:
        # Fall back — try anyway with ES256
        print("Warning: ES256 not explicitly listed, proceeding anyway", file=sys.stderr)

    # Exclude credentials we already have (if server requests it)
    exclude_ids = set()
    for exc in opts.get("excludeCredentials", []):
        exclude_ids.add(exc["id"])

    # Generate key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Generate credential ID (random 32 bytes)
    credential_id = secrets.token_bytes(32)
    credential_id_b64 = b64url_encode(credential_id)

    # Make sure we're not colliding with excluded credentials
    if credential_id_b64 in exclude_ids:
        # Astronomically unlikely, but handle it
        credential_id = secrets.token_bytes(32)
        credential_id_b64 = b64url_encode(credential_id)

    # Build authenticator data
    rp_id_hash = sha256(rp_id.encode("utf-8"))
    auth_data = build_auth_data_register(rp_id_hash, credential_id, public_key, sign_count=0)

    # Build attestation object (none attestation)
    att_obj = build_attestation_object_none(auth_data)

    # Build clientDataJSON
    # This is what the browser would normally construct
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge_b64,
        "origin": f"https://webauthn.io",
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

    # Store credential
    store_credential(
        rp_id=rp_id,
        user_id=user_id_b64,
        username=user_name,
        credential_id=credential_id,
        private_key=private_key,
        sign_count=0,
    )

    # Build the response in the format webauthn.io expects
    # webauthn.io (go-webauthn library) expects a JSON like:
    # {
    #   "id": <base64url credential id>,
    #   "rawId": <base64url credential id>,
    #   "type": "public-key",
    #   "response": {
    #     "attestationObject": <base64url>,
    #     "clientDataJSON": <base64url>
    #   }
    # }
    response = {
        "username": user_name,
        "response": {
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "attestationObject": b64url_encode(att_obj),
                #"authenticatorData": b64url_encode(auth_data), # 不需要，在attestationObject里已经有了，但Matthew做了就按这样填好了
                "clientDataJSON": b64url_encode(client_data_json),
                #"publicKey": b64url_encode(encode_public_key_cose(public_key)), #不一定对
                #"publicKeyAlgorithm": -7,
                },
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
    }

    return json.dumps(response)


# ---------------------------------------------------------------------------
# getAssertion — called during authentication
# ---------------------------------------------------------------------------

def get_assertion(options_json: str) -> str:
    """
    Process a WebAuthn authentication options JSON (from the server) and produce
    an authentication response JSON suitable for posting to /authentication/verification.

    Input: JSON string containing the PublicKeyCredentialRequestOptions
    Output: JSON string containing the assertion response

    Steps:
      1. Parse options (challenge, rpId, allowCredentials, etc.)
      2. Find matching stored credential
      3. Build authenticator data (without attested credential data)
      4. Build clientDataJSON
      5. Sign (authData || sha256(clientDataJSON)) with the stored private key
      6. Return the assertion response
    """
    options = json.loads(options_json)

    if "publicKey" in options:
        opts = options["publicKey"]
    else:
        opts = options

    rp_id = opts.get("rpId", "webauthn.io")
    challenge_b64 = opts["challenge"]
    challenge = b64url_decode(challenge_b64)

    # Collect allowed credential IDs
    allow_list = []
    for cred in opts.get("allowCredentials", []):
        allow_list.append(cred["id"])

    # Find a matching credential in our store
    if allow_list:
        credentials = find_credentials(rp_id, allow_credentials=allow_list)
    else:
        credentials = find_credentials(rp_id)

    if not credentials:
        print("Error: No matching credentials found in keystore", file=sys.stderr)
        sys.exit(1)

    # Use the first matching credential
    meta, private_key = credentials[0]
    credential_id_b64 = meta["credential_id_b64url"]
    credential_id = b64url_decode(credential_id_b64)

    # Increment sign count
    sign_count = increment_sign_count(credential_id_b64)

    # Build authenticator data
    rp_id_hash = sha256(rp_id.encode("utf-8"))
    auth_data = build_auth_data_authenticate(rp_id_hash, sign_count=sign_count)

    # Build clientDataJSON
    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": f"/fwd?q=aHR0cHM6Ly97cnBfaWR9",
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

    # Sign: signature is over (authData || sha256(clientDataJSON))
    client_data_hash = sha256(client_data_json)
    signed_data = auth_data + client_data_hash

    signature_der = private_key.sign(
        signed_data,
        ec.ECDSA(hashes.SHA256()),
    )

    # Build the response
    # The server expects userHandle to be the user.id from registration
    user_handle_b64 = meta.get("user_id", "")

    response = {
        "username": user_name,
        "response": {
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "authenticatorData": b64url_encode(auth_data),
                "clientDataJSON": b64url_encode(client_data_json),
                "signature": b64url_encode(signature_der),
                "userHandle": user_handle_b64,
                },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        },
    }

    return json.dumps(response)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """
    Usage:
      python soft_authenticator.py make_credential '<options_json>'
      python soft_authenticator.py get_assertion '<options_json>'

    Or read from a file:
      python soft_authenticator.py make_credential @options.json
      python soft_authenticator.py get_assertion @options.json
    """
    if len(sys.argv) < 3:
        print("Usage: soft_authenticator.py <make_credential|get_assertion> <json_or_@file>",
              file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    arg = sys.argv[2]

    # Read input
    if arg.startswith("@"):
        filepath = arg[1:]
        if filepath == "-":
            input_json = sys.stdin.read()
        else:
            with open(filepath) as f:
                input_json = f.read()
    else:
        input_json = arg

    if command == "make_credential":
        result = make_credential(input_json)
    elif command == "get_assertion":
        result = get_assertion(input_json)
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)

    print(result)


if __name__ == "__main__":
    main()
