#!/usr/bin/env python3
"""
Attested Software FIDO2/WebAuthn Authenticator

Extends the soft authenticator with "packed" attestation support:
  - Self-signed attestation certificate generation
  - CSR generation for obtaining a real attestation certificate
  - macOS Keychain import of attestation certificates

Attestation format: "packed" (with full attestation statement)
See: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation

Usage:
  # Generate a self-signed attestation certificate
  python attested_soft_authenticator.py gen-self-signed [--aaguid AAGUID] [--cn NAME] [--out-dir DIR]

  # Generate a CSR for a real attestation certificate
  python attested_soft_authenticator.py gen-csr [--aaguid AAGUID] [--cn NAME] [--out-dir DIR]

  # Import attestation certificate into macOS Keychain
  python attested_soft_authenticator.py import-keychain [--cert FILE] [--keychain NAME]

  # Registration (makeCredential) with packed attestation
  python attested_soft_authenticator.py make_credential '<options_json>'

  # Authentication (getAssertion) — same as soft_authenticator.py
  python attested_soft_authenticator.py get_assertion '<options_json>'
"""

import json
import sys
import os
import hashlib
import struct
import secrets
import base64
import argparse
import subprocess
import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives.serialization import pkcs12
import cbor2


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYSTORE_DIR = Path(os.environ.get("WEBAUTHN_KEYSTORE", "./keystore"))
ATTESTATION_DIR = Path(os.environ.get("WEBAUTHN_ATTESTATION_DIR", "./attestation"))

# FIDO Alliance OID arc for attestation extensions
# id-fido-gen-ce-aaguid: 1.3.6.1.4.1.45724.1.1.4
# This OID embeds the AAGUID in the attestation certificate so the RP can
# identify the authenticator model.
OID_FIDO_AAGUID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

# Default AAGUID for this software authenticator
# You can generate your own with: python -c "import uuid; print(uuid.uuid4())"
DEFAULT_AAGUID = "f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0"

DEFAULT_CN = "Soft Authenticator Attestation"


# ---------------------------------------------------------------------------
# Helpers (same as soft_authenticator.py)
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def parse_aaguid(aaguid_str: str) -> bytes:
    """Parse AAGUID string (with or without hyphens) into 16 bytes."""
    hex_str = aaguid_str.replace("-", "")
    if len(hex_str) != 32:
        raise ValueError(f"AAGUID must be 16 bytes (32 hex chars), got {len(hex_str)}")
    return bytes.fromhex(hex_str)


def encode_public_key_cose(public_key: ec.EllipticCurvePublicKey) -> bytes:
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
# Attestation Certificate Generation
# ---------------------------------------------------------------------------

def _ensure_dir(d: Path):
    d.mkdir(parents=True, exist_ok=True)


def _build_aaguid_extension(aaguid_bytes: bytes) -> bytes:
    """
    Build the FIDO AAGUID extension value.

    Per FIDO Metadata spec, the extension value is an ASN.1 OCTET STRING
    wrapping the 16-byte AAGUID. When embedded in an X.509 extension,
    the value field is the DER encoding of:
        OCTET STRING (16 bytes)

    The outer OCTET STRING wrapper is added by the X.509 extension encoding,
    so we just provide the inner encoding:
        04 10 <16 bytes>
    """
    # ASN.1 DER: OCTET STRING tag (0x04), length 16, then the 16 bytes
    return bytes([0x04, 0x10]) + aaguid_bytes


def generate_attestation_key() -> ec.EllipticCurvePrivateKey:
    """Generate a new EC P-256 key for attestation signing."""
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def generate_self_signed_cert(
    private_key: ec.EllipticCurvePrivateKey,
    cn: str = DEFAULT_CN,
    aaguid: str = DEFAULT_AAGUID,
    validity_days: int = 3650,
) -> x509.Certificate:
    """
    Generate a self-signed attestation certificate.

    This mimics what a real FIDO authenticator vendor would embed in their
    device, except it's self-signed (no root CA). The RP will see this as
    an untrusted attestation, but the packed attestation format will still
    be structurally valid.

    The certificate includes:
      - Subject: CN=<cn>, O=Software Authenticator
      - FIDO AAGUID extension (1.3.6.1.4.1.45724.1.1.4)
      - Key usage: digitalSignature only
      - Basic constraints: CA=false
    """
    aaguid_bytes = parse_aaguid(aaguid)
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Software Authenticator"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        # Basic constraints: not a CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Key usage: digital signature only
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # FIDO AAGUID extension
        .add_extension(
            x509.UnrecognizedExtension(
                oid=OID_FIDO_AAGUID,
                value=_build_aaguid_extension(aaguid_bytes),
            ),
            critical=False,
        )
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())
    return cert


def generate_csr(
    private_key: ec.EllipticCurvePrivateKey,
    cn: str = DEFAULT_CN,
    aaguid: str = DEFAULT_AAGUID,
) -> x509.CertificateSigningRequest:
    """
    Generate a Certificate Signing Request (CSR) for obtaining
    a real attestation certificate from a FIDO CA or your own CA.

    The CSR includes:
      - Subject: CN=<cn>, O=Software Authenticator
      - FIDO AAGUID extension request (1.3.6.1.4.1.45724.1.1.4)

    Send the resulting CSR PEM to your CA for signing.
    The CA should preserve the FIDO AAGUID extension in the issued cert.
    """
    aaguid_bytes = parse_aaguid(aaguid)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Software Authenticator"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.UnrecognizedExtension(
                oid=OID_FIDO_AAGUID,
                value=_build_aaguid_extension(aaguid_bytes),
            ),
            critical=False,
        )
    )

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr


def save_attestation_materials(
    out_dir: Path,
    private_key: ec.EllipticCurvePrivateKey,
    cert: x509.Certificate = None,
    csr: x509.CertificateSigningRequest = None,
    aaguid: str = DEFAULT_AAGUID,
):
    """Save attestation private key, certificate/CSR, and AAGUID config."""
    _ensure_dir(out_dir)

    # Save private key
    key_path = out_dir / "attestation_key.pem"
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    print(f"  Private key:   {key_path}")

    # Save cert or CSR
    if cert is not None:
        cert_path = out_dir / "attestation_cert.pem"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"  Certificate:   {cert_path}")

        # Also save DER for keychain import
        der_path = out_dir / "attestation_cert.der"
        with open(der_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))
        print(f"  Certificate (DER): {der_path}")

    if csr is not None:
        csr_path = out_dir / "attestation_csr.pem"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        print(f"  CSR:           {csr_path}")

    # Also export a PKCS#12 bundle for easy keychain import
    if cert is not None:
        p12_path = out_dir / "attestation.p12"
        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"Soft Authenticator Attestation",
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(b"changeit"),
        )
        with open(p12_path, "wb") as f:
            f.write(p12_data)
        os.chmod(p12_path, 0o600)
        print(f"  PKCS#12:       {p12_path} (password: changeit)")

    # Save config
    config_path = out_dir / "attestation_config.json"
    config = {
        "aaguid": aaguid,
        "key_file": str(key_path),
        "cert_file": str(out_dir / "attestation_cert.pem") if cert else None,
        "attestation_type": "self-signed" if cert else "csr-pending",
    }
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Config:        {config_path}")


def load_attestation_materials(att_dir: Path = ATTESTATION_DIR):
    """
    Load the attestation key and certificate from the attestation directory.
    Returns (private_key, cert_der_bytes, aaguid_bytes) or None if not found.
    """
    config_path = att_dir / "attestation_config.json"
    if not config_path.exists():
        return None

    with open(config_path) as f:
        config = json.load(f)

    key_path = att_dir / "attestation_key.pem"
    cert_path = att_dir / "attestation_cert.pem"

    if not key_path.exists() or not cert_path.exists():
        return None

    with open(key_path, "rb") as f:
        att_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(cert_path, "rb") as f:
        att_cert = x509.load_pem_x509_certificate(f.read())

    aaguid_bytes = parse_aaguid(config["aaguid"])

    return att_key, att_cert, aaguid_bytes


# ---------------------------------------------------------------------------
# macOS Keychain import
# ---------------------------------------------------------------------------

def import_to_keychain(
    cert_path: str = None,
    p12_path: str = None,
    keychain: str = "login.keychain-db",
):
    """
    Import attestation certificate (and optionally private key) into macOS Keychain.

    Two strategies:
      1. Import just the cert (.der or .pem) — useful if RP only needs to verify
      2. Import the PKCS#12 bundle (.p12) — imports both key + cert

    Uses the macOS `security` command-line tool.
    """
    import platform
    if platform.system() != "Darwin":
        print("Error: Keychain import is only supported on macOS", file=sys.stderr)
        sys.exit(1)

    if p12_path:
        # Import PKCS#12 (key + cert)
        p12_file = Path(p12_path)
        if not p12_file.exists():
            print(f"Error: PKCS#12 file not found: {p12_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Importing PKCS#12 bundle into keychain '{keychain}'...")
        print(f"  File: {p12_path}")
        print(f"  You will be prompted for the PKCS#12 password (default: changeit)")
        print(f"  You may also be prompted for your keychain password.\n")

        cmd = [
            "security", "import", str(p12_file),
            "-k", keychain,
            "-f", "pkcs12",
            "-T", "/usr/bin/codesign",  # Allow codesign to access
            "-T", "/usr/bin/security",  # Allow security tool to access
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ PKCS#12 imported successfully.")
            print(f"  Open Keychain Access.app to verify:")
            print(f"    Look for '{DEFAULT_CN}' in the '{keychain}' keychain")
        else:
            print(f"✗ Import failed (exit code {result.returncode})")
            if result.stderr:
                print(f"  stderr: {result.stderr.strip()}")
            # Try interactive mode
            print("\nTrying interactive import...")
            subprocess.run(["security", "import", str(p12_file), "-k", keychain])

    elif cert_path:
        # Import certificate only
        cert_file = Path(cert_path)
        if not cert_file.exists():
            print(f"Error: Certificate file not found: {cert_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Importing certificate into keychain '{keychain}'...")
        print(f"  File: {cert_path}")

        # Determine format
        fmt = "pemseq" if cert_path.endswith(".pem") else "openssl"

        cmd = [
            "security", "import", str(cert_file),
            "-k", keychain,
            "-f", fmt,
            "-t", "cert",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Certificate imported successfully.")
        else:
            print(f"✗ Import failed (exit code {result.returncode})")
            if result.stderr:
                print(f"  stderr: {result.stderr.strip()}")

    else:
        # Default: look for materials in attestation dir
        att_dir = ATTESTATION_DIR
        p12_default = att_dir / "attestation.p12"
        cert_default = att_dir / "attestation_cert.pem"

        if p12_default.exists():
            import_to_keychain(p12_path=str(p12_default), keychain=keychain)
        elif cert_default.exists():
            import_to_keychain(cert_path=str(cert_default), keychain=keychain)
        else:
            print("Error: No attestation materials found.", file=sys.stderr)
            print(f"  Run 'gen-self-signed' or 'gen-csr' first, or specify --cert/--p12", file=sys.stderr)
            sys.exit(1)


# ---------------------------------------------------------------------------
# Authenticator Data construction
# ---------------------------------------------------------------------------

def build_auth_data_register(
    rp_id_hash: bytes,
    credential_id: bytes,
    public_key: ec.EllipticCurvePublicKey,
    sign_count: int = 0,
    aaguid: bytes = None,
) -> bytes:
    """
    Build authenticatorData for registration.
    If aaguid is provided, use it; otherwise use 16 zero bytes.
    """
    flags = 0x45  # UP + UV + AT
    sign_count_bytes = struct.pack(">I", sign_count)

    if aaguid is None:
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
    flags = 0x05  # UP + UV
    sign_count_bytes = struct.pack(">I", sign_count)
    return rp_id_hash + bytes([flags]) + sign_count_bytes


# ---------------------------------------------------------------------------
# Attestation Objects
# ---------------------------------------------------------------------------

def build_attestation_object_none(auth_data: bytes) -> bytes:
    """Attestation format: none (no attestation statement)."""
    return cbor2.dumps({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })


def build_attestation_object_packed(
    auth_data: bytes,
    client_data_hash: bytes,
    att_key: ec.EllipticCurvePrivateKey,
    att_cert: x509.Certificate,
) -> bytes:
    """
    Attestation format: packed (full attestation).

    The attestation statement contains:
      - alg: -7 (ES256)
      - sig: signature over (authData || clientDataHash) using the attestation key
      - x5c: [attestation certificate DER]

    The RP verifies:
      1. sig is valid under the public key in x5c[0]
      2. x5c[0] contains the AAGUID matching authData
      3. x5c chains to a trusted root (if the RP cares)

    See: /fwd?q=aHR0cHM6Ly93d3cudzMub3JnL1RSL3dlYmF1dGhuLTIvI3NjdG4tcGFja2VkLWF0dGVzdGF0aW9u
    """
    # Sign (authData || clientDataHash) with attestation private key
    signed_data = auth_data + client_data_hash
    signature = att_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    # Certificate chain — just the leaf for self-signed
    x5c = [att_cert.public_bytes(serialization.Encoding.DER)]

    att_stmt = {
        "alg": -7,       # ES256
        "sig": signature,
        "x5c": x5c,
    }

    return cbor2.dumps({
        "fmt": "packed",
        "attStmt": att_stmt,
        "authData": auth_data,
    })


# ---------------------------------------------------------------------------
# Key storage (same as soft_authenticator.py)
# ---------------------------------------------------------------------------

def _ensure_keystore():
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)


def _cred_path(cred_id_b64: str) -> Path:
    safe = cred_id_b64.replace("/", "_").replace("+", "-")
    return KEYSTORE_DIR / f"{safe}.json"


def _key_path(cred_id_b64: str) -> Path:
    safe = cred_id_b64.replace("/", "_").replace("+", "-")
    return KEYSTORE_DIR / f"{safe}.pem"


def store_credential(
    rp_id, user_id, username, credential_id,
    private_key, sign_count=0,
):
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


def load_credential(cred_id_b64):
    meta_path = _cred_path(cred_id_b64)
    key_path = _key_path(cred_id_b64)
    if not meta_path.exists():
        raise FileNotFoundError(f"No credential found: {cred_id_b64}")
    with open(meta_path) as f:
        meta = json.load(f)
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return meta, private_key


def find_credentials(rp_id, allow_credentials=None):
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


def increment_sign_count(cred_id_b64):
    meta_path = _cred_path(cred_id_b64)
    with open(meta_path) as f:
        meta = json.load(f)
    meta["sign_count"] = meta.get("sign_count", 0) + 1
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    return meta["sign_count"]


# ---------------------------------------------------------------------------
# makeCredential — with attestation support
# ---------------------------------------------------------------------------

def make_credential(options_json: str) -> str:
    """
    Process WebAuthn registration options and produce a registration response.

    If attestation materials exist in ATTESTATION_DIR, uses "packed" attestation.
    Otherwise, falls back to "none" attestation.
    """
    options = json.loads(options_json)

    if "publicKey" in options:
        opts = options["publicKey"]
    else:
        opts = options

    rp_id = opts["rp"]["id"]
    user = opts["user"]
    user_id_b64 = user["id"]
    user_name = user.get("name", "unknown")

    challenge_b64 = opts["challenge"]

    # Check for ES256 support
    supported = False
    for param in opts.get("pubKeyCredParams", []):
        if param.get("alg") == -7 and param.get("type") == "public-key":
            supported = True
            break
    if not supported:
        print("Warning: ES256 not explicitly listed, proceeding anyway", file=sys.stderr)

    exclude_ids = set()
    for exc in opts.get("excludeCredentials", []):
        exclude_ids.add(exc["id"])

    # Generate credential key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    credential_id = secrets.token_bytes(32)
    credential_id_b64 = b64url_encode(credential_id)

    if credential_id_b64 in exclude_ids:
        credential_id = secrets.token_bytes(32)
        credential_id_b64 = b64url_encode(credential_id)

    # Build clientDataJSON
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge_b64,
        "origin": "https://webauthn.io",
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    client_data_hash = sha256(client_data_json)

    # Try loading attestation materials
    att_materials = load_attestation_materials()

    if att_materials is not None:
        att_key, att_cert, aaguid_bytes = att_materials
        print("Using packed attestation (attested)", file=sys.stderr)

        # Build authenticator data with real AAGUID
        rp_id_hash = sha256(rp_id.encode("utf-8"))
        auth_data = build_auth_data_register(
            rp_id_hash, credential_id, public_key,
            sign_count=0, aaguid=aaguid_bytes,
        )

        # Build packed attestation object
        att_obj = build_attestation_object_packed(
            auth_data, client_data_hash, att_key, att_cert,
        )
    else:
        print("No attestation materials found, using 'none' attestation", file=sys.stderr)

        rp_id_hash = sha256(rp_id.encode("utf-8"))
        auth_data = build_auth_data_register(
            rp_id_hash, credential_id, public_key, sign_count=0,
        )
        att_obj = build_attestation_object_none(auth_data)

    # Store credential
    store_credential(
        rp_id=rp_id,
        user_id=user_id_b64,
        username=user_name,
        credential_id=credential_id,
        private_key=private_key,
        sign_count=0,
    )

    # Build response
    response = {
        "username": user_name,
        "response": {
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "attestationObject": b64url_encode(att_obj),
                "clientDataJSON": b64url_encode(client_data_json),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        },
    }

    return json.dumps(response)


# ---------------------------------------------------------------------------
# getAssertion — same as soft_authenticator.py
# ---------------------------------------------------------------------------

def get_assertion(options_json: str) -> str:
    options = json.loads(options_json)

    if "publicKey" in options:
        opts = options["publicKey"]
    else:
        opts = options

    rp_id = opts.get("rpId", "webauthn.io")
    challenge_b64 = opts["challenge"]

    allow_list = []
    for cred in opts.get("allowCredentials", []):
        allow_list.append(cred["id"])

    if allow_list:
        credentials = find_credentials(rp_id, allow_credentials=allow_list)
    else:
        credentials = find_credentials(rp_id)

    if not credentials:
        print("Error: No matching credentials found in keystore", file=sys.stderr)
        sys.exit(1)

    meta, private_key = credentials[0]
    credential_id_b64 = meta["credential_id_b64url"]
    sign_count = increment_sign_count(credential_id_b64)

    rp_id_hash = sha256(rp_id.encode("utf-8"))
    auth_data = build_auth_data_authenticate(rp_id_hash, sign_count=sign_count)

    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": "https://webauthn.io",
        "crossOrigin": False,
    }
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode("utf-8")

    client_data_hash = sha256(client_data_json)
    signed_data = auth_data + client_data_hash

    signature_der = private_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))

    user_handle_b64 = meta.get("user_id", "")

    response = {
        "username": meta.get("username", ""),
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
# CLI with argparse
# ---------------------------------------------------------------------------

def cmd_gen_self_signed(args):
    """Generate a self-signed attestation certificate."""
    print(f"Generating self-signed attestation certificate...")
    print(f"  AAGUID: {args.aaguid}")
    print(f"  CN:     {args.cn}")
    print(f"  Output: {args.out_dir}/")
    print()

    private_key = generate_attestation_key()
    cert = generate_self_signed_cert(
        private_key, cn=args.cn, aaguid=args.aaguid,
        validity_days=args.validity_days,
    )

    out_dir = Path(args.out_dir)
    save_attestation_materials(
        out_dir, private_key, cert=cert, aaguid=args.aaguid,
    )

    print()
    print("✓ Self-signed attestation materials generated.")
    print()
    print("To use with the authenticator:")
    print(f"  export WEBAUTHN_ATTESTATION_DIR={args.out_dir}")
    print(f"  python attested_soft_authenticator.py make_credential '<options>'")
    print()
    print("To import into macOS Keychain:")
    print(f"  python attested_soft_authenticator.py import-keychain")


def cmd_gen_csr(args):
    """Generate a CSR for a real attestation certificate."""
    print(f"Generating attestation key + CSR...")
    print(f"  AAGUID: {args.aaguid}")
    print(f"  CN:     {args.cn}")
    print(f"  Output: {args.out_dir}/")
    print()

    private_key = generate_attestation_key()
    csr = generate_csr(private_key, cn=args.cn, aaguid=args.aaguid)

    out_dir = Path(args.out_dir)
    save_attestation_materials(
        out_dir, private_key, csr=csr, aaguid=args.aaguid,
    )

    print()
    print("✓ CSR generated.")
    print()
    print("Next steps:")
    print(f"  1. Send {args.out_dir}/attestation_csr.pem to your CA")
    print(f"  2. Save the signed certificate as {args.out_dir}/attestation_cert.pem")
    print(f"  3. Update {args.out_dir}/attestation_config.json:")
    print(f'     Set "attestation_type": "ca-signed"')
    print()
    print("To verify the CSR:")
    print(f"  openssl req -in {args.out_dir}/attestation_csr.pem -text -noout")


def cmd_import_keychain(args):
    """Import attestation certificate into macOS Keychain."""
    import_to_keychain(
        cert_path=args.cert,
        p12_path=args.p12,
        keychain=args.keychain,
    )


def cmd_make_credential(args):
    """Run makeCredential (registration)."""
    if args.input.startswith("@"):
        path = args.input[1:]
        if path == "-":
            input_json = sys.stdin.read()
        else:
            with open(path) as f:
                input_json = f.read()
    else:
        input_json = args.input

    result = make_credential(input_json)
    print(result)


def cmd_get_assertion(args):
    """Run getAssertion (authentication)."""
    if args.input.startswith("@"):
        path = args.input[1:]
        if path == "-":
            input_json = sys.stdin.read()
        else:
            with open(path) as f:
                input_json = f.read()
    else:
        input_json = args.input

    result = get_assertion(input_json)
    print(result)


def main():
    parser = argparse.ArgumentParser(
        description="Attested Software FIDO2/WebAuthn Authenticator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate self-signed attestation cert
  %(prog)s gen-self-signed --aaguid f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0

  # Generate CSR for real attestation cert
  %(prog)s gen-csr --cn "My Authenticator"

  # Import into macOS Keychain
  %(prog)s import-keychain

  # Register with packed attestation
  %(prog)s make_credential '{"publicKey": {...}}'

  # Authenticate (same as soft_authenticator.py)
  %(prog)s get_assertion '{"publicKey": {...}}'
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- gen-self-signed ---
    p_ss = subparsers.add_parser(
        "gen-self-signed",
        help="Generate a self-signed attestation certificate",
    )
    p_ss.add_argument("--aaguid", default=DEFAULT_AAGUID,
                       help=f"AAGUID for this authenticator (default: {DEFAULT_AAGUID})")
    p_ss.add_argument("--cn", default=DEFAULT_CN,
                       help=f"Common Name for the certificate (default: {DEFAULT_CN})")
    p_ss.add_argument("--out-dir", default=str(ATTESTATION_DIR),
                       help=f"Output directory (default: {ATTESTATION_DIR})")
    p_ss.add_argument("--validity-days", type=int, default=3650,
                       help="Certificate validity in days (default: 3650)")
    p_ss.set_defaults(func=cmd_gen_self_signed)

    # --- gen-csr ---
    p_csr = subparsers.add_parser(
        "gen-csr",
        help="Generate a CSR for obtaining a real attestation certificate",
    )
    p_csr.add_argument("--aaguid", default=DEFAULT_AAGUID,
                        help=f"AAGUID for this authenticator (default: {DEFAULT_AAGUID})")
    p_csr.add_argument("--cn", default=DEFAULT_CN,
                        help=f"Common Name for the CSR (default: {DEFAULT_CN})")
    p_csr.add_argument("--out-dir", default=str(ATTESTATION_DIR),
                        help=f"Output directory (default: {ATTESTATION_DIR})")
    p_csr.set_defaults(func=cmd_gen_csr)

    # --- import-keychain ---
    p_kc = subparsers.add_parser(
        "import-keychain",
        help="Import attestation certificate into macOS Keychain",
    )
    p_kc.add_argument("--cert", default=None,
                       help="Path to certificate file (.pem or .der)")
    p_kc.add_argument("--p12", default=None,
                       help="Path to PKCS#12 file (.p12)")
    p_kc.add_argument("--keychain", default="login.keychain-db",
                       help="Target keychain (default: login.keychain-db)")
    p_kc.set_defaults(func=cmd_import_keychain)

    # --- make_credential ---
    p_mc = subparsers.add_parser(
        "make_credential",
        help="Create a credential (registration)",
    )
    p_mc.add_argument("input", help="JSON options string or @filename (use @- for stdin)")
    p_mc.set_defaults(func=cmd_make_credential)

    # --- get_assertion ---
    p_ga = subparsers.add_parser(
        "get_assertion",
        help="Create an assertion (authentication)",
    )
    p_ga.add_argument("input", help="JSON options string or @filename (use @- for stdin)")
    p_ga.set_defaults(func=cmd_get_assertion)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
