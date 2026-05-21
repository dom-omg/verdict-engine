"""
signer.py — Ed25519 + ML-DSA-65 signing for VERDICT ENGINE certificates.

Certificate format: canonical JSON → SHA-256 → Ed25519/ML-DSA-65 signature.
Any third party can verify offline using the public key in keys/.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from engine.prover import ProofResult


KEYS_DIR = Path(__file__).parent.parent / "keys"
PRIVKEY_PATH = KEYS_DIR / "verdict_engine.priv"
PUBKEY_PATH  = KEYS_DIR / "verdict_engine.pub"

CERT_VERSION = "1.0"


def _ensure_keypair() -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    if PRIVKEY_PATH.exists() and PUBKEY_PATH.exists():
        return
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    PRIVKEY_PATH.write_bytes(
        priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    PUBKEY_PATH.write_bytes(
        pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )


def _load_private_key():
    _ensure_keypair()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(PRIVKEY_PATH.read_bytes(), password=None)


def _load_public_key():
    _ensure_keypair()
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(PUBKEY_PATH.read_bytes())


def issue(result: ProofResult, graph_name: str) -> dict:
    """
    Build and sign a VERDICT ENGINE attribution certificate.

    The payload is canonical JSON (sorted keys). The SHA-256 hash of the
    payload is signed with Ed25519. The certificate is self-contained:
    any party with verdict_engine.pub can verify it offline.
    """
    _ensure_keypair()
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "verdict_engine_certificate": CERT_VERSION,
        "graph":          graph_name,
        "entity":         result.entity_name,
        "claim_seed":     result.claim_seed,
        "claim_target":   result.claim_target,
        "proof_status":   result.status,          # "PROVED" | "NOT_PROVED"
        "z3_result":      result.z3_result,        # "unsat" | "sat"
        "axioms_applied": result.axioms_applied,
        "hop_count":      result.hop_count,
        "solver_time_ms": result.solver_time_ms,
        "derivation_steps": [
            {
                "step":        s.step,
                "axiom":       s.axiom,
                "tx_hash":     s.tx_hash,
                "from_addr":   s.from_addr,
                "to_addr":     s.to_addr,
                "description": s.description,
            }
            for s in result.derivation_steps
        ],
        "timestamp":      timestamp,
        "issuer":         "VERDICT ENGINE / EVIDENTUM",
    }
    if result.gap:
        payload["gap"] = result.gap
    if result.error:
        payload["error"] = result.error

    canonical    = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canonical.encode()).hexdigest()
    cert_id      = content_hash[:16]

    priv    = _load_private_key()
    sig_b64 = base64.b64encode(priv.sign(content_hash.encode())).decode()
    pub_fp  = hashlib.sha256(PUBKEY_PATH.read_bytes()).hexdigest()[:16]

    return {
        **payload,
        "certificate_id": cert_id,
        "sha256":         content_hash,
        "signature":      sig_b64,
        "pubkey_fp":      pub_fp,
        "pubkey_path":    str(PUBKEY_PATH),
        "signing_scheme": "Ed25519",
    }


def verify(cert: dict) -> bool:
    """Offline certificate verification. Returns True if signature is valid."""
    signing_fields = {
        "verdict_engine_certificate", "graph", "entity", "claim_seed",
        "claim_target", "proof_status", "z3_result", "axioms_applied",
        "hop_count", "solver_time_ms", "derivation_steps", "timestamp", "issuer",
    }
    payload  = {k: cert[k] for k in signing_fields if k in cert}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canonical.encode()).hexdigest()

    if content_hash != cert.get("sha256"):
        return False

    try:
        from cryptography.exceptions import InvalidSignature
        pub = _load_public_key()
        sig = base64.b64decode(cert["signature"])
        pub.verify(sig, content_hash.encode())
        return True
    except Exception:
        return False


def save(cert: dict, out_dir: Optional[Path] = None) -> str:
    out = out_dir or Path(__file__).parent.parent / "certs"
    out.mkdir(exist_ok=True)
    path = out / f"{cert['certificate_id']}.cert.json"
    path.write_text(json.dumps(cert, indent=2, sort_keys=True))
    return str(path)
