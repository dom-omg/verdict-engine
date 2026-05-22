"""
pqc_signer.py — ML-DSA-65 (CRYSTALS-Dilithium3) signing for PROOFNODE

Post-quantum digital signatures for PROOFNODE receipts.
NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard.

ML-DSA-65 parameters:
  Security: NIST Level 3 (~AES-192 classical, Grover/Shor-resistant)
  Public key:  1952 bytes
  Private key: 4000 bytes
  Signature:   3293 bytes

Keys live in keys/ alongside the Ed25519 pair.
Falls back gracefully if dilithium-py is not installed.
"""

import os
import base64
import hashlib
from pathlib import Path
from typing import Optional, Tuple

# ── dilithium-py import ───────────────────────────────────────────────────────

try:
    from dilithium_py.dilithium import Dilithium3
    ML_DSA_AVAILABLE = True
except ImportError:
    ML_DSA_AVAILABLE = False
    Dilithium3 = None


KEYS_DIR   = Path(__file__).parent.parent / "keys"
PQC_PK_PATH = KEYS_DIR / "verdict_mldsa65.pk"
PQC_SK_PATH = KEYS_DIR / "verdict_mldsa65.sk"

SCHEME = "ML-DSA-65"
FIPS   = "NIST FIPS 204"


# ── Key management ────────────────────────────────────────────────────────────

def _ensure_keypair() -> bool:
    """Generate and persist a demo ML-DSA-65 keypair. Returns True if available."""
    if not ML_DSA_AVAILABLE:
        return False
    KEYS_DIR.mkdir(exist_ok=True)
    if PQC_PK_PATH.exists() and PQC_SK_PATH.exists():
        return True
    pk, sk = Dilithium3.keygen()
    PQC_PK_PATH.write_bytes(pk)
    PQC_SK_PATH.write_bytes(sk)
    print(f"  [pqc] generated ML-DSA-65 keypair → {KEYS_DIR}/")
    return True


def load_public_key() -> Optional[bytes]:
    if not _ensure_keypair():
        return None
    return PQC_PK_PATH.read_bytes()


def _load_secret_key() -> Optional[bytes]:
    if not _ensure_keypair():
        return None
    return PQC_SK_PATH.read_bytes()


def pubkey_fingerprint() -> Optional[str]:
    """First 16 hex chars of SHA-256(public_key)."""
    pk = load_public_key()
    if pk is None:
        return None
    return hashlib.sha256(pk).hexdigest()[:16]


# ── Sign / verify ─────────────────────────────────────────────────────────────

def sign(message: bytes) -> Optional[bytes]:
    """
    Sign message with ML-DSA-65. Returns raw signature bytes.
    Returns None if ML-DSA not available.
    """
    sk = _load_secret_key()
    if sk is None:
        return None
    return Dilithium3.sign(sk, message)


def verify(message: bytes, signature: bytes, public_key: Optional[bytes] = None) -> bool:
    """
    Verify an ML-DSA-65 signature. Loads the repo public key if not provided.
    Returns True if valid.
    """
    if not ML_DSA_AVAILABLE:
        return False
    pk = public_key or load_public_key()
    if pk is None:
        return False
    try:
        return Dilithium3.verify(pk, message, signature)
    except Exception:
        return False


def sign_b64(message: bytes) -> Optional[str]:
    """Sign and return base64-encoded signature string."""
    sig = sign(message)
    return base64.b64encode(sig).decode() if sig else None


def verify_b64(message: bytes, signature_b64: str, public_key: Optional[bytes] = None) -> bool:
    """Verify a base64-encoded ML-DSA-65 signature."""
    try:
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    return verify(message, sig, public_key)


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ML_DSA_AVAILABLE:
        print("dilithium-py not installed — run: pip install dilithium-py")
        raise SystemExit(1)

    _ensure_keypair()
    msg = b"PROOFNODE ML-DSA-65 self-test"

    sig = sign(msg)
    print(f"scheme     : {SCHEME} ({FIPS})")
    print(f"message    : {msg.decode()}")
    print(f"sig bytes  : {len(sig)}")
    print(f"pubkey_fp  : {pubkey_fingerprint()}")

    ok = verify(msg, sig)
    print(f"verify     : {'OK' if ok else 'FAILED'}")

    tampered = b"PROOFNODE ML-DSA-65 self-test - tampered"
    ok_tampered = verify(tampered, sig)
    print(f"tampered   : {'OK (BAD!)' if ok_tampered else 'rejected (correct)'}")

    assert ok, "signature verification failed"
    assert not ok_tampered, "tampered message was not rejected"
    print("\nML-DSA-65 self-test passed.")
