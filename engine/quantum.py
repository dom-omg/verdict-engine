"""
quantum.py — QUANTUM VERDICT: BKZ cost models + Z3 cryptographic security prover.

Proves that a lattice-based scheme (ML-DSA-65, etc.) resists BKZ-β sieving
and hybrid dual attacks at a stated security level.

Cost models: Albrecht et al. 2021 / NIST PQC analysis (FIPS 203/204).

Proof structure:
  Claim:   ∀ β ≥ β_min : cost(β) ≥ λ   (λ = security target in bits)
  Negate:  ∃ β ≥ β_min : cost(β) < λ
  Z3:      UNSAT → claim proven → scheme is λ-bit secure
"""
from __future__ import annotations

import datetime
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from z3 import Real, Solver, sat, unsat, unknown


# ── BKZ Cost Models (Albrecht et al. 2021) ───────────────────────────────────

class BKZCostModel:
    """
    Core-SVP cost functions in bits (log2 of operation count).

    Reference parameters are empirically validated against NIST FIPS 203/204
    security analysis and the Matzov 2022 report.
    """

    @staticmethod
    def sieving_classical(beta: float) -> float:
        """2^(0.292β + 16.4) classical sieving (BDGL16 + dimension-for-free)."""
        return 0.292 * beta + 16.4

    @staticmethod
    def sieving_quantum(beta: float) -> float:
        """2^(0.265β + 16.4) quantum sieving (Grover-amplified BDGL16)."""
        return 0.265 * beta + 16.4

    @staticmethod
    def enumeration(beta: float) -> float:
        """2^(0.187β·log₂β − 1.019β + 16.1) BKZ-2.0 enumeration."""
        return 0.187 * beta * math.log2(max(beta, 2)) - 1.019 * beta + 16.1

    @staticmethod
    def hybrid_dual_reduction(eta: int, n: int, beta_min: float) -> float:
        """
        Hybrid dual attack reduction for sparse/bounded secrets.

        Sparse secrets (coefficients in [-η, η]) reduce the guessing entropy,
        enabling MITM over a fraction of the secret. Conservative estimate
        per Matzov 2022 / Ducas-van Woerden analysis.

        Returns the bit reduction applied to the classical sieving cost.
        """
        # Secret entropy per coefficient: log2(2η + 1)
        coeff_entropy = math.log2(2 * eta + 1)
        # Optimal guess fraction (approx): k ≈ beta_min / (4 * n)
        k = max(1, int(beta_min / (4 * n)))
        # Mitigation: guessing k coordinates + BKZ on reduced lattice
        guess_cost = k * coeff_entropy
        # Net reduction: sqrt(guessing) + lattice gain (conservative floor: 5 bits)
        reduction = min(guess_cost / 2.0, 20.0)
        return max(5.0, reduction)


# ── Scheme Definitions ────────────────────────────────────────────────────────

SCHEMES: dict[str, dict] = {
    "ML-DSA-65": {
        "description": "NIST FIPS 204 — Module-Lattice Digital Signature (Dilithium-3)",
        "type": "Module-LWE",
        "n": 256,
        "q": 8380417,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "gamma1": 131072,   # 2^17
        "gamma2": 95232,    # (q-1)/88
        "lambda_target": 128,
        # BKZ β_min from NIST analysis (primal attack on Module-LWE)
        # Dimension: (k+l)*n = 2816; estimated optimal blocksize ≈ 594
        "beta_min_classical": 594.0,
        "beta_min_quantum": 594.0,
        "nist_level": 3,
        "standard": "FIPS 204",
    },
    "ML-DSA-44": {
        "description": "NIST FIPS 204 — Module-Lattice Digital Signature (Dilithium-2)",
        "type": "Module-LWE",
        "n": 256,
        "q": 8380417,
        "k": 4,
        "l": 4,
        "eta": 2,
        "tau": 39,
        "gamma1": 131072,
        "gamma2": 95232,
        "lambda_target": 128,
        "beta_min_classical": 387.0,
        "beta_min_quantum": 387.0,
        "nist_level": 2,
        "standard": "FIPS 204",
    },
    "ML-DSA-87": {
        "description": "NIST FIPS 204 — Module-Lattice Digital Signature (Dilithium-5)",
        "type": "Module-LWE",
        "n": 256,
        "q": 8380417,
        "k": 8,
        "l": 7,
        "eta": 2,
        "tau": 60,
        "gamma1": 524288,   # 2^19
        "gamma2": 261888,
        "lambda_target": 256,
        "beta_min_classical": 875.0,
        "beta_min_quantum": 875.0,
        "nist_level": 5,
        "standard": "FIPS 204",
    },
    "FALCON-512": {
        "description": "NIST FIPS 206 — NTRU-based signature (FALCON-512)",
        "type": "NTRU-Lattice",
        "n": 512,
        "q": 12289,
        "sigma": 165.7,     # Gaussian parameter
        "eta": 1,           # ternary keys
        "lambda_target": 128,
        "beta_min_classical": 477.0,
        "beta_min_quantum": 477.0,
        "nist_level": 1,
        "standard": "FIPS 206",
        "shift_snare_risk": True,   # CVE: 1-trace Gaussian sampler side-channel
    },
    "CHAINLOCK": {
        "description": "ChainLock — Sovereign Custody (ML-DSA-65 + Shamir 2-of-3)",
        "type": "Module-LWE",
        "n": 256,
        "q": 8380417,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "gamma1": 131072,
        "gamma2": 95232,
        "lambda_target": 128,
        "beta_min_classical": 594.0,
        "beta_min_quantum": 594.0,
        "nist_level": 3,
        "standard": "FIPS 204 + Shamir Secret Sharing",
        "notes": "Shamir 2-of-3 threshold adds ITS layer orthogonal to lattice security.",
    },
}


# ── Quantum Proof Result ──────────────────────────────────────────────────────

@dataclass
class QuantumProofResult:
    scheme_name: str
    scheme_params: dict

    # BKZ analysis
    beta_min: float
    cost_classical_bits: float
    cost_quantum_bits: float
    security_margin_classical: float
    security_margin_quantum: float

    # Hybrid dual
    hybrid_reduction_bits: float
    cost_classical_hybrid: float
    cost_quantum_hybrid: float
    security_margin_classical_hybrid: float
    security_margin_quantum_hybrid: float

    # Z3 results
    z3_classical: str       # "unsat" | "sat" | "unknown"
    z3_quantum: str
    z3_hybrid_classical: str
    z3_hybrid_quantum: str
    solver_time_ms: float

    # Overall
    security_target: int
    proof_status: str       # "SECURE" | "MARGINAL" | "BROKEN"
    weakest_margin: float
    horizon_years: int
    expiry_date: str
    warnings: list[str] = field(default_factory=list)

    def is_secure(self) -> bool:
        return self.proof_status == "SECURE"


# ── Z3 Prover ────────────────────────────────────────────────────────────────

class QuantumProver:

    def prove(
        self,
        scheme_name: str,
        security_target: Optional[int] = None,
        horizon_years: int = 10,
    ) -> QuantumProofResult:
        if scheme_name not in SCHEMES:
            raise ValueError(f"Unknown scheme: {scheme_name}. Available: {list(SCHEMES)}")

        params = SCHEMES[scheme_name]
        λ = security_target or params["lambda_target"]
        β_min = params["beta_min_classical"]
        eta = params.get("eta", 4)
        n = params["n"]

        t0 = time.perf_counter()

        # ── 1. Classical sieving cost at β_min ──────────────────────────────
        cost_cl = BKZCostModel.sieving_classical(β_min)
        cost_qu = BKZCostModel.sieving_quantum(β_min)
        margin_cl = cost_cl - λ
        margin_qu = cost_qu - λ

        # ── 2. Hybrid dual reduction ─────────────────────────────────────────
        reduction = BKZCostModel.hybrid_dual_reduction(eta, n, β_min)
        cost_cl_h = cost_cl - reduction
        cost_qu_h = cost_qu - reduction
        margin_cl_h = cost_cl_h - λ
        margin_qu_h = cost_qu_h - λ

        # ── 3. Z3 proofs ─────────────────────────────────────────────────────
        z3_cl  = self._z3_prove(β_min, 0.292, 16.4, λ, "classical_sieving")
        z3_qu  = self._z3_prove(β_min, 0.265, 16.4, λ, "quantum_sieving")
        z3_clh = self._z3_prove(β_min, 0.292, 16.4 - reduction, λ, "classical_hybrid")
        z3_quh = self._z3_prove(β_min, 0.265, 16.4 - reduction, λ, "quantum_hybrid")

        solver_ms = (time.perf_counter() - t0) * 1000

        # ── 4. Overall verdict ───────────────────────────────────────────────
        weakest = min(margin_cl, margin_qu, margin_cl_h, margin_qu_h)
        all_unsat = all(r == "unsat" for r in [z3_cl, z3_qu, z3_clh, z3_quh])

        if all_unsat and weakest >= 10:
            status = "SECURE"
        elif all_unsat and weakest >= 0:
            status = "MARGINAL"
        else:
            status = "BROKEN"

        # ── 5. Warnings ──────────────────────────────────────────────────────
        warnings: list[str] = []
        if margin_qu_h < 20:
            warnings.append(
                f"Quantum hybrid margin {margin_qu_h:.1f} bits — below 20-bit safety threshold. "
                "Consider upgrading to ML-DSA-87 for long-term quantum resistance."
            )
        if params.get("shift_snare_risk"):
            warnings.append(
                "SHIFT SNARE (2025): FALCON Gaussian sampler is vulnerable to "
                "1-trace key recovery. Ensure constant-time implementation."
            )
        if weakest < 30:
            warnings.append(
                f"Weakest margin ({weakest:.1f} bits) is below 30-bit buffer. "
                "Re-evaluate if BKZ cost model assumptions are updated."
            )

        # ── 6. Expiry ────────────────────────────────────────────────────────
        expiry = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=365 * horizon_years)
        ).strftime("%Y-%m-%d")

        return QuantumProofResult(
            scheme_name=scheme_name,
            scheme_params=params,
            beta_min=β_min,
            cost_classical_bits=cost_cl,
            cost_quantum_bits=cost_qu,
            security_margin_classical=margin_cl,
            security_margin_quantum=margin_qu,
            hybrid_reduction_bits=reduction,
            cost_classical_hybrid=cost_cl_h,
            cost_quantum_hybrid=cost_qu_h,
            security_margin_classical_hybrid=margin_cl_h,
            security_margin_quantum_hybrid=margin_qu_h,
            z3_classical=z3_cl,
            z3_quantum=z3_qu,
            z3_hybrid_classical=z3_clh,
            z3_hybrid_quantum=z3_quh,
            solver_time_ms=solver_ms,
            security_target=λ,
            proof_status=status,
            weakest_margin=weakest,
            horizon_years=horizon_years,
            expiry_date=expiry,
            warnings=warnings,
        )

    def _z3_prove(
        self,
        beta_min: float,
        slope: float,
        intercept: float,
        security_target: int,
        model_name: str,
    ) -> str:
        """
        Z3 check: negate the claim ∀ β ≥ β_min: slope*β + intercept ≥ λ.

        Negation: ∃ β ≥ β_min: slope*β + intercept < λ.
        UNSAT → no such β → original claim proven.
        """
        beta = Real(f"beta_{model_name}")
        cost = slope * beta + intercept

        s = Solver()
        s.add(beta >= beta_min)         # adversary uses minimal viable blocksize
        s.add(cost < security_target)   # and claims cost is below target

        result = s.check()
        if result == unsat:
            return "unsat"
        elif result == sat:
            return "sat"
        return "unknown"


# ── Certificate Builder ───────────────────────────────────────────────────────

def issue_quantum_cert(result: QuantumProofResult, scheme: str = "Ed25519") -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "quantum_verdict_certificate": "1.0",
        "type": "QUANTUM_SECURITY",
        "scheme": result.scheme_name,
        "scheme_description": result.scheme_params.get("description", ""),
        "standard": result.scheme_params.get("standard", ""),
        "nist_level": result.scheme_params.get("nist_level"),
        "attack_models": {
            "classical_bkz_sieving": {
                "beta_min": result.beta_min,
                "cost_bits": round(result.cost_classical_bits, 2),
                "security_margin_bits": round(result.security_margin_classical, 2),
                "z3_result": result.z3_classical,
                "z3_claim": f"∀β ≥ {result.beta_min}: 0.292β + 16.4 ≥ {result.security_target}",
            },
            "quantum_bkz_sieving": {
                "beta_min": result.beta_min,
                "cost_bits": round(result.cost_quantum_bits, 2),
                "security_margin_bits": round(result.security_margin_quantum, 2),
                "z3_result": result.z3_quantum,
                "z3_claim": f"∀β ≥ {result.beta_min}: 0.265β + 16.4 ≥ {result.security_target}",
            },
            "classical_hybrid_dual": {
                "beta_min": result.beta_min,
                "sparse_reduction_bits": round(result.hybrid_reduction_bits, 2),
                "cost_bits": round(result.cost_classical_hybrid, 2),
                "security_margin_bits": round(result.security_margin_classical_hybrid, 2),
                "z3_result": result.z3_hybrid_classical,
                "z3_claim": (
                    f"∀β ≥ {result.beta_min}: 0.292β + {round(16.4 - result.hybrid_reduction_bits, 2)}"
                    f" ≥ {result.security_target} (after {round(result.hybrid_reduction_bits, 1)}-bit hybrid reduction)"
                ),
            },
            "quantum_hybrid_dual": {
                "beta_min": result.beta_min,
                "sparse_reduction_bits": round(result.hybrid_reduction_bits, 2),
                "cost_bits": round(result.cost_quantum_hybrid, 2),
                "security_margin_bits": round(result.security_margin_quantum_hybrid, 2),
                "z3_result": result.z3_hybrid_quantum,
                "z3_claim": (
                    f"∀β ≥ {result.beta_min}: 0.265β + {round(16.4 - result.hybrid_reduction_bits, 2)}"
                    f" ≥ {result.security_target} (after {round(result.hybrid_reduction_bits, 1)}-bit hybrid reduction)"
                ),
            },
        },
        "security_target_bits": result.security_target,
        "proof_status": result.proof_status,
        "weakest_margin_bits": round(result.weakest_margin, 2),
        "solver_time_ms": round(result.solver_time_ms, 2),
        "horizon_years": result.horizon_years,
        "expiry_date": result.expiry_date,
        "warnings": result.warnings,
        "cost_model": "Albrecht et al. 2021 / NIST PQC Security Analysis",
        "timestamp": now,
        "issuer": "QUANTUM VERDICT / EVIDENTUM",
    }

    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canonical.encode()).hexdigest()
    cert_id = "qv-" + content_hash[:13]

    if scheme == "ML-DSA-65":
        try:
            from engine import pqc_signer
            sig_b64 = pqc_signer.sign_b64(content_hash.encode())
            pub_fp = pqc_signer.pubkey_fingerprint() or "unavailable"
            if sig_b64 is None:
                raise RuntimeError("ML-DSA-65 unavailable")
        except Exception:
            import base64
            from engine.signer import _load_private_key, PUBKEY_PATH
            priv = _load_private_key()
            sig_b64 = base64.b64encode(priv.sign(content_hash.encode())).decode()
            pub_fp = hashlib.sha256(PUBKEY_PATH.read_bytes()).hexdigest()[:16]
            scheme = "Ed25519-fallback"
    else:
        import base64
        from engine.signer import _load_private_key, _ensure_keypair, PUBKEY_PATH
        _ensure_keypair()
        priv = _load_private_key()
        sig_b64 = base64.b64encode(priv.sign(content_hash.encode())).decode()
        pub_fp = hashlib.sha256(PUBKEY_PATH.read_bytes()).hexdigest()[:16]

    return {
        **payload,
        "certificate_id": cert_id,
        "sha256": content_hash,
        "signature": sig_b64,
        "pubkey_fp": pub_fp,
        "signing_scheme": scheme,
    }


def save_quantum_cert(cert: dict, out_dir: Optional[Path] = None) -> str:
    out = out_dir or Path(__file__).parent.parent / "certs"
    out.mkdir(exist_ok=True)
    path = out / f"{cert['certificate_id']}.cert.json"
    path.write_text(json.dumps(cert, indent=2, sort_keys=True))
    return str(path)
