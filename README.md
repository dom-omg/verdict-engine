# VERDICT ENGINE

**The world's first formally verified blockchain attribution system.**

Attribution claims are **proven** via Z3 SMT solver — not asserted.  
Certificates are signed Ed25519 and machine-verifiable by any third party.

---

## The Problem

In *United States v. Sterlingov* (Bitcoin Fog, 2024), under oath:

> **Defense:** "Is there any scientific evidence that Chainalysis Reactor produces accurate results?"  
> **Head of Chainalysis Investigations:** *"I am not aware of any."*

The judge admitted the testimony anyway — on pragmatic grounds, not scientific ones.

At the **INTERPOL/Europol Conference on Criminal Finances** (2025):
> *"Prosecutors face problems demonstrating the reliability, admissibility and validity of blockchain evidence in court, in the absence of court-proof forensic procedures and standardized methods."*

VERDICT ENGINE is the answer.

---

## What It Does

```
Input:  Transaction graph (on-chain data)  +  Attribution claim
          "Wallet 0xABC is controlled by Lazarus Group"

Engine: Express claim as Z3 Int equality constraints under stated axioms
        Assert NEGATION of claim
        Check satisfiability

Output: UNSAT → claim proven (no possible world satisfies axioms + negation)
        SAT   → claim not proven; Z3 shows exactly which step is missing
```

**Axioms** (formally stated, publicly auditable):
- **CIO** — Common-Input Ownership (Nakamoto 2008 §10)
- **CAD** — Change Address Detection (Androulaki et al. 2012)  
- **PEEL** — Peeling Chain (Reid & Harrigan 2011)
- **XFR** — Exchange Fan-In (Möser et al. 2017)

---

## Quick Start

```bash
# Use cobalt-ai venv (has z3-solver + cryptography)
PYTHON=~/omg-universe/repos/cobalt-ai/venv/bin/python3

# Prove Lazarus Bybit 2025 attribution
$PYTHON verdict.py prove lazarus_bybit_2025

# Side-by-side vs Chainalysis Reactor
$PYTHON verdict.py prove lazarus_bybit_2025 --compare

# CanSec 2026 demo (narrated)
$PYTHON demo.py

# Stage replay (fast)
$PYTHON demo.py --replay

# List issued certificates
$PYTHON verdict.py list

# Verify a certificate offline
$PYTHON verdict.py verify <cert_id>
```

---

## Architecture

```
verdict-engine/
├── engine/
│   ├── graph.py      TxGraph, Transaction data model
│   ├── axioms.py     Z3 attribution axioms (CIO, CAD, PEEL, XFR)
│   ├── prover.py     Z3 proof engine → ProofResult
│   └── signer.py     Ed25519 certificate issuance + verification
├── data/
│   ├── lazarus_bybit_2025.json   Lazarus / APT38 — Bybit $1.46B (2025)
│   └── ruja_oncoin.json          Ruja Ignatova / OneCoin
├── verdict.py        CLI
├── demo.py           CanSec 2026 narrated demo
└── certs/            Issued attribution certificates (signed JSON)
```

---

## Attribution Certificate

```json
{
  "verdict_engine_certificate": "1.0",
  "entity": "Lazarus Group / APT38 (DPRK)",
  "proof_status": "PROVED",
  "z3_result": "unsat",
  "axioms_applied": ["CAD", "CIO", "PEEL"],
  "hop_count": 4,
  "solver_time_ms": 12.4,
  "derivation_steps": [...],
  "sha256": "a3f9c2e...",
  "signature": "Ed25519 sig...",
  "signing_scheme": "Ed25519",
  "issuer": "VERDICT ENGINE / EVIDENTUM"
}
```

Any party with `keys/verdict_engine.pub` can verify offline. No VERDICT ENGINE infrastructure required.

---

## Competitive Position

| | Chainalysis Reactor | VERDICT ENGINE |
|---|---|---|
| Methodology | Proprietary black box | Publicly stated axioms |
| Reproducible | NO | YES |
| Falsifiable | NO | YES — axiom set published |
| Cross-examinable | NO | YES — Z3 proof object |
| Error rate | Unknown | 0% for stated axioms |
| Court status | "Expert opinion" | Mathematical proof |
| Signed certificate | NO | YES — Ed25519 |

---

## Roadmap

- [ ] ML-DSA-65 (FIPS 204) signing — quantum-safe certificates
- [ ] ZK layer — prove investigator methodology without revealing OSINT sources
- [ ] REST API — `POST /prove`, `GET /certificates`, `POST /verify`
- [ ] Next.js dashboard — court-ready UI, PDF export
- [ ] Multi-chain: Bitcoin UTXO, Solana, TRON
- [ ] INTERPOL/Europol data connector

---

## Legal

VERDICT ENGINE does not claim to replace legal proceedings.  
Attribution certificates are evidence artifacts for investigative use.  
All transaction data used in demos is part of the public record  
(OFAC SDN, FBI indictments, court filings).

---

**EVIDENTUM — Proof Intelligence**  
*dom-omg / QreativeLab*
