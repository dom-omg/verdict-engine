"""
server.py — VERDICT ENGINE REST API

FastAPI server exposing the attribution proof engine via HTTP.

Endpoints:
  POST /prove           — prove attribution claim, return signed certificate
  POST /verify          — verify a certificate offline
  GET  /certificates    — list all issued certificates
  GET  /graphs          — list available transaction graphs
  GET  /health          — service health + version

Run:
  python3 server.py
  # or
  uvicorn server:app --host 0.0.0.0 --port 8765 --reload

Swagger UI: http://localhost:8765/docs
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT      = Path(__file__).parent
DATA_DIR  = ROOT / "data"
CERTS_DIR = ROOT / "certs"

from engine.graph  import TxGraph
from engine.prover import prove
from engine.signer import issue, verify, save

app = FastAPI(
    title="VERDICT ENGINE",
    description=(
        "World's first formally verified blockchain attribution system. "
        "Z3 SMT proof engine · Ed25519 + ML-DSA-65 signed certificates · "
        "EVIDENTUM — Proof Intelligence"
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response models ─────────────────────────────────────────────────

class ProveRequest(BaseModel):
    graph: str                              # e.g. "lazarus_bybit_2025"
    seed: Optional[str] = None              # override seed address
    target: Optional[str] = None           # override target address
    scheme: str = "Ed25519"                 # "Ed25519" | "ML-DSA-65"


class VerifyRequest(BaseModel):
    certificate: dict                       # full certificate JSON


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "service": "VERDICT ENGINE",
        "version": "1.0.0",
        "status": "online",
        "issuer": "EVIDENTUM — Proof Intelligence",
        "graphs_available": [p.stem for p in DATA_DIR.glob("*.json")],
        "certificates_issued": len(list(CERTS_DIR.glob("*.cert.json"))),
    }


@app.get("/graphs")
def list_graphs():
    graphs = []
    for p in DATA_DIR.glob("*.json"):
        try:
            g = TxGraph.from_json(str(p))
            graphs.append({
                "name":          g.name,
                "entity":        g.entity_name,
                "seed_count":    len(g.seed_addresses),
                "target_count":  len(g.target_addresses),
                "tx_count":      len(g.transactions),
                "address_count": len(g.addresses),
            })
        except Exception as e:
            graphs.append({"name": p.stem, "error": str(e)})
    return {"graphs": graphs}


@app.post("/prove")
def prove_attribution(req: ProveRequest):
    graph_path = DATA_DIR / f"{req.graph}.json"
    if not graph_path.exists():
        raise HTTPException(404, f"Graph '{req.graph}' not found. "
                                 f"Available: {[p.stem for p in DATA_DIR.glob('*.json')]}")

    graph = TxGraph.from_json(str(graph_path))
    seed   = req.seed   or graph.seed_addresses[0]
    target = req.target or graph.target_addresses[0]

    if seed not in graph.addresses:
        raise HTTPException(400, f"Seed address not in graph: {seed}")
    if target not in graph.addresses:
        raise HTTPException(400, f"Target address not in graph: {target}")

    result = prove(graph, seed, target)
    cert   = issue(result, req.graph, scheme=req.scheme)
    path   = save(cert)

    return {
        "certificate": cert,
        "saved_to":    path,
        "comparison": {
            "chainalysis_reactor": {
                "result":         f"{graph.entity_name} (high confidence)",
                "methodology":    "PROPRIETARY — not disclosed",
                "reproducible":   False,
                "falsifiable":    False,
                "court_status":   "expert opinion (Daubert fragile)",
                "error_rate":     "unknown",
                "signed_cert":    False,
            },
            "verdict_engine": {
                "result":         cert["proof_status"],
                "z3_result":      cert["z3_result"],
                "methodology":    f"Axioms: {', '.join(cert['axioms_applied'])} (publicly stated)",
                "reproducible":   True,
                "falsifiable":    True,
                "court_status":   "Mathematical proof — UNSAT of negation",
                "error_rate":     "0% for stated axioms",
                "signed_cert":    True,
                "certificate_id": cert["certificate_id"],
                "signing_scheme": cert["signing_scheme"],
            },
        },
    }


@app.post("/verify")
def verify_certificate(req: VerifyRequest):
    ok = verify(req.certificate)
    return {
        "valid":          ok,
        "certificate_id": req.certificate.get("certificate_id"),
        "proof_status":   req.certificate.get("proof_status"),
        "entity":         req.certificate.get("entity"),
        "timestamp":      req.certificate.get("timestamp"),
        "signing_scheme": req.certificate.get("signing_scheme"),
        "message":        "Signature valid — certificate is authentic" if ok
                          else "INVALID — certificate has been tampered with",
    }


@app.get("/certificates")
def list_certificates():
    certs = []
    for p in sorted(CERTS_DIR.glob("*.cert.json")):
        try:
            c = json.loads(p.read_text())
            certs.append({
                "certificate_id": c.get("certificate_id"),
                "entity":         c.get("entity"),
                "proof_status":   c.get("proof_status"),
                "z3_result":      c.get("z3_result"),
                "axioms_applied": c.get("axioms_applied"),
                "hop_count":      c.get("hop_count"),
                "signing_scheme": c.get("signing_scheme"),
                "timestamp":      c.get("timestamp"),
                "graph":          c.get("graph"),
            })
        except Exception:
            pass
    return {"count": len(certs), "certificates": certs}


@app.get("/certificates/{cert_id}")
def get_certificate(cert_id: str):
    matches = list(CERTS_DIR.glob(f"{cert_id}*.cert.json"))
    if not matches:
        raise HTTPException(404, f"Certificate not found: {cert_id}")
    return json.loads(matches[0].read_text())


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8765))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
