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
    depends_on: list[str] = []             # cited proof URIs: "verdict:<id>", "proofnode:<id>", "trace:<id>"


class VerifyRequest(BaseModel):
    certificate: dict                       # full certificate JSON


class VerifyDagRequest(BaseModel):
    certificate: dict                       # root certificate
    dependencies: dict[str, dict] = {}     # id → cert/receipt dict for offline DAG verify


class WalletProveRequest(BaseModel):
    wallet: str                             # wallet address
    chain: str = "eth"
    entity_name: str = "Unknown Entity"
    signals: list[str] = []                 # ["OFAC", "MIXER", "SCAM", ...]
    risk_score: int = 0
    scheme: str = "Ed25519"
    depends_on: list[str] = []             # cited proof URIs


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service":   "VERDICT ENGINE",
        "version":   "1.0.0",
        "status":    "online",
        "issuer":    "EVIDENTUM — Proof Intelligence",
        "endpoints": ["/health", "/graphs", "/prove", "/prove_wallet", "/verify", "/verify_dag", "/certificates"],
        "docs":      "/docs",
    }


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
    cert   = issue(result, req.graph, scheme=req.scheme, depends_on=req.depends_on)
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


@app.post("/prove_wallet")
def prove_wallet(req: WalletProveRequest):
    """Prove attribution for an arbitrary wallet scan from chain-guardian / Wraith."""
    import time, hashlib, uuid

    # Check if we have a pre-built graph for this wallet
    KNOWN_WALLETS: dict[str, str] = {}
    for p in DATA_DIR.glob("*.json"):
        try:
            d = json.loads(p.read_text())
            for addr in d.get("seed_addresses", []) + d.get("target_addresses", []):
                KNOWN_WALLETS[addr.lower()] = p.stem
        except Exception:
            pass

    wallet_lower = req.wallet.lower()
    matched_graph = KNOWN_WALLETS.get(wallet_lower)

    if matched_graph:
        # Use pre-built graph
        graph = TxGraph.from_json(str(DATA_DIR / f"{matched_graph}.json"))
        seed   = graph.seed_addresses[0]
        target = graph.target_addresses[0]
        result = prove(graph, seed, target)
        cert   = issue(result, matched_graph, scheme=req.scheme)
    else:
        # Build synthetic graph from Wraith signals
        from engine.graph import Transaction
        sig_map = {
            "OFAC":    "ofac_sanctioned",
            "MIXER":   "mixer_protocol",
            "SCAM":    "scam_address",
            "EXPLOIT": "exploit_contract",
            "DARKNET": "darknet_market",
        }
        metadata = {sig_map.get(s, s.lower()): True for s in req.signals}

        synthetic_graph = TxGraph(
            name=f"dynamic_{req.wallet[:10]}",
            entity_name=req.entity_name,
            seed_addresses=[req.wallet],
            target_addresses=[req.wallet],
            transactions=[
                Transaction(
                    hash=f"0x{hashlib.sha256(req.wallet.encode()).hexdigest()}",
                    block=0,
                    chain=req.chain,
                    inputs=[req.wallet],
                    outputs=[req.wallet],
                    values_eth={req.wallet: req.risk_score / 100.0},
                    metadata=metadata,
                )
            ],
            known_mixers={req.wallet} if "MIXER" in req.signals else set(),
        )
        result = prove(synthetic_graph, req.wallet, req.wallet)
        cert   = issue(result, f"dynamic_{req.wallet[:10]}", scheme=req.scheme, depends_on=req.depends_on)

    path = save(cert)
    return {
        "certificate": cert,
        "saved_to": path,
        "verify_url": f"/certificates/{cert['certificate_id']}",
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


@app.post("/verify_dag")
def verify_dag(req: VerifyDagRequest):
    """
    Verify a proof certificate AND all its cited dependencies (proof DAG).

    Accepts the root cert + an optional inline dict of dependencies keyed by
    their URI (e.g. "proofnode:7b97a84a", "verdict:189692a1").  Missing deps
    are resolved from local cert/receipt storage.

    Returns per-node verification status so the caller can pinpoint any break
    in the chain.
    """
    import os

    PROOFNODE_DIR = Path(
        os.environ.get("PROOFNODE_RECEIPTS_DIR", str(ROOT.parent / "proofnode" / "receipts"))
    )
    TRACE_DIR = Path(
        os.environ.get("TRACE_EVIDENCE_DIR", str(ROOT.parent / "u-cant-hide" / "intel" / "evidence"))
    )

    def _resolve(uri: str) -> Optional[dict]:
        """Resolve a dep URI to its raw dict, checking inline deps then disk."""
        if uri in req.dependencies:
            return req.dependencies[uri]
        prefix, _, ref_id = uri.partition(":")
        if prefix == "verdict":
            matches = list(CERTS_DIR.glob(f"{ref_id}*.cert.json"))
            if matches:
                return json.loads(matches[0].read_text())
        elif prefix == "proofnode":
            matches = list(PROOFNODE_DIR.glob(f"{ref_id}*.receipt.json"))
            if matches:
                return json.loads(matches[0].read_text())
        elif prefix == "trace":
            matches = list(TRACE_DIR.glob(f"{ref_id}*.evidence.json"))
            if matches:
                return json.loads(matches[0].read_text())
        return None

    def _verify_node(uri: str, raw: dict) -> dict:
        prefix = uri.split(":")[0]
        if prefix == "verdict":
            ok = verify(raw)
            return {"uri": uri, "issuer": raw.get("issuer", "VERDICT ENGINE"), "valid": ok}
        elif prefix == "proofnode":
            try:
                import sys
                sys.path.insert(0, str(ROOT.parent / "proofnode"))
                import receipt as pn_receipt
                ok = pn_receipt.verify_receipt(raw)
            except Exception:
                ok = False
            return {"uri": uri, "issuer": "PROOFNODE", "valid": ok}
        elif prefix == "trace":
            ok = raw.get("sha256") == __import__("hashlib").sha256(
                __import__("json").dumps(
                    {k: raw[k] for k in raw if k not in ("sha256", "signature", "public_key", "evidence_id")},
                    sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                ).encode()
            ).hexdigest()
            return {"uri": uri, "issuer": "u-cant-hide / TRACE", "valid": ok}
        return {"uri": uri, "issuer": "unknown", "valid": False}

    results: list[dict] = []

    # Verify root cert
    root_ok = verify(req.certificate)
    results.append({
        "uri":    f"verdict:{req.certificate.get('certificate_id', '?')}",
        "issuer": req.certificate.get("issuer", "VERDICT ENGINE"),
        "valid":  root_ok,
        "role":   "root",
    })

    # Verify each dep in depends_on
    for dep_uri in req.certificate.get("depends_on", []):
        raw = _resolve(dep_uri)
        if raw is None:
            results.append({"uri": dep_uri, "issuer": "?", "valid": False, "error": "not found"})
        else:
            node = _verify_node(dep_uri, raw)
            results.append(node)

    all_valid = all(r["valid"] for r in results)
    return {
        "dag_valid":  all_valid,
        "node_count": len(results),
        "nodes":      results,
        "message":    "Full proof DAG verified — all dependencies valid" if all_valid
                      else "DAG INVALID — one or more nodes failed verification",
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
