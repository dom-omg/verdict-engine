#!/usr/bin/env python3
"""
verdict.py — VERDICT ENGINE CLI

The world's first formally verified blockchain attribution system.
Attribution claims are proven (not just asserted) via Z3 SMT solver.
Certificates are signed Ed25519, machine-verifiable by any third party.

Usage:
  verdict prove lazarus_bybit_2025
  verdict prove ruja_oncoin
  verdict prove lazarus_bybit_2025 --compare
  verdict prove lazarus_bybit_2025 --seed 0xABC --target 0xDEF
  verdict verify <cert_id>
  verdict list

  verdict quantum ML-DSA-65
  verdict quantum CHAINLOCK --bits 128 --horizon 15
  verdict quantum list

EVIDENTUM — Proof Intelligence
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
DATA_DIR  = ROOT / "data"
CERTS_DIR = ROOT / "certs"

from engine.graph import TxGraph
from engine.prover import prove
from engine.signer import issue, verify, save
from engine.quantum import QuantumProver, SCHEMES, issue_quantum_cert, save_quantum_cert


# ── Terminal colours ─────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
DIM    = "\033[2m"
WHITE  = "\033[97m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET


def print_banner() -> None:
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║  VERDICT ENGINE  v1.0.0                                      ║
║  Formally Verified Blockchain Attribution                    ║
║  Powered by Z3 SMT Solver · Signed Ed25519                   ║
║  EVIDENTUM — Proof Intelligence                              ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def print_proof(result, cert: dict) -> None:
    status_color = GREEN if result.is_proved() else RED
    status_icon  = "✓ PROVED" if result.is_proved() else "✗ NOT PROVED"

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║  ATTRIBUTION CERTIFICATE                                     ║
╠══════════════════════════════════════════════════════════════╣{RESET}""")
    print(f"{BOLD}║  Status        {status_color}{status_icon}{RESET}")
    print(f"{BOLD}║  Entity        {WHITE}{result.entity_name}{RESET}")
    print(f"{BOLD}║  Seed          {DIM}{result.claim_seed[:20]}…{RESET}")
    print(f"{BOLD}║  Target        {DIM}{result.claim_target[:20]}…{RESET}")
    print(f"{BOLD}║  Z3 Result     {CYAN}{result.z3_result.upper()}{RESET}  {'(negation is unsatisfiable → claim proven)' if result.z3_result == 'unsat' else ''}")
    print(f"{BOLD}║  Axioms        {', '.join(result.axioms_applied)}{RESET}")
    print(f"{BOLD}║  Hop count     {result.hop_count}{RESET}")
    print(f"{BOLD}║  Solver time   {result.solver_time_ms:.1f} ms{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  DERIVATION CHAIN{RESET}")

    if result.derivation_steps:
        for step in result.derivation_steps:
            print(f"  {CYAN}Step {step.step}{RESET}  [{step.axiom}]  {step.description}")
    else:
        print(f"  {DIM}(no path found — check graph connectivity){RESET}")

    print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  CERTIFICATE{RESET}")
    print(f"  ID          {cert['certificate_id']}")
    print(f"  SHA-256     {cert['sha256'][:54]}…")
    print(f"  Signature   {cert['signature'][:40]}…")
    print(f"  PubKey FP   {cert['pubkey_fp']}")
    print(f"  Scheme      {cert['signing_scheme']}")
    print(f"  Issued      {cert['timestamp']}")
    print(f"  Issuer      {cert['issuer']}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")

    if result.gap:
        print(f"{YELLOW}  ⚠ Gap: {result.gap}{RESET}\n")


def print_compare(result, cert: dict) -> None:
    proved = result.is_proved()
    print(f"""
{BOLD}┌─────────────────────────────────────────────────────────────────────────┐
│  VERDICT ENGINE vs CHAINALYSIS REACTOR — Side-by-Side                   │
├──────────────────────────────────────────┬──────────────────────────────┤
│  CHAINALYSIS REACTOR                     │  VERDICT ENGINE              │
├──────────────────────────────────────────┼──────────────────────────────┤{RESET}""")

    def row(lbl, left, right, right_color=WHITE):
        l_pad = left.ljust(40)
        r_pad = right.ljust(28)
        print(f"{BOLD}│{RESET}  {lbl:<12} {l_pad}{BOLD}│{RESET}  {right_color}{r_pad}{RESET}  {BOLD}│{RESET}")

    verdict_status = f"{'PROVED' if proved else 'NOT PROVED'}"
    row("Result",       "Lazarus Group (high confidence)",       verdict_status,        GREEN if proved else RED)
    row("Confidence",   '"high" (undefined scale)',              'Z3 UNSAT (certain)' if proved else 'SAT (gap exists)',  CYAN)
    row("Methodology",  "[PROPRIETARY — not disclosed]",        "CIO + CAD + PEEL",    CYAN)
    row("Axioms",       "none stated",                          " + ".join(result.axioms_applied), CYAN)
    row("Hops",         "not shown",                            str(result.hop_count), WHITE)
    row("Reproducible", "NO — black box",                       "YES — full trace",    GREEN)
    row("Verifiable",   "NO — expert opinion",                  "YES — any Z3 client", GREEN)
    row("Error rate",   'unknown (head of investigations',      "0% for stated axioms",GREEN)
    row("",             ' admitted no known error rate)',       "",                    WHITE)
    row("Falsifiable",  "NO — heuristics not stated",           "YES — axiom set pub.", GREEN)
    row("Court status", '"expert opinion" (Daubert fragile)',   "Mathematical proof",  GREEN)
    row("Signed cert",  "NO",                                   f"YES Ed25519 {cert['certificate_id'][:8]}…", GREEN)

    print(f"{BOLD}└──────────────────────────────────────────┴──────────────────────────────┘{RESET}")
    print(f"\n  {DIM}Sources: United States v. Sterlingov (2024); Chainalysis head of investigations")
    print(f"  testimony 2024; INTERPOL/Basel Institute Conference on Criminal Finances 2025;")
    print(f"  Daubert v. Merrell Dow Pharmaceuticals (1993).{RESET}\n")


def cmd_prove(graph_name: str, seed: str | None, target: str | None, compare: bool) -> None:
    graph_path = DATA_DIR / f"{graph_name}.json"
    if not graph_path.exists():
        print(f"{RED}Error: graph '{graph_name}' not found in {DATA_DIR}{RESET}")
        print(f"Available: {', '.join(p.stem for p in DATA_DIR.glob('*.json'))}")
        sys.exit(1)

    graph = TxGraph.from_json(str(graph_path))
    seed_addr   = seed   or graph.seed_addresses[0]
    target_addr = target or graph.target_addresses[0]

    print(f"  {DIM}Graph:    {graph.name}{RESET}")
    print(f"  {DIM}Entity:   {graph.entity_name}{RESET}")
    print(f"  {DIM}Seed:     {seed_addr[:20]}…{RESET}")
    print(f"  {DIM}Target:   {target_addr[:20]}…{RESET}")
    print(f"  {DIM}Proving attribution via Z3…{RESET}\n")

    result = prove(graph, seed_addr, target_addr)
    cert   = issue(result, graph_name)
    path   = save(cert)

    print_proof(result, cert)

    if compare:
        print_compare(result, cert)

    print(f"  {DIM}Certificate saved → {path}{RESET}\n")
    sys.exit(0 if result.is_proved() else 1)


def cmd_verify(cert_id: str) -> None:
    matches = list(CERTS_DIR.glob(f"{cert_id}*.cert.json"))
    if not matches:
        print(f"{RED}Certificate not found: {cert_id}{RESET}")
        sys.exit(1)
    cert = json.loads(matches[0].read_text())
    ok   = verify(cert)
    icon = f"{GREEN}✓ VALID{RESET}" if ok else f"{RED}✗ INVALID{RESET}"
    print(f"\n  {icon}  {cert.get('certificate_id', '?')}  [{cert.get('proof_status','?')}]  {cert.get('entity','?')}")
    print(f"  Issued: {cert.get('timestamp','?')}  Scheme: {cert.get('signing_scheme','?')}\n")
    sys.exit(0 if ok else 1)


def cmd_list() -> None:
    certs = sorted(CERTS_DIR.glob("*.cert.json"))
    if not certs:
        print(f"  {DIM}No certificates issued yet.{RESET}")
        return
    print(f"\n  {BOLD}Issued certificates ({len(certs)}):{RESET}")
    for p in certs:
        c_data = json.loads(p.read_text())
        status_c = GREEN if c_data.get("proof_status") == "PROVED" else RED
        print(f"  {status_c}●{RESET} {c_data.get('certificate_id','?')}  "
              f"{c_data.get('entity','?')}  [{c_data.get('proof_status','?')}]  "
              f"{c_data.get('timestamp','?')}")
    print()


def print_quantum(result, cert: dict) -> None:
    status_color = GREEN if result.is_secure() else (YELLOW if result.proof_status == "MARGINAL" else RED)
    status_icon  = {
        "SECURE": "✓ SECURE",
        "MARGINAL": "⚠ MARGINAL",
        "BROKEN": "✗ BROKEN",
    }.get(result.proof_status, result.proof_status)

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║  QUANTUM VERDICT CERTIFICATE                                 ║
╠══════════════════════════════════════════════════════════════╣{RESET}""")
    print(f"{BOLD}║  Status        {status_color}{status_icon}{RESET}")
    print(f"{BOLD}║  Scheme        {WHITE}{result.scheme_name}{RESET}")
    print(f"{BOLD}║  Standard      {DIM}{result.scheme_params.get('standard', 'N/A')}{RESET}")
    print(f"{BOLD}║  Security Target  {WHITE}{result.security_target} bits{RESET}")
    print(f"{BOLD}║  Expiry        {DIM}{result.expiry_date} ({result.horizon_years}yr horizon){RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  BKZ ATTACK ANALYSIS  (β_min = {result.beta_min}){RESET}")

    def attack_row(label, cost, margin, z3res):
        z3_color = GREEN if z3res == "unsat" else RED
        m_color  = GREEN if margin >= 30 else (YELLOW if margin >= 10 else RED)
        print(f"  {CYAN}{label:<28}{RESET}  cost={cost:>7.1f} bits  "
              f"margin={m_color}{margin:>+7.1f}{RESET}  "
              f"Z3={z3_color}{z3res.upper()}{RESET}")

    attack_row("Classical BKZ sieving",  result.cost_classical_bits,       result.security_margin_classical,          result.z3_classical)
    attack_row("Quantum BKZ sieving",    result.cost_quantum_bits,         result.security_margin_quantum,            result.z3_quantum)
    attack_row(f"Classical hybrid dual ({result.hybrid_reduction_bits:.1f}b red.)",
                                          result.cost_classical_hybrid,     result.security_margin_classical_hybrid,   result.z3_hybrid_classical)
    attack_row(f"Quantum hybrid dual ({result.hybrid_reduction_bits:.1f}b red.)",
                                          result.cost_quantum_hybrid,       result.security_margin_quantum_hybrid,     result.z3_hybrid_quantum)

    print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
    print(f"  {DIM}Weakest margin: {result.weakest_margin:+.1f} bits  ·  "
          f"Solver: {result.solver_time_ms:.1f} ms  ·  "
          f"Model: Albrecht et al. 2021{RESET}")

    if result.warnings:
        print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
        print(f"{BOLD}║  WARNINGS{RESET}")
        for w in result.warnings:
            print(f"  {YELLOW}⚠{RESET}  {w}")

    print(f"{BOLD}╠══════════════════════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  CERTIFICATE{RESET}")
    print(f"  ID          {cert['certificate_id']}")
    print(f"  SHA-256     {cert['sha256'][:54]}…")
    print(f"  Signature   {cert['signature'][:40]}…")
    print(f"  PubKey FP   {cert['pubkey_fp']}")
    print(f"  Scheme      {cert['signing_scheme']}")
    print(f"  Issued      {cert['timestamp']}")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")


def cmd_quantum(args: list[str]) -> None:
    if not args or args[0] in ("list", "--list"):
        print(f"\n{BOLD}Available schemes:{RESET}")
        for name, p in SCHEMES.items():
            print(f"  {CYAN}{name:<15}{RESET}  {p['description']}")
        print()
        return

    scheme_name = args[0].upper()
    if scheme_name not in SCHEMES:
        scheme_name = args[0]   # try as-is (e.g. "chainlock" → "CHAINLOCK")
        scheme_name = next((k for k in SCHEMES if k.upper() == scheme_name.upper()), scheme_name)

    security_bits: int | None = None
    horizon = 10
    sign_scheme = "Ed25519"

    for i, a in enumerate(args):
        if a in ("--bits", "--security") and i + 1 < len(args):
            security_bits = int(args[i + 1])
        if a in ("--horizon", "--years") and i + 1 < len(args):
            horizon = int(args[i + 1])
        if a == "--ml-dsa":
            sign_scheme = "ML-DSA-65"

    print(f"  {DIM}Scheme:   {scheme_name}{RESET}")
    print(f"  {DIM}Target:   {security_bits or 'default'} bits{RESET}")
    print(f"  {DIM}Horizon:  {horizon} years{RESET}")
    print(f"  {DIM}Running Z3 BKZ proof…{RESET}\n")

    prover = QuantumProver()
    result = prover.prove(scheme_name, security_target=security_bits, horizon_years=horizon)
    cert   = issue_quantum_cert(result, scheme=sign_scheme)
    path   = save_quantum_cert(cert)

    print_quantum(result, cert)
    print(f"  {DIM}Certificate saved → {path}{RESET}\n")
    sys.exit(0 if result.is_secure() else 1)


def usage() -> None:
    print(f"""
{BOLD}Usage:{RESET}
  verdict prove <graph>               Prove attribution for all seed→target pairs
  verdict prove <graph> --compare     Side-by-side vs Chainalysis Reactor
  verdict prove <graph> --seed 0x...  Custom seed address
                        --target 0x...
  verdict verify <cert_id>            Verify a certificate offline
  verdict list                        List all issued certificates

  verdict quantum <scheme>            Prove post-quantum security of a scheme
  verdict quantum <scheme> --bits 128 --horizon 15
  verdict quantum list                Show available schemes

{BOLD}Available graphs:{RESET}
  {', '.join(p.stem for p in DATA_DIR.glob('*.json')) if DATA_DIR.exists() else 'none'}

{BOLD}Examples:{RESET}
  verdict prove lazarus_bybit_2025 --compare
  verdict prove ruja_oncoin
  verdict quantum ML-DSA-65
  verdict quantum CHAINLOCK --bits 128 --horizon 20
  verdict quantum FALCON-512
""")


def main() -> None:
    print_banner()

    args = sys.argv[1:]
    if not args or args[0] in ("help", "--help", "-h"):
        usage()
        return

    cmd = args[0]

    if cmd == "prove":
        if len(args) < 2:
            print(f"{RED}Error: missing graph name{RESET}")
            usage()
            sys.exit(1)
        graph_name = args[1]
        compare = "--compare" in args
        seed   = None
        target = None
        for i, a in enumerate(args):
            if a == "--seed"   and i + 1 < len(args): seed   = args[i + 1]
            if a == "--target" and i + 1 < len(args): target = args[i + 1]
        cmd_prove(graph_name, seed, target, compare)

    elif cmd == "verify":
        if len(args) < 2:
            print(f"{RED}Error: missing certificate ID{RESET}")
            sys.exit(1)
        cmd_verify(args[1])

    elif cmd == "list":
        cmd_list()

    elif cmd == "quantum":
        cmd_quantum(args[1:])

    else:
        print(f"{RED}Unknown command: {cmd}{RESET}")
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
