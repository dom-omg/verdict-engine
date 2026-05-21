"""
prover.py — Z3 attribution proof engine for VERDICT ENGINE.

Takes a TxGraph + AttributionClaim, runs the axiom set through Z3,
and emits a structured ProofResult with full derivation trace.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from z3 import sat, unsat

from engine.graph import TxGraph
from engine.axioms import AxiomSet, AxiomApplication


@dataclass
class DerivationStep:
    step: int
    axiom: str
    tx_hash: str
    from_addr: str
    to_addr: str
    description: str


@dataclass
class ProofResult:
    status: str                         # "PROVED" | "NOT_PROVED" | "ERROR"
    claim_seed: str
    claim_target: str
    entity_name: str
    axioms_applied: list[str]
    derivation: list[AxiomApplication]
    derivation_steps: list[DerivationStep]
    z3_result: str                      # "unsat" | "sat" | "unknown"
    solver_time_ms: float
    hop_count: int
    gap: Optional[str] = None           # if NOT_PROVED, why
    error: Optional[str] = None

    def is_proved(self) -> bool:
        return self.status == "PROVED"


def prove(graph: TxGraph, seed_addr: str, target_addr: str) -> ProofResult:
    """
    Core proof function.

    Encodes the graph's transaction patterns as Z3 Int equality constraints
    via the AxiomSet, then checks whether the negation of the attribution
    claim (entity[seed] ≠ entity[target]) is UNSAT.

    UNSAT → claim is provable under stated axioms (no possible world where
            the axioms hold and the attribution is false).
    SAT   → claim is not yet provable; returns witness showing the gap.
    """
    if seed_addr not in graph.addresses:
        return ProofResult(
            status="ERROR", claim_seed=seed_addr, claim_target=target_addr,
            entity_name=graph.entity_name, axioms_applied=[], derivation=[],
            derivation_steps=[], z3_result="error", solver_time_ms=0.0,
            hop_count=0, error=f"Seed address not found in graph: {seed_addr}",
        )
    if target_addr not in graph.addresses:
        return ProofResult(
            status="ERROR", claim_seed=seed_addr, claim_target=target_addr,
            entity_name=graph.entity_name, axioms_applied=[], derivation=[],
            derivation_steps=[], z3_result="error", solver_time_ms=0.0,
            hop_count=0, error=f"Target address not found in graph: {target_addr}",
        )

    axiom_set = AxiomSet(graph=graph)
    solver, entities = axiom_set.build_solver()

    # Assert the NEGATION of the attribution claim
    solver.push()
    solver.add(entities[seed_addr] != entities[target_addr])

    t0 = time.perf_counter()
    result = solver.check()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    solver.pop()

    axiom_ids = sorted(set(a.axiom_id for a in axiom_set.applied))

    # Build human-readable derivation steps
    steps = []
    seed_entity_addr = seed_addr
    step_idx = 1
    for app in axiom_set.applied:
        if seed_addr in app.addresses or target_addr in app.addresses:
            steps.append(DerivationStep(
                step=step_idx,
                axiom=app.axiom_id,
                tx_hash=app.tx_hash,
                from_addr=app.addresses[0],
                to_addr=app.addresses[1] if len(app.addresses) > 1 else app.addresses[0],
                description=app.description,
            ))
            step_idx += 1

    # Also include all CIO/CAD steps that form the chain
    chain_steps = _extract_chain(axiom_set.applied, seed_addr, target_addr)
    hop_count = len(chain_steps)

    if result == unsat:
        return ProofResult(
            status="PROVED",
            claim_seed=seed_addr,
            claim_target=target_addr,
            entity_name=graph.entity_name,
            axioms_applied=axiom_ids,
            derivation=axiom_set.applied,
            derivation_steps=chain_steps,
            z3_result="unsat",
            solver_time_ms=round(elapsed_ms, 2),
            hop_count=hop_count,
        )
    elif result == sat:
        gap_model = solver.model() if result == sat else None
        gap_msg = None
        if gap_model:
            sv = gap_model[entities[seed_addr]]
            tv = gap_model[entities[target_addr]]
            gap_msg = (
                f"entity[{seed_addr[:10]}…]={sv} ≠ entity[{target_addr[:10]}…]={tv} "
                f"— no transaction chain connects seed to target under current axioms"
            )
        return ProofResult(
            status="NOT_PROVED",
            claim_seed=seed_addr,
            claim_target=target_addr,
            entity_name=graph.entity_name,
            axioms_applied=axiom_ids,
            derivation=axiom_set.applied,
            derivation_steps=chain_steps,
            z3_result="sat",
            solver_time_ms=round(elapsed_ms, 2),
            hop_count=hop_count,
            gap=gap_msg,
        )
    else:
        return ProofResult(
            status="ERROR",
            claim_seed=seed_addr,
            claim_target=target_addr,
            entity_name=graph.entity_name,
            axioms_applied=axiom_ids,
            derivation=axiom_set.applied,
            derivation_steps=chain_steps,
            z3_result="unknown",
            solver_time_ms=round(elapsed_ms, 2),
            hop_count=0,
            error="Z3 returned unknown — increase solver timeout or simplify graph",
        )


def _extract_chain(
    applications: list[AxiomApplication],
    seed: str,
    target: str,
) -> list[DerivationStep]:
    """
    BFS through the axiom applications to find the shortest derivation
    chain from seed to target. Returns ordered DerivationSteps.
    """
    # Build adjacency: addr → [AxiomApplication linking it to another addr]
    adj: dict[str, list[tuple[str, AxiomApplication]]] = {}
    for app in applications:
        for i, a in enumerate(app.addresses):
            for j, b in enumerate(app.addresses):
                if i != j:
                    adj.setdefault(a, []).append((b, app))

    # BFS
    from collections import deque
    visited: set[str] = {seed}
    queue: deque[tuple[str, list[tuple[str, AxiomApplication]]]] = deque([(seed, [])])

    while queue:
        node, path = queue.popleft()
        if node == target:
            steps = []
            for idx, (addr, app) in enumerate(path, 1):
                prev = path[idx - 2][0] if idx >= 2 else seed
                steps.append(DerivationStep(
                    step=idx,
                    axiom=app.axiom_id,
                    tx_hash=app.tx_hash,
                    from_addr=prev,
                    to_addr=addr,
                    description=app.description,
                ))
            return steps
        for neighbor, app in adj.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [(neighbor, app)]))

    return []
