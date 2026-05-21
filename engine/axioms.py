"""
axioms.py — Z3 attribution axioms for blockchain forensics.

Each axiom maps a transaction pattern to an entity equivalence constraint.
Axioms are the formal specification of what "same controller" means.

References:
  CIO — Common-Input Ownership (Nakamoto 2008 §10, Meiklejohn et al. 2013)
  CAD — Change Address Detection (Androulaki et al. 2012)
  PEEL — Peeling Chain heuristic (Reid & Harrigan 2011)
  XFR — Exchange Deposit Fan-In (Möser et al. 2017)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from z3 import Int, Solver, sat, unsat, unknown

if TYPE_CHECKING:
    from engine.graph import TxGraph


@dataclass
class AxiomApplication:
    axiom_id: str       # "CIO" | "CAD" | "PEEL" | "XFR"
    tx_hash: str
    addresses: list[str]
    description: str


@dataclass
class AxiomSet:
    """
    Encodes blockchain attribution axioms as Z3 Int equality constraints.

    Each address in the graph gets an Int variable entity[addr].
    Axioms constrain which entities must be equal.
    The attribution claim is: entity[seed] == entity[target].
    We prove it by checking UNSAT of the negation.
    """
    graph: "TxGraph"
    applied: list[AxiomApplication] = field(default_factory=list)

    def _entity_var_name(self, addr: str) -> str:
        idx = self.graph.addresses.index(addr)
        return f"e_{idx}"

    def build_solver(self) -> tuple[Solver, dict[str, object]]:
        """
        Returns (solver, entity_vars) where entity_vars maps addr → z3.Int.
        The solver contains all axiom constraints.
        """
        addrs = self.graph.addresses
        entities: dict[str, object] = {
            addr: Int(self._entity_var_name(addr)) for addr in addrs
        }

        s = Solver()

        # Entity IDs are positive integers
        for e in entities.values():
            s.add(e > 0)

        for tx in self.graph.transactions:
            self._apply_cio(s, entities, tx)
            self._apply_cad(s, entities, tx)
            self._apply_peel(s, entities, tx)
            self._apply_xfr(s, entities, tx)

        return s, entities

    def _apply_cio(self, s: Solver, entities: dict, tx) -> None:
        """
        CIO — Common-Input Ownership:
        All inputs in a transaction share a single controlling entity.
        Rationale: spending from an address requires the private key;
        a tx with N inputs was signed by whoever controls all N keys.
        """
        inputs = [a for a in tx.inputs if a in entities]
        for i in range(len(inputs)):
            for j in range(i + 1, len(inputs)):
                s.add(entities[inputs[i]] == entities[inputs[j]])
                self.applied.append(AxiomApplication(
                    axiom_id="CIO",
                    tx_hash=tx.hash,
                    addresses=[inputs[i], inputs[j]],
                    description=f"CIO: inputs {inputs[i][:10]}… and {inputs[j][:10]}… "
                                f"co-sign tx {tx.hash[:10]}…",
                ))

    def _apply_cad(self, s: Solver, entities: dict, tx) -> None:
        """
        CAD — Change Address Detection:
        A transaction output explicitly tagged as 'change' is controlled
        by the same entity as the transaction sender (first input).
        """
        if not tx.change_address or tx.change_address not in entities:
            return
        if not tx.inputs or tx.inputs[0] not in entities:
            return
        sender = tx.inputs[0]
        change = tx.change_address
        s.add(entities[change] == entities[sender])
        self.applied.append(AxiomApplication(
            axiom_id="CAD",
            tx_hash=tx.hash,
            addresses=[sender, change],
            description=f"CAD: change output {change[:10]}… → same entity as sender "
                        f"{sender[:10]}… in tx {tx.hash[:10]}…",
        ))

    def _apply_peel(self, s: Solver, entities: dict, tx) -> None:
        """
        PEEL — Peeling Chain:
        A tx with exactly 2 outputs where one is a known exchange deposit
        implies the other output is change (same entity as sender).
        """
        if len(tx.outputs) != 2:
            return
        if not tx.inputs or tx.inputs[0] not in entities:
            return
        exchange_outs = [o for o in tx.outputs if self.graph.is_exchange(o) and o in entities]
        change_outs = [o for o in tx.outputs if not self.graph.is_exchange(o) and o in entities]
        if len(exchange_outs) != 1 or len(change_outs) != 1:
            return
        sender = tx.inputs[0]
        change = change_outs[0]
        s.add(entities[change] == entities[sender])
        self.applied.append(AxiomApplication(
            axiom_id="PEEL",
            tx_hash=tx.hash,
            addresses=[sender, change, exchange_outs[0]],
            description=f"PEEL: tx {tx.hash[:10]}… sends to exchange {exchange_outs[0][:10]}…; "
                        f"change {change[:10]}… → same entity as {sender[:10]}…",
        ))

    def _apply_xfr(self, s: Solver, entities: dict, tx) -> None:
        """
        XFR — Exchange Fan-In:
        If all inputs are known to belong to the same entity (from prior constraints)
        and a new address appears as co-input, it joins the same cluster.
        Applies when tx.metadata["fan_in"] == True.
        """
        if not tx.metadata.get("fan_in"):
            return
        inputs = [a for a in tx.inputs if a in entities]
        for i in range(len(inputs)):
            for j in range(i + 1, len(inputs)):
                s.add(entities[inputs[i]] == entities[inputs[j]])
                self.applied.append(AxiomApplication(
                    axiom_id="XFR",
                    tx_hash=tx.hash,
                    addresses=[inputs[i], inputs[j]],
                    description=f"XFR: fan-in tx {tx.hash[:10]}…: "
                                f"{inputs[i][:10]}… and {inputs[j][:10]}… merge entity",
                ))
