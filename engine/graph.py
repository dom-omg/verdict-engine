"""
graph.py — Blockchain transaction graph data model for VERDICT ENGINE.

A TxGraph is the input to the Z3 attribution prover.
Addresses are canonical hex strings. Transactions carry their on-chain metadata.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Transaction:
    hash: str                       # 0x... tx hash
    block: int                      # block number
    chain: str                      # "ethereum" | "bitcoin" | "polygon" | ...
    inputs: list[str]               # input addresses
    outputs: list[str]              # output addresses
    values_eth: dict[str, float]    # {address: value_in_native_token}
    change_address: Optional[str] = None  # explicitly tagged change output
    metadata: dict = field(default_factory=dict)  # e.g. {"mixer": True}


@dataclass
class TxGraph:
    name: str                       # e.g. "lazarus_bybit_2025"
    entity_name: str                # human label, e.g. "Lazarus Group / APT38"
    seed_addresses: list[str]       # previously attributed (OFAC, FBI, etc.)
    target_addresses: list[str]     # addresses under investigation
    transactions: list[Transaction]
    known_exchanges: set[str] = field(default_factory=set)
    known_mixers: set[str] = field(default_factory=set)
    address_labels: dict[str, str] = field(default_factory=dict)  # addr → human label

    @property
    def addresses(self) -> list[str]:
        seen = []
        for tx in self.transactions:
            for a in tx.inputs + tx.outputs:
                if a not in seen:
                    seen.append(a)
        return seen

    def is_exchange(self, addr: str) -> bool:
        return addr in self.known_exchanges

    def is_mixer(self, addr: str) -> bool:
        return addr in self.known_mixers

    @classmethod
    def from_json(cls, path: str) -> "TxGraph":
        with open(path) as f:
            d = json.load(f)
        txs = [
            Transaction(
                hash=t["hash"],
                block=t["block"],
                chain=t["chain"],
                inputs=t["inputs"],
                outputs=t["outputs"],
                values_eth=t.get("values_eth", {}),
                change_address=t.get("change_address"),
                metadata=t.get("metadata", {}),
            )
            for t in d["transactions"]
        ]
        return cls(
            name=d["name"],
            entity_name=d["entity_name"],
            seed_addresses=d["seed_addresses"],
            target_addresses=d["target_addresses"],
            transactions=txs,
            known_exchanges=set(d.get("known_exchanges", [])),
            known_mixers=set(d.get("known_mixers", [])),
            address_labels=d.get("address_labels", {}),
        )
