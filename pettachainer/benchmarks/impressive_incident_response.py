#!/usr/bin/env python3
"""Proof-backed incident-response demo for PeTTaChainer.

The scenario is intentionally small enough to run quickly, but it combines
recursive compromise propagation, distractor infrastructure, data sensitivity
facts, and policy rules that turn inferred incidents into actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pettachainer import PeTTaChainer


STV_RE = re.compile(r"\(STV\s+([^\s\)]+)\s+([^\s\)]+)\)")
ATOM_LABEL_RE = re.compile(r"^\(:\s+([^\s\)]+)")

PRIMARY_CHAIN = [
    ("Laptop", "VPN"),
    ("VPN", "BuildServer"),
    ("BuildServer", "ArtifactRegistry"),
    ("ArtifactRegistry", "DeployBot"),
    ("DeployBot", "ProdCluster"),
    ("ProdCluster", "CustomerDB"),
]

SECONDARY_CHAIN = [
    ("TokenVault", "IAM"),
    ("IAM", "ProdCluster"),
    ("ProdCluster", "CustomerDB"),
]

NOISE_EDGES = [
    ("Printer", "GuestWifi"),
    ("GuestWifi", "LobbyTV"),
    ("Docs", "Wiki"),
    ("CIWorker", "Cache"),
    ("Cache", "Mirror"),
    ("Sandbox", "ToyDB"),
    ("Phone", "MDM"),
    ("MDM", "Inventory"),
    ("DevBox", "Staging"),
    ("Staging", "DemoDB"),
    ("Metrics", "Dashboard"),
    ("Dashboard", "Pager"),
    ("VendorPortal", "Invoices"),
    ("Invoices", "Archive"),
    ("TestHarness", "FakeProd"),
]

REPLAY_QUERIES = {
    "compromised_customerdb": "(: $prf (Compromised CustomerDB) $tv)",
    "critical_customerdb": "(: $prf (CriticalIncident CustomerDB) $tv)",
    "isolate_customerdb": "(: $prf (Action Isolate CustomerDB) $tv)",
    "rotate_customerdb": "(: $prf (Action RotateSecrets CustomerDB) $tv)",
    "compromised_demodb": "(: $prf (Compromised DemoDB) $tv)",
    "isolate_demodb": "(: $prf (Action Isolate DemoDB) $tv)",
    "compromised_iam": "(: $prf (Compromised IAM) $tv)",
}


@dataclass
class IngressExplanation:
    name: str
    isolate_customerdb: int
    truth_value: tuple[float, float] | None
    strength: float
    confidence: float
    proof_tokens: dict[str, int]
    proof_sha256: str


@dataclass
class AblationCase:
    name: str
    mode: str
    removed_labels: list[str]
    expected_isolate_customerdb: int
    isolate_customerdb: int
    proof_tokens: dict[str, int]
    proof_sha256: str
    passed: bool


@dataclass
class DemoResult:
    runtime_s: float
    forward_steps: int
    query_steps: int
    facts: int
    rules: int
    noise_edges: int
    phase_timings_s: dict[str, float]
    forward_result: list[str]
    query_counts: dict[str, int]
    truth_values: dict[str, tuple[float, float] | None]
    isolate_proof_tokens: dict[str, int]
    ingress_ranking: list[IngressExplanation]
    ingress_confidence_margin: float
    causal_ablation: list[AblationCase]
    causal_checks: dict[str, bool]
    counterfactuals: dict[str, dict[str, int]]
    checks: dict[str, bool]
    proof_ladder: list[str]
    proof_structure: dict[str, object]
    raw_isolate_proof: str
    proof_sha256: str
    scenario_sha256: str
    no_pii_isolate_count: int
    trace_path: str


@contextmanager
def redirect_process_output(path: Path):
    """Redirect Python and SWI-Prolog stdout/stderr at file-descriptor level."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)
        try:
            os.dup2(handle.fileno(), 1)
            os.dup2(handle.fileno(), 2)
            yield
        finally:
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            os.close(saved_stdout)
            os.close(saved_stderr)


def first(items: list[str]) -> str:
    return items[0] if items else ""


def parse_stv(proof: str) -> tuple[float, float] | None:
    match = STV_RE.search(proof)
    if not match:
        return None
    return float(match.group(1)), float(match.group(2))


def add_all(handler: PeTTaChainer, atoms: Iterable[str]) -> int:
    count = 0
    for atom in atoms:
        handler.add_atom(atom)
        count += 1
    return count


def fact_atoms(
    include_customer_pii: bool,
    include_entry_points: bool,
    include_phish_laptop: bool = True,
    include_token_seed: bool = True,
) -> list[str]:
    atoms = [
        "(: demodb_pii (StoresPII DemoDB) (STV 0.90 0.75))",
        "(: prod_tier (Tier CustomerDB CrownJewels) (STV 1.0 0.95))",
    ]
    if include_entry_points:
        if include_phish_laptop:
            atoms.append("(: phish_laptop (Compromised Laptop) (STV 0.96 0.92))")
        if include_token_seed:
            atoms.append("(: token_seed (Compromised TokenVault) (STV 0.72 0.80))")
    if include_customer_pii:
        atoms.append("(: customerdb_pii (StoresPII CustomerDB) (STV 0.99 0.96))")
    for idx, (src, dst) in enumerate(PRIMARY_CHAIN, start=1):
        atoms.append(f"(: trust_primary_{idx} (Trusts {src} {dst}) (STV 0.95 0.90))")
    for idx, (src, dst) in enumerate(SECONDARY_CHAIN, start=1):
        atoms.append(f"(: trust_secondary_{idx} (Trusts {src} {dst}) (STV 0.78 0.72))")
    for idx, (src, dst) in enumerate(NOISE_EDGES, start=1):
        atoms.append(f"(: noise_{idx} (Trusts {src} {dst}) (STV 0.80 0.60))")
    return atoms


def rule_atoms(include_isolate_policy: bool) -> list[str]:
    atoms = [
        "(: lateral_move "
        "(Implication (Premises (Compromised $x) (Trusts $x $y)) "
        "(Conclusions (Compromised $y))) "
        "(STV 0.94 0.91))",
        "(: pii_incident "
        "(Implication (Premises (Compromised $x) (StoresPII $x)) "
        "(Conclusions (CriticalIncident $x))) "
        "(STV 0.98 0.94))",
        "(: rotate_policy "
        "(Implication (Premises (CriticalIncident $x)) "
        "(Conclusions (Action RotateSecrets $x))) "
        "(STV 0.97 0.93))",
    ]
    if include_isolate_policy:
        atoms.append(
            "(: isolate_policy "
            "(Implication (Premises (CriticalIncident $x)) "
            "(Conclusions (Action Isolate $x))) "
            "(STV 0.99 0.97))"
        )
    return atoms


def scenario_atoms(
    include_customer_pii: bool = True,
    include_entry_points: bool = True,
    include_isolate_policy: bool = True,
    include_phish_laptop: bool = True,
    include_token_seed: bool = True,
) -> list[str]:
    return fact_atoms(
        include_customer_pii=include_customer_pii,
        include_entry_points=include_entry_points,
        include_phish_laptop=include_phish_laptop,
        include_token_seed=include_token_seed,
    ) + rule_atoms(include_isolate_policy=include_isolate_policy)


def scenario_text() -> str:
    return "\n".join(scenario_atoms()) + "\n"


def scenario_atoms_from_text(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]


def atom_label(atom: str) -> str:
    match = ATOM_LABEL_RE.match(atom)
    if not match:
        raise ValueError(f"Could not extract atom label from: {atom}")
    return match.group(1)


def without_atom_labels(atoms: Iterable[str], labels: Iterable[str]) -> list[str]:
    excluded = set(labels)
    return [atom for atom in atoms if atom_label(atom) not in excluded]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_numbered_tokens(proof: str, prefix: str, total: int) -> int:
    return sum(1 for idx in range(1, total + 1) if f"{prefix}{idx}" in proof)


def audit_proof_tokens(proof: str) -> dict[str, int]:
    primary_edges = count_numbered_tokens(proof, "trust_primary_", len(PRIMARY_CHAIN))
    secondary_edges = count_numbered_tokens(
        proof, "trust_secondary_", len(SECONDARY_CHAIN)
    )
    noise_edges = count_numbered_tokens(proof, "noise_", len(NOISE_EDGES))
    return {
        "lateral_move": primary_edges if "lateral_move" in proof else 0,
        "pii_incident": int("pii_incident" in proof),
        "isolate_policy": int("isolate_policy" in proof),
        "rotate_policy": int("rotate_policy" in proof),
        "phish_laptop": int("phish_laptop" in proof),
        "token_seed": int("token_seed" in proof),
        "trust_primary_": primary_edges,
        "trust_secondary_": secondary_edges,
        "noise_": noise_edges,
    }


def build_handler(
    include_customer_pii: bool = True,
    include_entry_points: bool = True,
    include_isolate_policy: bool = True,
    include_phish_laptop: bool = True,
    include_token_seed: bool = True,
) -> tuple[PeTTaChainer, int, int]:
    handler = PeTTaChainer()
    facts = add_all(
        handler,
        fact_atoms(
            include_customer_pii=include_customer_pii,
            include_entry_points=include_entry_points,
            include_phish_laptop=include_phish_laptop,
            include_token_seed=include_token_seed,
        ),
    )
    rules = add_all(handler, rule_atoms(include_isolate_policy=include_isolate_policy))
    return handler, facts, rules


def build_handler_from_atoms(atoms: Iterable[str]) -> PeTTaChainer:
    handler = PeTTaChainer()
    for atom in atoms:
        handler.add_atom(atom)
    return handler


def count_query(handler: PeTTaChainer, query: str, steps: int) -> int:
    return len(handler.query(query, steps=steps, timeout_sec=0))


def query_one(handler: PeTTaChainer, query: str, steps: int) -> str:
    return first(handler.query(query, steps=steps, timeout_sec=0))


def isolate_counterfactual(handler: PeTTaChainer, query_steps: int) -> dict[str, int]:
    compromised = count_query(
        handler, "(: $prf (Compromised CustomerDB) $tv)", query_steps
    )
    proof = query_one(handler, "(: $prf (Action Isolate CustomerDB) $tv)", query_steps)
    tokens = audit_proof_tokens(proof)
    return {
        "compromised_customerdb": compromised,
        "isolate_customerdb": int(bool(proof)),
        "phish_laptop": tokens["phish_laptop"],
        "token_seed": tokens["token_seed"],
        "trust_primary_": tokens["trust_primary_"],
        "trust_secondary_": tokens["trust_secondary_"],
        "noise_": tokens["noise_"],
    }


def build_ranked_ingress_explanation(
    name: str,
    include_phish_laptop: bool,
    include_token_seed: bool,
    forward_steps: int,
    query_steps: int,
) -> IngressExplanation:
    handler, _facts, _rules = build_handler(
        include_phish_laptop=include_phish_laptop,
        include_token_seed=include_token_seed,
    )
    handler.forward_chain(steps=forward_steps)
    proof = query_one(handler, "(: $prf (Action Isolate CustomerDB) $tv)", query_steps)
    truth = parse_stv(proof)
    strength, confidence = truth if truth is not None else (0.0, 0.0)
    return IngressExplanation(
        name=name,
        isolate_customerdb=int(bool(proof)),
        truth_value=truth,
        strength=strength,
        confidence=confidence,
        proof_tokens=audit_proof_tokens(proof),
        proof_sha256=sha256_text(proof) if proof else "",
    )


def ingress_explanation_ranking(
    forward_steps: int, query_steps: int
) -> list[IngressExplanation]:
    explanations = [
        build_ranked_ingress_explanation(
            "primary_laptop_path",
            include_phish_laptop=True,
            include_token_seed=False,
            forward_steps=forward_steps,
            query_steps=query_steps,
        ),
        build_ranked_ingress_explanation(
            "fallback_tokenvault_path",
            include_phish_laptop=False,
            include_token_seed=True,
            forward_steps=forward_steps,
            query_steps=query_steps,
        ),
    ]
    return sorted(
        explanations,
        key=lambda item: (item.confidence, item.strength, item.name),
        reverse=True,
    )


def ranking_margin(ranking: list[IngressExplanation]) -> float:
    if len(ranking) < 2:
        return 0.0
    return ranking[0].confidence - ranking[1].confidence


def run_ablation_case(
    name: str,
    mode: str,
    base_atoms: list[str],
    removed_labels: list[str],
    expected_isolate_customerdb: int,
    forward_steps: int,
    query_steps: int,
) -> AblationCase:
    handler = build_handler_from_atoms(without_atom_labels(base_atoms, removed_labels))
    handler.forward_chain(steps=forward_steps)
    proof = query_one(handler, REPLAY_QUERIES["isolate_customerdb"], query_steps)
    tokens = audit_proof_tokens(proof)
    isolate_count = int(bool(proof))
    return AblationCase(
        name=name,
        mode=mode,
        removed_labels=removed_labels,
        expected_isolate_customerdb=expected_isolate_customerdb,
        isolate_customerdb=isolate_count,
        proof_tokens=tokens,
        proof_sha256=sha256_text(proof) if proof else "",
        passed=isolate_count == expected_isolate_customerdb,
    )


def causal_ablation_certificate(
    forward_steps: int, query_steps: int
) -> tuple[list[AblationCase], dict[str, bool]]:
    primary_atoms = without_atom_labels(
        scenario_atoms(include_token_seed=False),
        [f"trust_secondary_{idx}" for idx in range(1, len(SECONDARY_CHAIN) + 1)],
    )
    primary_required = [
        "phish_laptop",
        *(f"trust_primary_{idx}" for idx in range(1, len(PRIMARY_CHAIN) + 1)),
        "customerdb_pii",
        "lateral_move",
        "pii_incident",
        "isolate_policy",
    ]
    cases = [
        run_ablation_case(
            name=f"remove_{label}",
            mode="primary_path_minimality",
            base_atoms=primary_atoms,
            removed_labels=[label],
            expected_isolate_customerdb=0,
            forward_steps=forward_steps,
            query_steps=query_steps,
        )
        for label in primary_required
    ]
    cases.append(
        run_ablation_case(
            name="remove_all_distractor_trust_edges",
            mode="distractor_invariance",
            base_atoms=scenario_atoms(),
            removed_labels=[f"noise_{idx}" for idx in range(1, len(NOISE_EDGES) + 1)],
            expected_isolate_customerdb=1,
            forward_steps=forward_steps,
            query_steps=query_steps,
        )
    )
    primary_cases = [
        case for case in cases if case.mode == "primary_path_minimality"
    ]
    distractor_case = next(
        case for case in cases if case.mode == "distractor_invariance"
    )
    checks = {
        "primary_path_single_atom_ablations_block_isolation": all(
            case.passed and case.isolate_customerdb == 0 for case in primary_cases
        ),
        "distractor_removal_preserves_isolation": (
            distractor_case.passed
            and distractor_case.isolate_customerdb == 1
            and distractor_case.proof_tokens["noise_"] == 0
        ),
    }
    return cases, checks


def counterfactual_counts(forward_steps: int, query_steps: int) -> dict[str, dict[str, int]]:
    no_pii_handler, _facts, _rules = build_handler(include_customer_pii=False)
    no_pii_handler.forward_chain(steps=forward_steps)

    no_entry_handler, _facts, _rules = build_handler(include_entry_points=False)
    no_entry_handler.forward_chain(steps=forward_steps)

    no_phish_handler, _facts, _rules = build_handler(include_phish_laptop=False)
    no_phish_handler.forward_chain(steps=forward_steps)

    no_token_handler, _facts, _rules = build_handler(include_token_seed=False)
    no_token_handler.forward_chain(steps=forward_steps)

    no_policy_handler, _facts, _rules = build_handler(include_isolate_policy=False)
    no_policy_handler.forward_chain(steps=forward_steps)

    return {
        "without_customerdb_pii": {
            "isolate_customerdb": count_query(
                no_pii_handler, "(: $prf (Action Isolate CustomerDB) $tv)", query_steps
            ),
        },
        "without_initial_compromise": {
            "compromised_customerdb": count_query(
                no_entry_handler, "(: $prf (Compromised CustomerDB) $tv)", query_steps
            ),
            "isolate_customerdb": count_query(
                no_entry_handler, "(: $prf (Action Isolate CustomerDB) $tv)", query_steps
            ),
        },
        "without_phishing_seed": isolate_counterfactual(no_phish_handler, query_steps),
        "without_token_seed": isolate_counterfactual(no_token_handler, query_steps),
        "without_isolate_policy": {
            "critical_customerdb": count_query(
                no_policy_handler, "(: $prf (CriticalIncident CustomerDB) $tv)", query_steps
            ),
            "isolate_customerdb": count_query(
                no_policy_handler, "(: $prf (Action Isolate CustomerDB) $tv)", query_steps
            ),
        },
    }


def run_queries(handler: PeTTaChainer, steps: int) -> dict[str, list[str]]:
    return {
        name: handler.query(query, steps=steps, timeout_sec=0)
        for name, query in REPLAY_QUERIES.items()
    }


def proof_ladder() -> list[str]:
    ladder = ["phish_laptop proves Compromised Laptop"]
    current = "Laptop"
    for idx, (_src, dst) in enumerate(PRIMARY_CHAIN, start=1):
        ladder.append(f"trust_primary_{idx}: Compromised {current} -> Compromised {dst}")
        current = dst
    ladder.extend(
        [
            "customerdb_pii gates the compromise into CriticalIncident CustomerDB",
            "isolate_policy turns the critical incident into Action Isolate CustomerDB",
        ]
    )
    return ladder


_AUDIT_HANDLER: "PeTTaChainer | None" = None


def _audit_handler() -> PeTTaChainer:
    """Cached handler hosting the MeTTa proof_structure_audit heads."""
    global _AUDIT_HANDLER
    if _AUDIT_HANDLER is None:
        _AUDIT_HANDLER = PeTTaChainer()
    return _AUDIT_HANDLER


def _audit_first(handler: PeTTaChainer, expr: str) -> str:
    raw = handler.handler.process_metta_string(expr)
    items = [raw] if isinstance(raw, str) else list(raw)
    for item in items:
        text = str(item).strip()
        if text and text != "()":
            return text
    return ""


def _audit_count(handler: PeTTaChainer, symbol: str, proof: str) -> int:
    return int(_audit_first(handler, f"!(count-token {symbol} {proof})") or 0)


def _audit_count_any(handler: PeTTaChainer, labels: list[str], proof: str) -> int:
    group = "(" + " ".join(labels) + ")"
    return int(_audit_first(handler, f"!(count-any {group} {proof})") or 0)


def _audit_bool(handler: PeTTaChainer, expr: str) -> bool:
    return _audit_first(handler, expr).strip().lower() == "true"


def _empty_proof_certificate(
    raw_proof: str, expected_primary: list[str], error: str
) -> dict[str, object]:
    return {
        "certificate_kind": "pettachainer_structural_proof_audit",
        "proof_sha256": sha256_text(raw_proof),
        "target_action": "Action Isolate CustomerDB",
        "truth_value": None,
        "expected_primary_chain": expected_primary,
        "operator_counts": {},
        "forbidden_label_counts": {},
        "checks": {"parse_ok": False},
        "error": error,
        "certificate_passes": False,
    }


def proof_structure_certificate(
    raw_proof: str, handler: "PeTTaChainer | None" = None
) -> dict[str, object]:
    # Structural audit by native MeTTa matching (proof_structure_audit.metta).
    # The proof is already a structured atom, so we hand it to the MeTTa heads
    # instead of parsing it in Python. Counts over the whole result atom equal
    # counts over the proof term (the Action/STV parts carry none of the labels).
    expected_primary = [f"trust_primary_{idx}" for idx in range(1, len(PRIMARY_CHAIN) + 1)]
    if not raw_proof or not raw_proof.strip():
        return _empty_proof_certificate(raw_proof, expected_primary, "empty proof")

    audit = handler if handler is not None else _audit_handler()
    n = len(PRIMARY_CHAIN)
    operator_counts = {
        "merge/revision": _audit_count(audit, "merge/revision", raw_proof),
        "rule-proof": _audit_count(audit, "rule-proof", raw_proof),
        "lateral_move": _audit_count(audit, "lateral_move", raw_proof),
        "pii_incident": _audit_count(audit, "pii_incident", raw_proof),
        "isolate_policy": _audit_count(audit, "isolate_policy", raw_proof),
    }
    forbidden_counts = {
        "noise_": _audit_count_any(
            audit, [f"noise_{i}" for i in range(1, len(NOISE_EDGES) + 1)], raw_proof
        ),
        "trust_secondary_": _audit_count_any(
            audit, [f"trust_secondary_{i}" for i in range(1, len(SECONDARY_CHAIN) + 1)], raw_proof
        ),
        "rotate_policy": _audit_count(audit, "rotate_policy", raw_proof),
        "token_seed": _audit_count(audit, "token_seed", raw_proof),
    }
    truth = parse_stv(raw_proof)
    truth_value = (
        {"strength": truth[0], "confidence": truth[1]} if truth is not None else None
    )
    checks = {
        "parse_ok": True,
        "target_action_matches": "(Action Isolate CustomerDB)" in raw_proof,
        "truth_value_present": truth_value is not None,
        "primary_chain_found": _audit_bool(audit, f"!(has-primary-chain? {raw_proof} {n})"),
        "pii_gate_found": _audit_bool(audit, f"!(has-pii-gate? {raw_proof} {n})"),
        "isolate_policy_step_found": _audit_bool(audit, f"!(has-isolate-policy-step? {raw_proof})"),
        "no_forbidden_ingress_labels": all(count == 0 for count in forbidden_counts.values()),
    }
    return {
        "certificate_kind": "pettachainer_structural_proof_audit",
        "proof_sha256": sha256_text(raw_proof),
        "target_action": "Action Isolate CustomerDB",
        "truth_value": truth_value,
        "expected_primary_chain": expected_primary,
        "operator_counts": operator_counts,
        "forbidden_label_counts": forbidden_counts,
        "checks": checks,
        "certificate_passes": all(checks.values()),
    }


def showcase_checks(
    query_counts: dict[str, int],
    counterfactuals: dict[str, dict[str, int]],
    isolate_proof_tokens: dict[str, int],
    ingress_ranking: list[IngressExplanation],
    ingress_confidence_margin: float,
    causal_checks: dict[str, bool],
    raw_isolate_proof: str,
    proof_structure: dict[str, object],
) -> dict[str, bool]:
    no_pii = counterfactuals["without_customerdb_pii"]
    no_entry = counterfactuals["without_initial_compromise"]
    no_phish = counterfactuals["without_phishing_seed"]
    no_token = counterfactuals["without_token_seed"]
    no_policy = counterfactuals["without_isolate_policy"]
    return {
        "customerdb_compromise_proven": query_counts.get("compromised_customerdb") == 1,
        "response_actions_derived": (
            query_counts.get("isolate_customerdb") == 1
            and query_counts.get("rotate_customerdb") == 1
        ),
        "demodb_negative_control_holds": (
            query_counts.get("compromised_demodb") == 0
            and query_counts.get("isolate_demodb") == 0
        ),
        "counterfactuals_disable_isolation": (
            no_pii["isolate_customerdb"] == 0
            and no_entry["compromised_customerdb"] == 0
            and no_entry["isolate_customerdb"] == 0
            and no_policy["critical_customerdb"] == 1
            and no_policy["isolate_customerdb"] == 0
        ),
        "redundant_ingress_paths_survive_single_seed_loss": (
            no_phish["compromised_customerdb"] == 1
            and no_phish["isolate_customerdb"] == 1
            and no_phish["phish_laptop"] == 0
            and no_phish["token_seed"] == 1
            and no_phish["trust_secondary_"] >= 2
            and no_phish["noise_"] == 0
            and no_token["compromised_customerdb"] == 1
            and no_token["isolate_customerdb"] == 1
            and no_token["phish_laptop"] == 1
            and no_token["token_seed"] == 0
            and no_token["trust_primary_"] == len(PRIMARY_CHAIN)
            and no_token["noise_"] == 0
        ),
        "ranked_explanations_prefer_primary_path": (
            len(ingress_ranking) == 2
            and ingress_ranking[0].name == "primary_laptop_path"
            and ingress_ranking[0].isolate_customerdb == 1
            and ingress_ranking[0].proof_tokens.get("trust_primary_") == len(PRIMARY_CHAIN)
            and ingress_ranking[0].proof_tokens.get("trust_secondary_") == 0
            and ingress_ranking[1].name == "fallback_tokenvault_path"
            and ingress_ranking[1].isolate_customerdb == 1
            and ingress_ranking[1].proof_tokens.get("trust_secondary_") >= 2
            and ingress_ranking[1].proof_tokens.get("noise_") == 0
            and ingress_confidence_margin > 0.0
        ),
        "six_hop_primary_proof": (
            isolate_proof_tokens.get("lateral_move") == len(PRIMARY_CHAIN)
            and isolate_proof_tokens.get("trust_primary_") == len(PRIMARY_CHAIN)
        ),
        "proof_ignores_distractors": (
            isolate_proof_tokens.get("noise_") == 0
            and isolate_proof_tokens.get("trust_secondary_") == 0
        ),
        "causal_ablation_certificate_passes": all(causal_checks.values()),
        "proof_term_materialized": bool(raw_isolate_proof),
        "proof_structure_certificate_passes": bool(
            proof_structure.get("certificate_passes")
        ),
    }


def run_demo(forward_steps: int, query_steps: int, trace_path: Path) -> DemoResult:
    start = time.perf_counter()
    phase_start = start
    phase_timings_s: dict[str, float] = {}

    handler, facts, rules = build_handler(include_customer_pii=True)
    phase_timings_s["setup"] = time.perf_counter() - phase_start

    phase_start = time.perf_counter()
    forward_result = handler.forward_chain(steps=forward_steps)
    phase_timings_s["forward_chain"] = time.perf_counter() - phase_start

    phase_start = time.perf_counter()
    queries = run_queries(handler, steps=query_steps)
    phase_timings_s["queries"] = time.perf_counter() - phase_start

    phase_start = time.perf_counter()
    counterfactuals = counterfactual_counts(forward_steps, query_steps)
    phase_timings_s["counterfactuals"] = time.perf_counter() - phase_start

    phase_start = time.perf_counter()
    ingress_ranking = ingress_explanation_ranking(forward_steps, query_steps)
    phase_timings_s["ingress_ranking"] = time.perf_counter() - phase_start
    ingress_confidence_margin = ranking_margin(ingress_ranking)

    phase_start = time.perf_counter()
    causal_ablation, causal_checks = causal_ablation_certificate(
        forward_steps, query_steps
    )
    phase_timings_s["causal_ablation"] = time.perf_counter() - phase_start

    runtime_s = time.perf_counter() - start
    phase_timings_s["total"] = runtime_s
    raw_isolate_proof = first(queries["isolate_customerdb"])

    query_counts = {name: len(value) for name, value in queries.items()}
    isolate_proof_tokens = audit_proof_tokens(raw_isolate_proof)
    proof_structure = proof_structure_certificate(raw_isolate_proof)

    return DemoResult(
        runtime_s=runtime_s,
        forward_steps=forward_steps,
        query_steps=query_steps,
        facts=facts,
        rules=rules,
        noise_edges=len(NOISE_EDGES),
        phase_timings_s=phase_timings_s,
        forward_result=forward_result if isinstance(forward_result, list) else [str(forward_result)],
        query_counts=query_counts,
        truth_values={name: parse_stv(first(value)) for name, value in queries.items()},
        isolate_proof_tokens=isolate_proof_tokens,
        ingress_ranking=ingress_ranking,
        ingress_confidence_margin=ingress_confidence_margin,
        causal_ablation=causal_ablation,
        causal_checks=causal_checks,
        counterfactuals=counterfactuals,
        checks=showcase_checks(
            query_counts,
            counterfactuals,
            isolate_proof_tokens,
            ingress_ranking,
            ingress_confidence_margin,
            causal_checks,
            raw_isolate_proof,
            proof_structure,
        ),
        proof_ladder=proof_ladder(),
        proof_structure=proof_structure,
        raw_isolate_proof=raw_isolate_proof,
        proof_sha256=sha256_text(raw_isolate_proof),
        scenario_sha256=sha256_text(scenario_text()),
        no_pii_isolate_count=counterfactuals["without_customerdb_pii"]["isolate_customerdb"],
        trace_path=str(trace_path),
    )


def mermaid_graph() -> str:
    lines = ["flowchart LR"]
    for src, dst in PRIMARY_CHAIN:
        lines.append(f"    {src}[{src}] -->|Trusts| {dst}[{dst}]")
    for src, dst in SECONDARY_CHAIN:
        lines.append(f"    {src}[{src}] -->|Fallback Trusts| {dst}[{dst}]")
    lines.extend(
        [
            "    CustomerDB -->|Compromised + StoresPII| Critical[CriticalIncident CustomerDB]",
            "    Critical -->|isolate_policy| Isolate[Action Isolate CustomerDB]",
            "    Critical -->|rotate_policy| Rotate[Action RotateSecrets CustomerDB]",
            f"    Noise[{len(NOISE_EDGES)} distractor trust edges] -. not used .-> CustomerDB",
        ]
    )
    return "\n".join(lines)


def graphviz_dot(result: DemoResult) -> str:
    lines = [
        "digraph PeTTaChainerIncidentProof {",
        '  rankdir="LR";',
        '  node [shape=box, style="rounded"];',
        '  "Laptop" [label="Laptop\\nCompromised seed"];',
        '  "TokenVault" [label="TokenVault\\nFallback compromised seed"];',
    ]
    for src, dst in PRIMARY_CHAIN:
        lines.append(f'  "{src}" -> "{dst}" [label="Trusts + lateral_move"];')
    for src, dst in SECONDARY_CHAIN:
        lines.append(f'  "{src}" -> "{dst}" [label="Fallback Trusts + lateral_move", style=bold];')
    lines.extend(
        [
            '  "CustomerDB" -> "CriticalIncident CustomerDB" [label="StoresPII + pii_incident"];',
            '  "CriticalIncident CustomerDB" -> "Action Isolate CustomerDB" [label="isolate_policy"];',
            '  "CriticalIncident CustomerDB" -> "Action RotateSecrets CustomerDB" [label="rotate_policy"];',
            (
                f'  "Distractors" [label="{result.noise_edges} distractor trust edges\\n'
                'not used in isolate proof", shape=note];'
            ),
            '  "Distractors" -> "CustomerDB" [style=dashed, label="rejected by proof audit"];',
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def explanation_ledger(result: DemoResult) -> dict[str, object]:
    return {
        "bundle_kind": "pettachainer_incident_response_explanation_ledger",
        "forward_steps": result.forward_steps,
        "query_steps": result.query_steps,
        "phase_timings_s": result.phase_timings_s,
        "derived_decisions": {
            name: {
                "proofs": result.query_counts[name],
                "truth_value": result.truth_values.get(name),
            }
            for name in REPLAY_QUERIES
        },
        "ranked_ingress_explanations": [
            asdict(explanation) for explanation in result.ingress_ranking
        ],
        "causal_ablation": [asdict(case) for case in result.causal_ablation],
        "causal_checks": result.causal_checks,
        "counterfactuals": result.counterfactuals,
        "isolate_proof_audit": {
            "proof_sha256": result.proof_sha256,
            "tokens": result.isolate_proof_tokens,
            "ladder": result.proof_ladder,
            "structure": result.proof_structure,
        },
        "replay_requirements": {
            "scenario_sha256": result.scenario_sha256,
            "query_counts": result.query_counts,
            "isolate_proof_sha256": result.proof_sha256,
            "isolate_proof_tokens": result.isolate_proof_tokens,
        },
        "showcase_checks": result.checks,
    }


def write_audit_bundle(result: DemoResult, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads = {
        "explanation-ledger.json": json.dumps(
            explanation_ledger(result), indent=2, sort_keys=True
        )
        + "\n",
        "scenario.metta": scenario_text(),
        "raw-isolate-proof.metta": result.raw_isolate_proof + "\n",
        "proof-structure.json": json.dumps(
            result.proof_structure, indent=2, sort_keys=True
        )
        + "\n",
        "result.json": json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        "report.md": markdown_report(result),
        "proof.dot": graphviz_dot(result),
    }

    file_hashes: dict[str, str] = {}
    for filename, text in payloads.items():
        (output_dir / filename).write_text(text, encoding="utf-8")
        file_hashes[filename] = sha256_text(text)

    manifest = {
        "bundle_version": 1,
        "checks_pass": all(result.checks.values()),
        "proof_sha256": result.proof_sha256,
        "scenario_sha256": result.scenario_sha256,
        "files": file_hashes,
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (output_dir / "MANIFEST.json").write_text(manifest_text, encoding="utf-8")
    file_hashes["MANIFEST.json"] = sha256_text(manifest_text)
    return {filename: str(output_dir / filename) for filename in sorted(file_hashes)}


def verify_audit_bundle(bundle_dir: Path) -> dict[str, bool]:
    manifest_path = bundle_dir / "MANIFEST.json"
    if not manifest_path.exists():
        return {"manifest_present": False}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files", {})
    file_hashes_match = all(
        (bundle_dir / filename).exists()
        and sha256_text((bundle_dir / filename).read_text(encoding="utf-8")) == expected
        for filename, expected in files.items()
    )
    scenario_path = bundle_dir / "scenario.metta"
    proof_path = bundle_dir / "raw-isolate-proof.metta"
    proof_structure_path = bundle_dir / "proof-structure.json"
    ledger_path = bundle_dir / "explanation-ledger.json"
    raw_proof = proof_path.read_text(encoding="utf-8").rstrip("\n") if proof_path.exists() else ""
    proof_structure = (
        json.loads(proof_structure_path.read_text(encoding="utf-8"))
        if proof_structure_path.exists()
        else {}
    )
    scenario_hash_matches = (
        scenario_path.exists()
        and sha256_text(scenario_path.read_text(encoding="utf-8"))
        == manifest.get("files", {}).get("scenario.metta")
        and manifest.get("scenario_sha256")
        == sha256_text(scenario_path.read_text(encoding="utf-8"))
    )
    proof_hash_matches = (
        proof_path.exists()
        and sha256_text(raw_proof) == manifest.get("proof_sha256")
    )
    proof_structure_matches = (
        proof_structure_path.exists()
        and proof_structure == proof_structure_certificate(raw_proof)
    )
    return {
        "manifest_present": True,
        "file_hashes_match": file_hashes_match,
        "ledger_present": ledger_path.exists(),
        "proof_structure_present": proof_structure_path.exists(),
        "scenario_hash_matches": scenario_hash_matches,
        "proof_hash_matches": proof_hash_matches,
        "proof_structure_matches": proof_structure_matches,
        "proof_structure_certificate_passes": bool(
            proof_structure.get("certificate_passes")
        ),
        "checks_pass": bool(manifest.get("checks_pass")),
    }


def replay_audit_bundle(bundle_dir: Path, trace_path: Path | None = None) -> dict[str, bool]:
    def replay() -> dict[str, bool]:
        base_checks = verify_audit_bundle(bundle_dir)
        checks = {
            "base_bundle_verified": bool(base_checks) and all(base_checks.values()),
            "result_present": (bundle_dir / "result.json").exists(),
            "scenario_present": (bundle_dir / "scenario.metta").exists(),
        }
        if not all(checks.values()):
            return checks

        manifest = json.loads((bundle_dir / "MANIFEST.json").read_text(encoding="utf-8"))
        expected = json.loads((bundle_dir / "result.json").read_text(encoding="utf-8"))
        scenario = (bundle_dir / "scenario.metta").read_text(encoding="utf-8")
        atoms = scenario_atoms_from_text(scenario)

        handler = build_handler_from_atoms(atoms)
        forward_result = handler.forward_chain(steps=int(expected["forward_steps"]))
        queries = run_queries(handler, steps=int(expected["query_steps"]))
        raw_isolate_proof = first(queries["isolate_customerdb"])
        query_counts = {name: len(value) for name, value in queries.items()}
        proof_tokens = audit_proof_tokens(raw_isolate_proof)
        proof_sha256 = sha256_text(raw_isolate_proof)
        proof_structure = proof_structure_certificate(raw_isolate_proof)

        checks.update(
            {
                "scenario_hash_matches_result": (
                    sha256_text(scenario) == expected["scenario_sha256"]
                ),
                "scenario_atom_count_matches": (
                    len(atoms) == int(expected["facts"]) + int(expected["rules"])
                ),
                "forward_replay_completed": bool(forward_result),
                "query_counts_match": query_counts == expected["query_counts"],
                "proof_hash_matches_result": proof_sha256 == expected["proof_sha256"],
                "proof_hash_matches_manifest": proof_sha256 == manifest["proof_sha256"],
                "proof_tokens_match": proof_tokens == expected["isolate_proof_tokens"],
                "proof_structure_matches_result": (
                    proof_structure == expected["proof_structure"]
                ),
                "proof_structure_certificate_passes": bool(
                    proof_structure.get("certificate_passes")
                ),
                "noise_still_rejected": proof_tokens["noise_"] == 0,
            }
        )
        return checks

    if trace_path is None:
        return replay()
    with redirect_process_output(trace_path):
        return replay()


def markdown_report(result: DemoResult) -> str:
    verdict = "PASS" if all(result.checks.values()) else "FAIL"
    lines = [
        "# PeTTaChainer Incident-Response Proof Report",
        "",
        f"Showcase verdict: **{verdict}**",
        "",
        "## Reproduction",
        "",
        "```bash",
        ".venv/bin/python pettachainer/benchmarks/impressive_incident_response.py --strict",
        "```",
        "",
        "## Evidence Graph",
        "",
        "```mermaid",
        mermaid_graph(),
        "```",
        "",
        "## Derived Decisions",
        "",
        "| Query | Proofs | Truth |",
        "| --- | ---: | --- |",
    ]
    for key in (
        "compromised_customerdb",
        "critical_customerdb",
        "isolate_customerdb",
        "rotate_customerdb",
        "compromised_demodb",
        "isolate_demodb",
        "compromised_iam",
    ):
        truth = result.truth_values.get(key)
        truth_text = "n/a" if truth is None else f"STV {truth[0]:.6f} {truth[1]:.6f}"
        lines.append(f"| `{key}` | {result.query_counts[key]} | {truth_text} |")

    lines.extend(
        [
            "",
            "## Ranked Ingress Explanations",
            "",
            "| Rank | Explanation | Proofs | Truth | Path tokens | Proof hash |",
            "| ---: | --- | ---: | --- | --- | --- |",
        ]
    )
    for rank, explanation in enumerate(result.ingress_ranking, start=1):
        truth = explanation.truth_value
        truth_text = "n/a" if truth is None else f"STV {truth[0]:.6f} {truth[1]:.6f}"
        tokens = explanation.proof_tokens
        token_text = (
            f"primary={tokens['trust_primary_']}, "
            f"secondary={tokens['trust_secondary_']}, "
            f"noise={tokens['noise_']}"
        )
        lines.append(
            f"| {rank} | `{explanation.name}` | {explanation.isolate_customerdb} | "
            f"{truth_text} | {token_text} | `{explanation.proof_sha256[:12]}` |"
        )
    lines.append(f"Confidence margin: `{result.ingress_confidence_margin:.6f}`")

    lines.extend(
        [
            "",
            "## Causal Minimality Certificate",
            "",
            "| Case | Mode | Removed labels | Expected isolate proofs | Observed | Result |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for case in result.causal_ablation:
        status = "PASS" if case.passed else "FAIL"
        labels = ", ".join(f"`{label}`" for label in case.removed_labels)
        lines.append(
            f"| `{case.name}` | `{case.mode}` | {labels} | "
            f"{case.expected_isolate_customerdb} | {case.isolate_customerdb} | {status} |"
        )
    lines.extend(["", "| Certificate check | Result |", "| --- | --- |"])
    for name, passed in result.causal_checks.items():
        status = "PASS" if passed else "FAIL"
        lines.append(f"| `{name}` | {status} |")

    no_pii = result.counterfactuals["without_customerdb_pii"]
    no_entry = result.counterfactuals["without_initial_compromise"]
    no_phish = result.counterfactuals["without_phishing_seed"]
    no_token = result.counterfactuals["without_token_seed"]
    no_policy = result.counterfactuals["without_isolate_policy"]
    lines.extend(
        [
            "",
            "## Counterfactual Controls",
            "",
            "| Control | Removed input | Expected blocked result | Observed proofs |",
            "| --- | --- | --- | ---: |",
            (
                "| `without_customerdb_pii` | CustomerDB PII | "
                f"`isolate_customerdb` | {no_pii['isolate_customerdb']} |"
            ),
            (
                "| `without_initial_compromise` | Initial compromises | "
                "`compromised_customerdb`, `isolate_customerdb` | "
                f"{no_entry['compromised_customerdb']}, {no_entry['isolate_customerdb']} |"
            ),
            (
                "| `without_phishing_seed` | Laptop seed | "
                "`isolate_customerdb` should still be provable through TokenVault/IAM | "
                f"{no_phish['isolate_customerdb']} "
                f"(token={no_phish['token_seed']}, secondary_edges={no_phish['trust_secondary_']}) |"
            ),
            (
                "| `without_token_seed` | TokenVault seed | "
                "`isolate_customerdb` should still be provable through Laptop primary chain | "
                f"{no_token['isolate_customerdb']} "
                f"(phish={no_token['phish_laptop']}, primary_edges={no_token['trust_primary_']}) |"
            ),
            (
                "| `without_isolate_policy` | Isolation policy | "
                "`isolate_customerdb` while `critical_customerdb` remains provable | "
                f"{no_policy['isolate_customerdb']} |"
            ),
            "",
            "## Proof Audit",
            "",
            "| Token | Count in isolate proof |",
            "| --- | ---: |",
        ]
    )
    for token, count in result.isolate_proof_tokens.items():
        lines.append(f"| `{token}` | {count} |")

    lines.extend(["", "## Showcase Checks", "", "| Check | Result |", "| --- | --- |"])
    for name, passed in result.checks.items():
        status = "PASS" if passed else "FAIL"
        lines.append(f"| `{name}` | {status} |")

    lines.extend(["", "## Phase Timings", "", "| Phase | Seconds |", "| --- | ---: |"])
    for name, seconds in result.phase_timings_s.items():
        lines.append(f"| `{name}` | {seconds:.6f} |")

    lines.extend(
        [
            "",
            f"Runtime: `{result.runtime_s:.3f}s`",
            f"Scenario SHA-256: `{result.scenario_sha256}`",
            f"Isolate proof SHA-256: `{result.proof_sha256}`",
            f"Verbose PeTTa trace: `{result.trace_path}`",
            "",
        ]
    )
    return "\n".join(lines)


def print_text(result: DemoResult, show_proof: bool) -> None:
    print("PeTTaChainer impressive incident-response demo")
    print(f"Runtime: {result.runtime_s:.3f}s")
    print(f"Loaded: {result.facts} facts, {result.rules} rules, {result.noise_edges} distractor trust edges")
    print(f"Forward-chain result: {result.forward_result}")
    print(
        "Phase timings: "
        + ", ".join(
            f"{name}={seconds:.3f}s" for name, seconds in result.phase_timings_s.items()
        )
    )
    print()
    print("Decisions")
    for key in (
        "compromised_customerdb",
        "critical_customerdb",
        "isolate_customerdb",
        "rotate_customerdb",
        "compromised_demodb",
        "isolate_demodb",
        "compromised_iam",
    ):
        truth = result.truth_values.get(key)
        suffix = ""
        if truth is not None:
            suffix = f" strength={truth[0]:.6f} confidence={truth[1]:.6f}"
        print(f"- {key}: {result.query_counts[key]} proof(s){suffix}")
    print()
    print("Showcase checks")
    for name, passed in result.checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"- {status} {name}")
    print()
    print("Ranked ingress explanations")
    for idx, explanation in enumerate(result.ingress_ranking, start=1):
        truth = explanation.truth_value
        truth_text = "n/a" if truth is None else f"strength={truth[0]:.6f} confidence={truth[1]:.6f}"
        tokens = explanation.proof_tokens
        print(
            f"- {idx}. {explanation.name}: {explanation.isolate_customerdb} proof(s), "
            f"{truth_text}, primary_edges={tokens['trust_primary_']}, "
            f"secondary_edges={tokens['trust_secondary_']}, noise_edges={tokens['noise_']}"
        )
    print(f"  confidence_margin: {result.ingress_confidence_margin:.6f}")
    print()
    print("Causal minimality certificate")
    for name, passed in result.causal_checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"- {status} {name}")
    primary_failures = [
        case.name for case in result.causal_ablation
        if case.mode == "primary_path_minimality" and not case.passed
    ]
    print(
        "- primary_path_ablation_cases: "
        f"{sum(case.mode == 'primary_path_minimality' for case in result.causal_ablation)}"
    )
    print(f"- primary_path_ablation_failures: {primary_failures}")
    distractor_case = next(
        case for case in result.causal_ablation if case.mode == "distractor_invariance"
    )
    print(
        "- all distractor edges removed -> "
        f"isolate_customerdb: {distractor_case.isolate_customerdb} proof(s), "
        f"noise_edges: {distractor_case.proof_tokens['noise_']}"
    )
    print()
    print("Counterfactual checks")
    no_pii = result.counterfactuals["without_customerdb_pii"]
    no_entry = result.counterfactuals["without_initial_compromise"]
    no_phish = result.counterfactuals["without_phishing_seed"]
    no_token = result.counterfactuals["without_token_seed"]
    no_policy = result.counterfactuals["without_isolate_policy"]
    print(f"- without CustomerDB PII -> isolate_customerdb: {no_pii['isolate_customerdb']} proof(s)")
    print(
        "- without initial compromise -> "
        f"compromised_customerdb: {no_entry['compromised_customerdb']} proof(s), "
        f"isolate_customerdb: {no_entry['isolate_customerdb']} proof(s)"
    )
    print(
        "- without phishing seed -> "
        f"isolate_customerdb: {no_phish['isolate_customerdb']} proof(s), "
        f"token_seed: {no_phish['token_seed']}, "
        f"secondary_edges: {no_phish['trust_secondary_']}, "
        f"noise_edges: {no_phish['noise_']}"
    )
    print(
        "- without token seed -> "
        f"isolate_customerdb: {no_token['isolate_customerdb']} proof(s), "
        f"phish_laptop: {no_token['phish_laptop']}, "
        f"primary_edges: {no_token['trust_primary_']}, "
        f"noise_edges: {no_token['noise_']}"
    )
    print(
        "- without isolate policy -> "
        f"critical_customerdb: {no_policy['critical_customerdb']} proof(s), "
        f"isolate_customerdb: {no_policy['isolate_customerdb']} proof(s)"
    )
    print()
    print("Why the isolate decision is warranted")
    for idx, step in enumerate(result.proof_ladder, start=1):
        print(f"{idx:02d}. {step}")
    print()
    print("Proof-token counts for Action Isolate CustomerDB")
    for token, count in result.isolate_proof_tokens.items():
        print(f"- {token}: {count}")
    print()
    print(f"Scenario SHA-256: {result.scenario_sha256}")
    print(f"Isolate proof SHA-256: {result.proof_sha256}")
    if show_proof:
        print()
        print("Raw isolate proof")
        print(result.raw_isolate_proof)
    print()
    print(f"Verbose PeTTa trace: {result.trace_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forward-steps", type=int, default=350)
    parser.add_argument("--query-steps", type=int, default=120)
    parser.add_argument("--trace", type=Path, default=Path("/tmp/pettachainer-impressive-demo.log"))
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--markdown-out", type=Path, help="Write a Markdown proof report")
    parser.add_argument("--bundle-out", type=Path, help="Write a replayable audit bundle directory")
    parser.add_argument("--verify-bundle", type=Path, help="Verify a previously written audit bundle")
    parser.add_argument("--replay-bundle", type=Path, help="Rerun and verify a written audit bundle")
    parser.add_argument("--show-proof", action="store_true", help="Print the raw nested proof term")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero if any showcase check fails")
    parser.add_argument("--no-silence", action="store_true", help="Do not redirect verbose PeTTa output")
    args = parser.parse_args()

    if args.verify_bundle:
        checks = verify_audit_bundle(args.verify_bundle)
        print(json.dumps(checks, indent=2, sort_keys=True))
        return 0 if checks and all(checks.values()) else 1

    if args.replay_bundle:
        replay_trace = args.trace.with_name(f"{args.trace.stem}-replay{args.trace.suffix}")
        checks = replay_audit_bundle(args.replay_bundle, replay_trace)
        print(json.dumps(checks, indent=2, sort_keys=True))
        return 0 if checks and all(checks.values()) else 1

    if args.no_silence:
        result = run_demo(args.forward_steps, args.query_steps, args.trace)
    else:
        with redirect_process_output(args.trace):
            result = run_demo(args.forward_steps, args.query_steps, args.trace)

    if args.json:
        print(json.dumps(asdict(result), indent=2, sort_keys=True))
    else:
        print_text(result, show_proof=args.show_proof)
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown_report(result), encoding="utf-8")
    if args.bundle_out:
        files = write_audit_bundle(result, args.bundle_out)
        print(f"Audit bundle: {args.bundle_out}")
        for name, path in files.items():
            print(f"- {name}: {path}")
    return 0 if not args.strict or all(result.checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
