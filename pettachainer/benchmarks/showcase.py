#!/usr/bin/env python3
"""Run the full PeTTaChainer showcase in one audited command."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pettachainer.benchmarks.impressive_incident_response import (
    DemoResult,
    REPLAY_QUERIES,
    audit_proof_tokens,
    build_handler_from_atoms,
    markdown_report as incident_markdown_report,
    redirect_process_output,
    replay_audit_bundle,
    run_demo,
    scenario_atoms,
    verify_audit_bundle,
    write_audit_bundle,
)
from pettachainer.benchmarks.context_showcase import (
    ContextShowcaseResult,
    run_context_showcase,
)
from pettachainer.benchmarks.complementary_evidence import (
    ComplementaryEvidenceResult,
    run_complementary_evidence_showcase,
)
from pettachainer.benchmarks.smart_dispatch import (
    DispatchBenchmarkResult,
    run_benchmark as run_dispatch_benchmark,
)
from pettachainer.benchmarks.context_eval import ContextEval, evaluate_context
from pettachainer.pettachainer import PeTTaChainer


@dataclass
class ShowcaseResult:
    runtime_s: float
    output_dir: str
    dispatch: DispatchBenchmarkResult
    context: ContextShowcaseResult
    complementary: ComplementaryEvidenceResult
    incident: DemoResult
    bundle_verification: dict[str, bool]
    replay_verification: dict[str, bool]
    tamper_drill: dict[str, dict[str, object]]
    noise_stability: list[dict[str, object]]
    context_noise_stability: list[dict[str, object]]
    context_counterfactuals: list[dict[str, object]]
    checks: dict[str, bool]
    report_path: str
    result_path: str
    contract_path: str
    witness_path: str


def dispatch_timings_by_name(result: DispatchBenchmarkResult):
    return {timing.name: timing for timing in result.timings}


def build_showcase_checks(
    dispatch: DispatchBenchmarkResult,
    context: ContextShowcaseResult,
    complementary: ComplementaryEvidenceResult,
    incident: DemoResult,
    bundle_verification: dict[str, bool],
    replay_verification: dict[str, bool],
    tamper_drill: dict[str, dict[str, object]],
    noise_stability: list[dict[str, object]],
    context_noise_stability: list[dict[str, object]],
    context_counterfactuals: list[dict[str, object]],
) -> dict[str, bool]:
    timings = dispatch_timings_by_name(dispatch)
    return {
        "smart_dispatch_checks_pass": all(dispatch.checks.values()),
        "dispatch_speedup_observed": (
            timings["reduce"].ratio_to_smart > 1.0
            and timings["eval"].ratio_to_smart > timings["reduce"].ratio_to_smart
        ),
        "generated_context_showcase_checks_pass": all(context.checks.values()),
        "generated_context_artifacts_written": all(
            Path(path).exists()
            for path in (
                context.result_path,
                context.report_path,
                context.manifest_path,
                *(demo.log_path for demo in context.demos),
            )
        ),
        "complementary_evidence_checks_pass": all(complementary.checks.values()),
        "complementary_evidence_artifacts_written": all(
            Path(path).exists()
            for path in (
                complementary.result_path,
                complementary.report_path,
                complementary.manifest_path,
                complementary.log_path,
            )
        ),
        "incident_checks_pass": all(incident.checks.values()),
        "causal_certificate_passes": all(incident.causal_checks.values()),
        "causal_ablation_certificate_passes": bool(
            incident.checks.get("causal_ablation_certificate_passes", False)
        ),
        "proof_structure_certificate_passes": bool(
            incident.checks.get("proof_structure_certificate_passes", False)
        ),
        "bundle_hash_verification_passes": all(bundle_verification.values()),
        "bundle_replay_verification_passes": all(replay_verification.values()),
        "semantic_forgery_rejected_by_replay": all(
            bool(case["hash_verification_passed"])
            and bool(case["replay_rejected"])
            and bool(case["semantic_mismatch_detected"])
            for case in tamper_drill.values()
        ),
        "noise_stability_sweep_passes": (
            bool(noise_stability)
            and max(int(case["extra_edges"]) for case in noise_stability) > 0
            and all(bool(case["stable"]) for case in noise_stability)
        ),
        "generated_context_noise_stability_passes": (
            bool(context_noise_stability)
            and max(int(case["extra_packets"]) for case in context_noise_stability) > 0
            and all(bool(case["stable"]) for case in context_noise_stability)
        ),
        "generated_context_counterfactual_sensitivity_passes": (
            bool(context_counterfactuals)
            and all(bool(case["passed"]) for case in context_counterfactuals)
        ),
    }


def sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_text(path.read_text(encoding="utf-8"))


def canonical_json_sha256(payload: dict[str, Any]) -> str:
    return sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def recompute_manifest_for_files(bundle_dir: Path, *, scenario_sha256: str | None = None) -> None:
    manifest_path = bundle_dir / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = {
        filename: sha256_text((bundle_dir / filename).read_text(encoding="utf-8"))
        for filename in manifest["files"]
    }
    if scenario_sha256 is not None:
        manifest["scenario_sha256"] = scenario_sha256
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def semantic_tamper_drill(bundle_dir: Path, output_dir: Path) -> dict[str, dict[str, object]]:
    drill_dir = output_dir / "tamper-drill"
    if drill_dir.exists():
        shutil.rmtree(drill_dir)
    drill_dir.mkdir(parents=True)

    cases: dict[str, dict[str, object]] = {}
    for case_name, forge_result_metadata in (
        ("hash_consistent_scenario_forgery", False),
        ("metadata_consistent_semantic_forgery", True),
    ):
        forged_dir = drill_dir / case_name
        shutil.copytree(bundle_dir, forged_dir)

        scenario_path = forged_dir / "scenario.metta"
        scenario_lines = scenario_path.read_text(encoding="utf-8").splitlines()
        scenario_lines = [
            line for line in scenario_lines if not line.startswith("(: customerdb_pii ")
        ]
        forged_scenario = "\n".join(scenario_lines) + "\n"
        scenario_path.write_text(forged_scenario, encoding="utf-8")
        forged_scenario_sha = sha256_text(forged_scenario)

        if forge_result_metadata:
            result_path = forged_dir / "result.json"
            result = json.loads(result_path.read_text(encoding="utf-8"))
            result["scenario_sha256"] = forged_scenario_sha
            result["facts"] = int(result["facts"]) - 1
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        recompute_manifest_for_files(forged_dir, scenario_sha256=forged_scenario_sha)
        hash_checks = verify_audit_bundle(forged_dir)
        replay_checks = replay_audit_bundle(forged_dir, drill_dir / f"{case_name}-replay.log")
        replay_failures = [
            name for name, passed in replay_checks.items() if not passed
        ]
        cases[case_name] = {
            "path": str(forged_dir),
            "removed_label": "customerdb_pii",
            "hash_verification": hash_checks,
            "replay_verification": replay_checks,
            "hash_verification_passed": all(hash_checks.values()),
            "replay_rejected": not all(replay_checks.values()),
            "semantic_mismatch_detected": any(
                name in replay_failures
                for name in (
                    "scenario_hash_matches_result",
                    "scenario_atom_count_matches",
                    "query_counts_match",
                    "proof_hash_matches_result",
                    "proof_tokens_match",
                )
            ),
            "replay_failures": replay_failures,
        }
    return cases


def injected_noise_atoms(count: int) -> list[str]:
    return [
        (
            f"(: injected_noise_{idx} "
            f"(Trusts NoiseSource{idx} NoiseSink{idx}) "
            "(STV 0.80 0.60))"
        )
        for idx in range(1, count + 1)
    ]


def noise_stability_sweep(
    *,
    expected_proof_sha256: str,
    forward_steps: int,
    query_steps: int,
    levels: tuple[int, ...],
) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for extra_edges in levels:
        started = time.perf_counter()
        atoms = scenario_atoms() + injected_noise_atoms(extra_edges)

        phase_start = time.perf_counter()
        handler = build_handler_from_atoms(atoms)
        setup_s = time.perf_counter() - phase_start

        phase_start = time.perf_counter()
        handler.forward_chain(steps=forward_steps)
        forward_s = time.perf_counter() - phase_start

        phase_start = time.perf_counter()
        proofs = handler.query(
            REPLAY_QUERIES["isolate_customerdb"],
            steps=query_steps,
            timeout_sec=0,
        )
        query_s = time.perf_counter() - phase_start

        proof = proofs[0] if proofs else ""
        proof_sha256 = sha256_text(proof) if proof else ""
        tokens = audit_proof_tokens(proof)
        injected_hits = sum(
            1 for idx in range(1, extra_edges + 1) if f"injected_noise_{idx}" in proof
        )
        stable = (
            len(proofs) == 1
            and proof_sha256 == expected_proof_sha256
            and tokens["noise_"] == 0
            and injected_hits == 0
        )
        cases.append(
            {
                "extra_edges": extra_edges,
                "atoms": len(atoms),
                "proofs": len(proofs),
                "proof_sha256": proof_sha256,
                "proof_hash_matches_incident": proof_sha256 == expected_proof_sha256,
                "built_in_noise_tokens": tokens["noise_"],
                "injected_noise_tokens": injected_hits,
                "stable": stable,
                "runtime_s": time.perf_counter() - started,
                "setup_s": setup_s,
                "forward_s": forward_s,
                "query_s": query_s,
            }
        )
    return cases


@dataclass(frozen=True)
class EvidencePacket:
    statement: str
    positive: float
    negative: float
    features: frozenset[str]
    provenance: str = ""


CONTEXT_QUERY_FEATURES = frozenset({"type:Bird", "type:Penguin", "source:zoo-record"})
CONTEXT_EXPECTED_GUARD = ("type:Penguin",)
CONTEXT_MIN_RANKING_MARGIN = 0.05


def context_base_packets() -> list[EvidencePacket]:
    return [
        EvidencePacket(
            "(Fly x)",
            positive=950,
            negative=50,
            features=frozenset(
                {
                    "type:Bird",
                    "taxon:ordinary-bird",
                    "habitat:temperate",
                    "source:aviary",
                }
            ),
            provenance="temperate-aviary",
        ),
        EvidencePacket(
            "(Fly x)",
            positive=0,
            negative=100,
            features=frozenset({"type:Bird", "type:Penguin", "source:antarctic-study"}),
            provenance="antarctic-study",
        ),
        EvidencePacket(
            "(Fly x)",
            positive=50,
            negative=450,
            features=frozenset({"type:Bird", "habitat:urban", "source:urban-survey"}),
            provenance="urban-survey",
        ),
    ]


def injected_context_noise_packets(count: int) -> list[EvidencePacket]:
    return [
        EvidencePacket(
            "(Irrelevant ContextSignal)",
            positive=2,
            negative=0,
            features=frozenset(
                {
                    f"type:ContextNoise{idx}",
                    f"source:context-noise-{idx}",
                    f"channel:{idx % 7}",
                }
            ),
            provenance=f"context-noise-{idx}",
        )
        for idx in range(1, count + 1)
    ]


def context_noise_stability_sweep(*, levels: tuple[int, ...]) -> list[dict[str, object]]:
    handler = PeTTaChainer()
    cases: list[dict[str, object]] = []
    for extra_packets in levels:
        started = time.perf_counter()
        packets = context_base_packets() + injected_context_noise_packets(extra_packets)
        synth = [(p.statement, p.positive, p.negative, p.features, p.provenance) for p in packets]
        ev: ContextEval = evaluate_context(handler, synth, CONTEXT_QUERY_FEATURES)

        best_guard = ev.best_guard
        runner_up_guard = ev.runner_up_guard
        ranking_margin = ev.ranking_margin
        routed_required = ev.routed_required
        routed_forbidden = ev.routed_forbidden  # () in the MeTTa model
        noise_guard_hits = sum(1 for f in best_guard if "Noise" in f)
        noise_route_hits = sum(1 for f in (*routed_required, *routed_forbidden) if "Noise" in f)
        stable = (
            best_guard == CONTEXT_EXPECTED_GUARD
            and CONTEXT_EXPECTED_GUARD[0] in routed_required
            and ev.strength < 0.05
            and ranking_margin >= CONTEXT_MIN_RANKING_MARGIN
            and noise_guard_hits == 0
            and noise_route_hits == 0
        )
        cases.append(
            {
                "extra_packets": extra_packets,
                "packets": len(packets),
                "best_guard": list(best_guard),
                "best_score": ev.best_score,
                "runner_up_guard": list(runner_up_guard),
                "runner_up_score": ev.runner_up_score,
                "ranking_margin": ranking_margin,
                "top_candidates": [
                    {"guard": list(best_guard), "score": ev.best_score},
                    {"guard": list(runner_up_guard), "score": ev.runner_up_score},
                ],
                "routed_required": list(routed_required),
                "routed_forbidden": list(routed_forbidden),
                "routed_strength": ev.strength,
                "noise_guard_hits": noise_guard_hits,
                "noise_route_hits": noise_route_hits,
                "stable": stable,
                "runtime_s": time.perf_counter() - started,
            }
        )
    return cases


def context_counterfactual_packets(case_name: str) -> list[EvidencePacket]:
    packets = context_base_packets()
    if case_name == "remove_penguin_exception":
        return [packet for packet in packets if "type:Penguin" not in packet.features]
    if case_name == "invert_penguin_exception":
        return [
            EvidencePacket(
                packet.statement,
                positive=100,
                negative=0,
                features=packet.features,
                provenance=packet.provenance,
            )
            if "type:Penguin" in packet.features
            else packet
            for packet in packets
        ]
    if case_name == "ambiguous_penguin_exception":
        return [
            EvidencePacket(
                packet.statement,
                positive=10,
                negative=10,
                features=packet.features,
                provenance=packet.provenance,
            )
            if "type:Penguin" in packet.features
            else packet
            for packet in packets
        ]
    raise ValueError(f"unknown counterfactual case: {case_name}")


def context_counterfactual_sensitivity_cases() -> list[dict[str, object]]:
    specs = (
        (
            "remove_penguin_exception",
            "selected_guard_removed",
            "Removing the only penguin exception evidence must remove the generated penguin context.",
        ),
        (
            "invert_penguin_exception",
            "routed_strength_flips_positive",
            "Changing penguin evidence from negative to positive must preserve the local guard but flip the routed strength.",
        ),
        (
            "ambiguous_penguin_exception",
            "ranking_margin_collapses",
            "Making penguin evidence ambiguous must collapse the certification margin below the stability threshold.",
        ),
    )
    cases: list[dict[str, object]] = []
    handler = PeTTaChainer()
    for case_name, expectation, description in specs:
        packets = context_counterfactual_packets(case_name)
        synth = [(p.statement, p.positive, p.negative, p.features, p.provenance) for p in packets]
        ev: ContextEval = evaluate_context(handler, synth, CONTEXT_QUERY_FEATURES)

        best_guard = list(ev.best_guard)
        routed_required = list(ev.routed_required)
        ranking_margin = ev.ranking_margin
        if expectation == "selected_guard_removed":
            # MeTTa routes the query inside (type Bird) once penguin is gone -> strength ~0.667.
            passed = (
                best_guard != list(CONTEXT_EXPECTED_GUARD)
                and CONTEXT_EXPECTED_GUARD[0] not in routed_required
                and 0.55 < ev.strength < 0.80
            )
        elif expectation == "routed_strength_flips_positive":
            # Penguin still wins but ties Bird at 0.78, so the margin is 0.0; strength flip is the signal.
            passed = (
                best_guard == list(CONTEXT_EXPECTED_GUARD)
                and CONTEXT_EXPECTED_GUARD[0] in routed_required
                and ev.strength > 0.95
            )
        elif expectation == "ranking_margin_collapses":
            passed = (
                best_guard == list(CONTEXT_EXPECTED_GUARD)
                and 0.45 <= ev.strength <= 0.55
                and ranking_margin < CONTEXT_MIN_RANKING_MARGIN
            )
        else:
            passed = False
        cases.append(
            {
                "name": case_name,
                "expectation": expectation,
                "description": description,
                "packets": len(packets),
                "best_guard": best_guard,
                "best_score": ev.best_score,
                "runner_up_guard": list(ev.runner_up_guard),
                "runner_up_score": ev.runner_up_score,
                "ranking_margin": ranking_margin,
                "routed_required": routed_required,
                "routed_forbidden": list(ev.routed_forbidden),
                "routed_strength": ev.strength,
                "top_candidates": [
                    {"guard": best_guard, "score": ev.best_score},
                    {"guard": list(ev.runner_up_guard), "score": ev.runner_up_score},
                ],
                "passed": passed,
            }
        )
    return cases


def build_showcase_witness(
    result: ShowcaseResult,
    contract: dict[str, object],
) -> dict[str, object]:
    output_dir = Path(result.output_dir)
    artifact_files = [
        "showcase-result.json",
        "showcase-report.md",
        "showcase-contract.json",
        "context-showcase/context-showcase-result.json",
        "context-showcase/context-showcase-report.md",
        "context-showcase/context-showcase-manifest.json",
        "context-showcase/adaptive-control.log",
        "context-showcase/beam-needle-control.log",
        "complementary-evidence/complementary-evidence-result.json",
        "complementary-evidence/complementary-evidence-report.md",
        "complementary-evidence/complementary-evidence-manifest.json",
        "complementary-evidence/additive-complement-merge.log",
        "incident-bundle/MANIFEST.json",
        "incident-bundle/explanation-ledger.json",
        "incident-bundle/raw-isolate-proof.metta",
        "incident-bundle/proof-structure.json",
        "incident-bundle/proof.dot",
        "incident-bundle/scenario.metta",
    ]
    dispatch = dispatch_timings_by_name(result.dispatch)
    primary_ablation_count = sum(
        case.mode == "primary_path_minimality"
        for case in result.incident.causal_ablation
    )
    distractor_ablation_count = sum(
        case.mode == "distractor_invariance"
        for case in result.incident.causal_ablation
    )
    max_noise_edges = max(
        (int(case["extra_edges"]) for case in result.noise_stability),
        default=0,
    )
    body: dict[str, object] = {
        "witness_version": 1,
        "artifact_kind": "pettachainer_showcase_witness_certificate",
        "objective": contract.get("objective", ""),
        "artifact_hashes": {
            filename: sha256_file(output_dir / filename) for filename in artifact_files
        },
        "contract_claim_ids": [
            str(claim["id"]) for claim in contract.get("claims", [])
        ],
        "showcase_checks": result.checks,
        "dispatch_evidence": {
            name: {
                "ratio_to_smart": dispatch[name].ratio_to_smart,
                "codegen_marker": dispatch[name].codegen_marker,
            }
            for name in ("smart", "call", "reduce", "eval")
        },
        "proof_evidence": {
            "scenario_sha256": result.incident.scenario_sha256,
            "isolate_proof_sha256": result.incident.proof_sha256,
            "query_counts": result.incident.query_counts,
            "isolate_proof_tokens": result.incident.isolate_proof_tokens,
            "proof_ladder": result.incident.proof_ladder,
            "proof_structure": result.incident.proof_structure,
        },
        "causal_evidence": {
            "primary_ablation_count": primary_ablation_count,
            "distractor_ablation_count": distractor_ablation_count,
            "causal_checks": result.incident.causal_checks,
        },
        "context_evidence": {
            "checks": result.context.checks,
            "demos": {
                demo.name: {
                    "metta_file": demo.metta_file,
                    "summary_lines": demo.summary_lines,
                    "summary_sha256": demo.summary_sha256,
                    "checks": {
                        check.name: {
                            "passed": check.passed,
                            "expected": check.expected,
                            "matched_line": check.matched_line,
                        }
                        for check in demo.checks
                    },
                }
                for demo in result.context.demos
            },
            "noise_stability": [
                {
                    "extra_packets": int(case["extra_packets"]),
                    "best_guard": list(case["best_guard"]),
                    "runner_up_guard": list(case["runner_up_guard"]),
                    "ranking_margin": float(case["ranking_margin"]),
                    "routed_required": list(case["routed_required"]),
                    "routed_strength": float(case["routed_strength"]),
                    "noise_guard_hits": int(case["noise_guard_hits"]),
                    "noise_route_hits": int(case["noise_route_hits"]),
                    "stable": bool(case["stable"]),
                }
                for case in result.context_noise_stability
            ],
            "counterfactuals": [
                {
                    "name": str(case["name"]),
                    "expectation": str(case["expectation"]),
                    "best_guard": list(case["best_guard"]),
                    "runner_up_guard": list(case["runner_up_guard"]),
                    "ranking_margin": float(case["ranking_margin"]),
                    "routed_required": list(case["routed_required"]),
                    "routed_strength": float(case["routed_strength"]),
                    "passed": bool(case["passed"]),
                }
                for case in result.context_counterfactuals
            ],
        },
        "complementary_evidence": {
            "checks": result.complementary.checks,
            "metta_file": result.complementary.metta_file,
            "summary_lines": result.complementary.summary_lines,
            "summary_sha256": result.complementary.summary_sha256,
        },
        "noise_evidence": {
            "max_extra_edges": max_noise_edges,
            "cases": [
                {
                    "extra_edges": int(case["extra_edges"]),
                    "proof_sha256": case["proof_sha256"],
                    "proof_hash_matches_incident": bool(
                        case["proof_hash_matches_incident"]
                    ),
                    "built_in_noise_tokens": int(case["built_in_noise_tokens"]),
                    "injected_noise_tokens": int(case["injected_noise_tokens"]),
                    "stable": bool(case["stable"]),
                }
                for case in result.noise_stability
            ],
        },
        "tamper_evidence": {
            name: {
                "hash_verification_passed": bool(case["hash_verification_passed"]),
                "replay_rejected": bool(case["replay_rejected"]),
                "semantic_mismatch_detected": bool(case["semantic_mismatch_detected"]),
                "replay_failures": list(case["replay_failures"]),
            }
            for name, case in sorted(result.tamper_drill.items())
        },
    }
    return {**body, "witness_root_sha256": canonical_json_sha256(body)}


def build_acceptance_contract(result: ShowcaseResult) -> dict[str, object]:
    max_noise_edges = max(
        (int(case["extra_edges"]) for case in result.noise_stability),
        default=0,
    )
    max_context_noise_packets = max(
        (int(case["extra_packets"]) for case in result.context_noise_stability),
        default=0,
    )
    return {
        "contract_version": 1,
        "artifact_kind": "pettachainer_showcase_acceptance_contract",
        "objective": "make it really impressive",
        "artifacts": {
            "result_json": Path(result.result_path).name,
            "report_markdown": Path(result.report_path).name,
            "generated_context_showcase": "context-showcase",
            "generated_context_manifest": "context-showcase/context-showcase-manifest.json",
            "complementary_evidence_showcase": "complementary-evidence",
            "complementary_evidence_manifest": "complementary-evidence/complementary-evidence-manifest.json",
            "incident_bundle": "incident-bundle",
            "verifier_json": "showcase-verifier-result.json",
            "witness_certificate": Path(result.witness_path).name,
        },
        "claims": [
            {
                "id": "smart_dispatch_direct_codegen_speedup",
                "description": "Known recursive MeTTa calls compile to direct predicates and beat dynamic/runtime dispatch.",
                "enforced_by": [
                    "smart_dispatch_checks_pass",
                    "dispatch_speedup_observed",
                    "dispatch_artifact_claims_pass",
                ],
            },
            {
                "id": "generated_context_inference_control",
                "description": "PeTTa generates evidence-derived contexts at query time, flips branch control after new evidence, and finds a depth-4 exception guard through the Prolog beam scorer.",
                "enforced_by": [
                    "generated_context_showcase_checks_pass",
                    "generated_context_artifacts_written",
                    "context_showcase_artifacts_verify",
                ],
            },
            {
                "id": "generated_context_noise_stability",
                "description": "Irrelevant evidence packets do not change the generated exception guard or the routed local context.",
                "enforced_by": [
                    "generated_context_noise_stability_passes",
                    "recorded_context_noise_stability_passes",
                    "context_noise_replay_passes",
                ],
            },
            {
                "id": "generated_context_counterfactual_sensitivity",
                "description": "Removing, inverting, or weakening decisive exception evidence changes the generated context behavior in the expected direction.",
                "enforced_by": [
                    "generated_context_counterfactual_sensitivity_passes",
                    "recorded_context_counterfactual_sensitivity_passes",
                    "context_counterfactual_replay_passes",
                ],
            },
            {
                "id": "complementary_evidence_additive_merge",
                "description": "Fact and not-fact evidence for the same support are preserved as complementary branches and merged additively.",
                "enforced_by": [
                    "complementary_evidence_checks_pass",
                    "complementary_evidence_artifacts_written",
                    "complementary_evidence_artifacts_verify",
                ],
            },
            {
                "id": "replayable_incident_decision",
                "description": "The incident decision is replayable from the saved bundle in a fresh handler.",
                "enforced_by": [
                    "bundle_hash_verification_passes",
                    "bundle_replay_verification_passes",
                ],
            },
            {
                "id": "causal_minimality",
                "description": "Single-atom ablations block the primary proof while distractor removal preserves it.",
                "enforced_by": [
                    "causal_certificate_passes",
                    "causal_ablation_certificate_passes",
                ],
            },
            {
                "id": "structural_proof_audit",
                "description": "The isolate proof parses as a nested six-hop primary-chain proof with PII and isolation gates.",
                "enforced_by": [
                    "proof_structure_certificate_passes",
                    "bundle_hash_verification_passes",
                    "bundle_replay_verification_passes",
                    "witness_certificate_verified",
                ],
            },
            {
                "id": "semantic_forgery_rejection",
                "description": "Hash-consistent forged bundles are rejected by semantic replay.",
                "enforced_by": [
                    "semantic_forgery_rejected_by_replay",
                    "tamper_artifacts_reject_on_replay",
                ],
            },
            {
                "id": "needle_in_haystack_noise_stability",
                "description": "Injected irrelevant trust edges do not alter the isolate proof hash or enter the proof.",
                "enforced_by": [
                    "noise_stability_sweep_passes",
                    "recorded_noise_stability_passes",
                    "noise_replay_passes",
                ],
            },
            {
                "id": "machine_checkable_witness_certificate",
                "description": "A canonical witness binds the report, result, contract, bundle hashes, and proof evidence.",
                "enforced_by": [
                    "witness_certificate_verified",
                ],
            },
        ],
        "required_showcase_checks": sorted(result.checks),
        "required_verifier_checks": [
            "artifact_files_present",
            "result_checks_claim_pass",
            "dispatch_artifact_claims_pass",
            "report_mentions_audit_sections",
            "bundle_hash_verification_passes",
            "bundle_replay_verification_passes",
            "tamper_artifacts_reject_on_replay",
            "context_showcase_artifacts_verify",
            "complementary_evidence_artifacts_verify",
            "recorded_context_noise_stability_passes",
            "context_noise_replay_passes",
            "recorded_context_counterfactual_sensitivity_passes",
            "context_counterfactual_replay_passes",
            "recorded_noise_stability_passes",
            "noise_replay_passes",
            "witness_certificate_verified",
            "contract_claims_covered",
            "contract_enforced",
            "verifier_completed",
        ],
        "required_report_sections": [
            "PeTTaChainer Full Showcase",
            "Generated Context Control",
            "Complementary Evidence Merge",
            "Generated Context Noise Stability",
            "Generated Context Counterfactuals",
            "Needle-in-Haystack Noise Sweep",
            "Adversarial Tamper Drill",
            "Causal Minimality Certificate",
        ],
        "required_tamper_cases": [
            "hash_consistent_scenario_forgery",
            "metadata_consistent_semantic_forgery",
        ],
        "thresholds": {
            "dispatch_reduce_ratio_gt": 1.0,
            "dispatch_eval_ratio_gt_reduce": True,
            "minimum_noise_extra_edges": max_noise_edges,
            "minimum_context_noise_packets": max_context_noise_packets,
            "noise_proofs": 1,
            "noise_tokens": 0,
        },
    }


def markdown_report(result: ShowcaseResult) -> str:
    dispatch = dispatch_timings_by_name(result.dispatch)
    verdict = "PASS" if all(result.checks.values()) else "FAIL"
    lines = [
        "# PeTTaChainer Full Showcase",
        "",
        f"Showcase verdict: **{verdict}**",
        "",
        "## What This Demonstrates",
        "",
        "- PeTTa Smart Dispatch compiles known MeTTa recursion to direct Prolog predicates.",
        "- PeTTa generated-context demos derive guards at query time and use them for branch control.",
        "- Generated contexts stay stable when irrelevant context evidence is injected.",
        "- Counterfactual context cases prove the generated guard is evidence-sensitive, not hardcoded.",
        "- Complementary positive and negated evidence branches merge additively into one auditable proof.",
        "- PeTTaChainer derives a multi-hop incident response decision with PLN truth values.",
        "- The incident proof is replayable from an audit bundle in a fresh handler.",
        "- Causal ablations certify the selected primary proof path and distractor invariance.",
        "- A noise sweep injects irrelevant trust edges and requires the proof hash to remain stable.",
        "",
        "## Smart Dispatch",
        "",
        "| Variant | Median seconds | Ratio to smart | Codegen |",
        "| --- | ---: | ---: | --- |",
    ]
    for name in ("smart", "call", "reduce", "eval"):
        timing = dispatch[name]
        lines.append(
            f"| `{name}` | {timing.median_s:.6f} | "
            f"{timing.ratio_to_smart:.2f}x | `{timing.codegen_marker}` |"
        )

    lines.extend(
        [
            "",
            "## Generated Context Control",
            "",
            "| Demo | Runtime seconds | Checks |",
            "| --- | ---: | --- |",
        ]
    )
    for demo in result.context.demos:
        passed = sum(1 for check in demo.checks if check.passed)
        lines.append(
            f"| `{demo.name}` | {demo.runtime_s:.3f} | {passed}/{len(demo.checks)} PASS |"
        )
    for demo in result.context.demos:
        lines.extend(["", f"### {demo.name}", "", "```text"])
        lines.extend(demo.summary_lines)
        lines.append("```")

    lines.extend(
        [
            "",
            "## Complementary Evidence Merge",
            "",
            "| Runtime seconds | Checks | Summary SHA-256 |",
            "| ---: | --- | --- |",
            f"| {result.complementary.runtime_s:.3f} | "
            f"{sum(result.complementary.checks.values())}/{len(result.complementary.checks)} PASS | "
            f"`{result.complementary.summary_sha256}` |",
            "",
            "```text",
            *result.complementary.summary_lines,
            "```",
        ]
    )

    lines.extend(
        [
            "",
            "## Generated Context Noise Stability",
            "",
            "| Extra context packets | Total packets | Best guard | Runner-up | Margin | Routed required features | Noise hits | Stable | Runtime seconds |",
            "| ---: | ---: | --- | --- | ---: | --- | ---: | --- | ---: |",
        ]
    )
    for case in result.context_noise_stability:
        noise_hits = int(case["noise_guard_hits"]) + int(case["noise_route_hits"])
        lines.append(
            f"| {case['extra_packets']} | {case['packets']} | "
            f"`{' & '.join(case['best_guard'])}` | "
            f"`{' & '.join(case['runner_up_guard'])}` | "
            f"{float(case['ranking_margin']):.3f} | "
            f"`{' & '.join(case['routed_required'])}` | "
            f"{noise_hits} | {'PASS' if case['stable'] else 'FAIL'} | "
            f"{float(case['runtime_s']):.3f} |"
        )

    lines.extend(
        [
            "",
            "## Generated Context Counterfactuals",
            "",
            "| Case | Expectation | Best guard | Runner-up | Margin | Routed strength | Result |",
            "| --- | --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for case in result.context_counterfactuals:
        lines.append(
            f"| `{case['name']}` | `{case['expectation']}` | "
            f"`{' & '.join(case['best_guard'])}` | "
            f"`{' & '.join(case['runner_up_guard'])}` | "
            f"{float(case['ranking_margin']):.3f} | "
            f"{float(case['routed_strength']):.3f} | "
            f"{'PASS' if case['passed'] else 'FAIL'} |"
        )

    lines.extend(
        [
            "",
            "## Incident Proof Summary",
            "",
            "| Signal | Value |",
            "| --- | --- |",
            f"| Facts | {result.incident.facts} |",
            f"| Rules | {result.incident.rules} |",
            f"| Distractor trust edges | {result.incident.noise_edges} |",
            f"| Isolate proofs | {result.incident.query_counts['isolate_customerdb']} |",
            f"| Primary-path ablation cases | "
            f"{sum(case.mode == 'primary_path_minimality' for case in result.incident.causal_ablation)} |",
            f"| Causal checks | {'PASS' if all(result.incident.causal_checks.values()) else 'FAIL'} |",
            f"| Bundle replay | {'PASS' if all(result.replay_verification.values()) else 'FAIL'} |",
            "",
            "## Needle-in-Haystack Noise Sweep",
            "",
            "| Extra trust edges | Atoms | Proofs | Hash stable | Noise tokens | Runtime seconds |",
            "| ---: | ---: | ---: | --- | ---: | ---: |",
        ]
    )
    for case in result.noise_stability:
        noise_tokens = int(case["built_in_noise_tokens"]) + int(case["injected_noise_tokens"])
        lines.append(
            f"| {case['extra_edges']} | {case['atoms']} | {case['proofs']} | "
            f"{'PASS' if case['proof_hash_matches_incident'] else 'FAIL'} | "
            f"{noise_tokens} | {float(case['runtime_s']):.3f} |"
        )

    lines.extend(
        [
            "",
            "## Adversarial Tamper Drill",
            "",
            "| Forgery | Hash verification | Replay rejected | Detected failures |",
            "| --- | --- | --- | --- |",
        ]
    )
    for name, case in result.tamper_drill.items():
        failures = ", ".join(f"`{failure}`" for failure in case["replay_failures"])
        lines.append(
            f"| `{name}` | {'PASS' if case['hash_verification_passed'] else 'FAIL'} | "
            f"{'PASS' if case['replay_rejected'] else 'FAIL'} | {failures} |"
        )

    lines.extend(
        [
            "",
            "## Combined Checks",
            "",
            "| Check | Result |",
            "| --- | --- |",
        ]
    )
    for name, passed in result.checks.items():
        lines.append(f"| `{name}` | {'PASS' if passed else 'FAIL'} |")

    lines.extend(
        [
            "",
            "## Artifact Paths",
            "",
            f"- Incident bundle: `{Path(result.output_dir) / 'incident-bundle'}`",
            f"- Incident report: `{Path(result.output_dir) / 'incident-report.md'}`",
            f"- Dispatch trace: `{result.dispatch.trace_path}`",
            f"- Incident trace: `{result.incident.trace_path}`",
            f"- Complementary evidence artifact: `{result.complementary.output_dir}`",
            f"- Replay trace: `{Path(result.output_dir) / 'incident-replay.log'}`",
            f"- Noise sweep trace: `{Path(result.output_dir) / 'noise-sweep.log'}`",
            f"- Witness certificate: `{result.witness_path}`",
            "",
            "## Incident Detail",
            "",
            incident_markdown_report(result.incident),
        ]
    )
    return "\n".join(lines)


def run_showcase(
    *,
    output_dir: Path = Path("/tmp/pettachainer-showcase"),
    dispatch_iterations: int = 20_000,
    dispatch_repeats: int = 3,
    forward_steps: int = 350,
    query_steps: int = 120,
    noise_sweep_levels: tuple[int, ...] = (0, 50, 200),
    context_noise_levels: tuple[int, ...] = (0, 50, 200),
    context_timeout_s: int = 30,
) -> ShowcaseResult:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)

    dispatch = run_dispatch_benchmark(
        iterations=dispatch_iterations,
        repeats=dispatch_repeats,
        trace_path=output_dir / "smart-dispatch.log",
    )
    context = run_context_showcase(
        output_dir=output_dir / "context-showcase",
        timeout_s=context_timeout_s,
    )
    complementary = run_complementary_evidence_showcase(
        output_dir=output_dir / "complementary-evidence",
        timeout_s=context_timeout_s,
    )

    incident_trace = output_dir / "incident.log"
    with redirect_process_output(incident_trace):
        incident = run_demo(
            forward_steps=forward_steps,
            query_steps=query_steps,
            trace_path=incident_trace,
        )

    bundle_dir = output_dir / "incident-bundle"
    write_audit_bundle(incident, bundle_dir)
    bundle_verification = verify_audit_bundle(bundle_dir)
    replay_verification = replay_audit_bundle(
        bundle_dir, output_dir / "incident-replay.log"
    )
    with redirect_process_output(output_dir / "noise-sweep.log"):
        noise_stability = noise_stability_sweep(
            expected_proof_sha256=incident.proof_sha256,
            forward_steps=forward_steps,
            query_steps=query_steps,
            levels=noise_sweep_levels,
        )
    context_noise_stability = context_noise_stability_sweep(
        levels=context_noise_levels,
    )
    context_counterfactuals = context_counterfactual_sensitivity_cases()
    tamper_drill = semantic_tamper_drill(bundle_dir, output_dir)

    checks = build_showcase_checks(
        dispatch,
        context,
        complementary,
        incident,
        bundle_verification,
        replay_verification,
        tamper_drill,
        noise_stability,
        context_noise_stability,
        context_counterfactuals,
    )

    placeholder = ShowcaseResult(
        runtime_s=time.perf_counter() - started,
        output_dir=str(output_dir),
        dispatch=dispatch,
        context=context,
        complementary=complementary,
        incident=incident,
        bundle_verification=bundle_verification,
        replay_verification=replay_verification,
        tamper_drill=tamper_drill,
        noise_stability=noise_stability,
        context_noise_stability=context_noise_stability,
        context_counterfactuals=context_counterfactuals,
        checks=checks,
        report_path=str(output_dir / "showcase-report.md"),
        result_path=str(output_dir / "showcase-result.json"),
        contract_path=str(output_dir / "showcase-contract.json"),
        witness_path=str(output_dir / "showcase-witness.json"),
    )
    report_text = markdown_report(placeholder)
    Path(placeholder.report_path).write_text(report_text, encoding="utf-8")
    contract = build_acceptance_contract(placeholder)
    Path(placeholder.contract_path).write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(placeholder.result_path).write_text(
        json.dumps(asdict(placeholder), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    witness = build_showcase_witness(placeholder, contract)
    Path(placeholder.witness_path).write_text(
        json.dumps(witness, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return placeholder


def print_text(result: ShowcaseResult) -> None:
    dispatch = dispatch_timings_by_name(result.dispatch)
    print("PeTTaChainer full showcase")
    print(f"Runtime: {result.runtime_s:.3f}s")
    print(f"Output: {result.output_dir}")
    print()
    print("Smart Dispatch")
    print(
        "- smart vs reduce: "
        f"{dispatch['reduce'].ratio_to_smart:.2f}x dynamic-dispatch overhead"
    )
    print(
        "- smart vs eval: "
        f"{dispatch['eval'].ratio_to_smart:.2f}x runtime-eval overhead"
    )
    print()
    print("Generated Context Control")
    print(
        "- context checks: "
        f"{sum(result.context.checks.values())}/{len(result.context.checks)} PASS"
    )
    print(f"- context artifact: {result.context.output_dir}")
    max_context_noise_packets = max(
        (int(case["extra_packets"]) for case in result.context_noise_stability),
        default=0,
    )
    print(
        "- context noise stability: "
        f"{'PASS' if result.checks['generated_context_noise_stability_passes'] else 'FAIL'} "
        f"through +{max_context_noise_packets} irrelevant packets"
    )
    print(
        "- context counterfactuals: "
        f"{'PASS' if result.checks['generated_context_counterfactual_sensitivity_passes'] else 'FAIL'}"
    )
    print(
        "- complementary evidence merge: "
        f"{'PASS' if result.checks['complementary_evidence_checks_pass'] else 'FAIL'}"
    )
    print()
    print("Incident Reasoning")
    print(
        "- isolate_customerdb: "
        f"{result.incident.query_counts['isolate_customerdb']} proof(s)"
    )
    print(
        "- causal ablations: "
        f"{sum(case.mode == 'primary_path_minimality' for case in result.incident.causal_ablation)}"
    )
    print(
        "- replay verification: "
        f"{'PASS' if all(result.replay_verification.values()) else 'FAIL'}"
    )
    print(
        "- semantic forgery rejection: "
        f"{'PASS' if result.checks['semantic_forgery_rejected_by_replay'] else 'FAIL'}"
    )
    max_noise_edges = max(
        (int(case["extra_edges"]) for case in result.noise_stability),
        default=0,
    )
    print(
        "- noise stability: "
        f"{'PASS' if result.checks['noise_stability_sweep_passes'] else 'FAIL'} "
        f"through +{max_noise_edges} extra trust edges"
    )
    print()
    print("Combined checks")
    for name, passed in result.checks.items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")
    print()
    print(f"Report: {result.report_path}")
    print(f"JSON: {result.result_path}")
    print(f"Contract: {result.contract_path}")
    print(f"Witness: {result.witness_path}")


def parse_noise_sweep_levels(text: str) -> tuple[int, ...]:
    levels = tuple(int(part.strip()) for part in text.split(",") if part.strip())
    if not levels:
        raise argparse.ArgumentTypeError("noise sweep levels must not be empty")
    if any(level < 0 for level in levels):
        raise argparse.ArgumentTypeError("noise sweep levels must be non-negative")
    return levels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/pettachainer-showcase"))
    parser.add_argument("--dispatch-iterations", type=int, default=20_000)
    parser.add_argument("--dispatch-repeats", type=int, default=3)
    parser.add_argument("--forward-steps", type=int, default=350)
    parser.add_argument("--query-steps", type=int, default=120)
    parser.add_argument("--context-timeout-s", type=int, default=30)
    parser.add_argument(
        "--context-noise-levels",
        type=parse_noise_sweep_levels,
        default=(0, 50, 200),
        help="Comma-separated counts of irrelevant context packets to inject",
    )
    parser.add_argument(
        "--noise-sweep-levels",
        type=parse_noise_sweep_levels,
        default=(0, 50, 200),
        help="Comma-separated counts of extra irrelevant Trusts facts to inject",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero if any check fails")
    args = parser.parse_args()

    result = run_showcase(
        output_dir=args.output_dir,
        dispatch_iterations=args.dispatch_iterations,
        dispatch_repeats=args.dispatch_repeats,
        forward_steps=args.forward_steps,
        query_steps=args.query_steps,
        noise_sweep_levels=args.noise_sweep_levels,
        context_noise_levels=args.context_noise_levels,
        context_timeout_s=args.context_timeout_s,
    )
    if args.json:
        print(json.dumps(asdict(result), indent=2, sort_keys=True))
    else:
        print_text(result)
    return 0 if not args.strict or all(result.checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
