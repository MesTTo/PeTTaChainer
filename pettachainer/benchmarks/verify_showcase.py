#!/usr/bin/env python3
"""Verify a saved PeTTaChainer showcase artifact directory."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import platform
import shutil
import sys
import warnings
import zipfile
from pathlib import Path
from typing import Any


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pettachainer.benchmarks.impressive_incident_response import (
    redirect_process_output,
    replay_audit_bundle,
    verify_audit_bundle,
)
from pettachainer.benchmarks.verify_context_showcase import (
    verify_context_showcase_artifacts,
)
from pettachainer.benchmarks.verify_complementary_evidence import (
    verify_complementary_evidence_artifacts,
)
from pettachainer.benchmarks.showcase import (
    CONTEXT_MIN_RANKING_MARGIN,
    canonical_json_sha256,
    context_counterfactual_sensitivity_cases,
    context_noise_stability_sweep,
    noise_stability_sweep,
    sha256_text,
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_json_pointer(document: object, pointer: str) -> object:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise KeyError(pointer)
    current = document
    for raw_part in pointer.lstrip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise KeyError(pointer)
    return current


def tamper_case_path(output_dir: Path, case_name: str) -> Path:
    return output_dir / "tamper-drill" / case_name


def verify_recorded_noise(result: dict[str, Any]) -> bool:
    cases = result.get("noise_stability", [])
    expected_sha = result.get("incident", {}).get("proof_sha256")
    return (
        bool(cases)
        and max(int(case["extra_edges"]) for case in cases) > 0
        and all(
            bool(case["stable"])
            and int(case["proofs"]) == 1
            and case["proof_sha256"] == expected_sha
            and int(case["built_in_noise_tokens"]) == 0
            and int(case["injected_noise_tokens"]) == 0
            for case in cases
        )
    )


def verify_recorded_context_noise(result: dict[str, Any]) -> bool:
    cases = result.get("context_noise_stability", [])
    return (
        bool(cases)
        and max(int(case["extra_packets"]) for case in cases) > 0
        and all(
            bool(case["stable"])
            and case["best_guard"] == ["type:Penguin"]
            and case["runner_up_guard"] != case["best_guard"]
            and float(case["ranking_margin"]) >= CONTEXT_MIN_RANKING_MARGIN
            and "type:Penguin" in case["routed_required"]
            and float(case["routed_strength"]) < 0.05
            and int(case["noise_guard_hits"]) == 0
            and int(case["noise_route_hits"]) == 0
            for case in cases
        )
    )


def verify_recorded_context_counterfactuals(result: dict[str, Any]) -> bool:
    cases = result.get("context_counterfactuals", [])
    by_name = {str(case.get("name")): case for case in cases}
    required = {
        "remove_penguin_exception",
        "invert_penguin_exception",
        "ambiguous_penguin_exception",
    }
    if set(by_name) != required:
        return False
    remove = by_name["remove_penguin_exception"]
    invert = by_name["invert_penguin_exception"]
    ambiguous = by_name["ambiguous_penguin_exception"]
    return (
        all(bool(case.get("passed")) for case in cases)
        and remove.get("expectation") == "selected_guard_removed"
        and remove.get("best_guard") != ["type:Penguin"]
        and "type:Penguin" not in remove.get("routed_required", [])
        and 0.55 < float(remove.get("routed_strength", 0.0)) < 0.80
        and invert.get("expectation") == "routed_strength_flips_positive"
        and invert.get("best_guard") == ["type:Penguin"]
        and float(invert.get("routed_strength", 0.0)) > 0.95
        and ambiguous.get("expectation") == "ranking_margin_collapses"
        and ambiguous.get("best_guard") == ["type:Penguin"]
        and 0.45 <= float(ambiguous.get("routed_strength", 0.0)) <= 0.55
        and float(ambiguous.get("ranking_margin", 1.0)) < CONTEXT_MIN_RANKING_MARGIN
    )


def hash_file(path: Path) -> str:
    return sha256_text(path.read_text(encoding="utf-8"))


def canonical_object_sha256(value: object) -> str:
    return canonical_json_sha256(value)


def merkle_leaf_hash(path: str, artifact_sha256: str) -> str:
    return canonical_object_sha256(
        {"kind": "artifact_leaf", "path": path, "sha256": artifact_sha256}
    )


def merkle_parent_hash(left_sha256: str, right_sha256: str) -> str:
    return canonical_object_sha256(
        {"kind": "artifact_node", "left": left_sha256, "right": right_sha256}
    )


def build_artifact_merkle_tree(
    artifact_hashes: dict[str, object],
) -> dict[str, object]:
    leaves = [
        {
            "path": path,
            "artifact_sha256": str(artifact_sha256),
            "leaf_sha256": merkle_leaf_hash(path, str(artifact_sha256)),
        }
        for path, artifact_sha256 in sorted(artifact_hashes.items())
    ]
    if not leaves:
        return {
            "tree_version": 1,
            "artifact_kind": "pettachainer_artifact_merkle_tree",
            "leaf_count": 0,
            "root_sha256": canonical_object_sha256([]),
            "leaves": [],
            "proofs": {},
        }

    levels: list[list[str]] = [[str(leaf["leaf_sha256"]) for leaf in leaves]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[str] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(merkle_parent_hash(left, right))
        levels.append(next_level)

    proofs: dict[str, list[dict[str, str]]] = {}
    for leaf_index, leaf in enumerate(leaves):
        index = leaf_index
        proof: list[dict[str, str]] = []
        for level in levels[:-1]:
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            sibling_sha = level[sibling_index] if sibling_index < len(level) else level[index]
            proof.append(
                {
                    "side": "right" if index % 2 == 0 else "left",
                    "sha256": sibling_sha,
                }
            )
            index //= 2
        proofs[str(leaf["path"])] = proof

    return {
        "tree_version": 1,
        "artifact_kind": "pettachainer_artifact_merkle_tree",
        "leaf_count": len(leaves),
        "root_sha256": levels[-1][0],
        "leaves": leaves,
        "proofs": proofs,
    }


def verify_artifact_merkle_proofs(tree: dict[str, object]) -> bool:
    root = str(tree.get("root_sha256", ""))
    leaves = list(tree.get("leaves", []))
    proofs = dict(tree.get("proofs", {}))
    if not root or not leaves:
        return False
    for leaf in leaves:
        path = str(leaf.get("path", ""))
        current = merkle_leaf_hash(path, str(leaf.get("artifact_sha256", "")))
        if current != leaf.get("leaf_sha256"):
            return False
        for step in list(proofs.get(path, [])):
            sibling = str(step.get("sha256", ""))
            if step.get("side") == "left":
                current = merkle_parent_hash(sibling, current)
            elif step.get("side") == "right":
                current = merkle_parent_hash(current, sibling)
            else:
                return False
        if current != root:
            return False
    return True


def artifact_key_from_path(artifact_path: Path, output_dir: Path) -> str:
    if artifact_path.is_absolute():
        try:
            return artifact_path.resolve().relative_to(output_dir).as_posix()
        except ValueError:
            return artifact_path.as_posix()
    return artifact_path.as_posix().lstrip("./")


def verify_artifact_inclusion(
    packet_path: Path,
    artifact_path: Path,
    *,
    artifact_dir: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {"packet_present": packet_path.exists()}
    if not checks["packet_present"]:
        checks["inclusion_verified"] = False
        return {
            "packet_path": str(packet_path),
            "artifact_path": str(artifact_path),
            "checks": checks,
        }

    packet = load_json(packet_path)
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else Path(str(packet.get("output_dir", packet_path.parent))).resolve()
    )
    artifact_key = artifact_key_from_path(artifact_path, output_dir)
    resolved_artifact_path = output_dir / artifact_key
    artifact_hashes = dict(packet.get("artifact_hashes", {}))
    tree = dict(packet.get("artifact_merkle_tree", {}))
    roots = dict(packet.get("roots", {}))
    leaves_by_path = {
        str(leaf.get("path", "")): dict(leaf) for leaf in list(tree.get("leaves", []))
    }
    proof = list(dict(tree.get("proofs", {})).get(artifact_key, []))
    expected_artifact_sha = str(artifact_hashes.get(artifact_key, ""))
    actual_artifact_sha = (
        hash_file(resolved_artifact_path) if resolved_artifact_path.exists() else ""
    )
    leaf = leaves_by_path.get(artifact_key, {})
    computed_leaf_sha = (
        merkle_leaf_hash(artifact_key, expected_artifact_sha)
        if expected_artifact_sha
        else ""
    )
    computed_root = computed_leaf_sha
    proof_steps_valid = bool(proof) or int(tree.get("leaf_count", 0)) == 1
    for step in proof:
        sibling = str(dict(step).get("sha256", ""))
        side = dict(step).get("side")
        if side == "left":
            computed_root = merkle_parent_hash(sibling, computed_root)
        elif side == "right":
            computed_root = merkle_parent_hash(computed_root, sibling)
        else:
            proof_steps_valid = False
            break

    checks.update(
        {
            "artifact_named_in_packet": artifact_key in artifact_hashes,
            "artifact_file_present": resolved_artifact_path.exists(),
            "artifact_hash_matches_packet": bool(expected_artifact_sha)
            and actual_artifact_sha == expected_artifact_sha,
            "leaf_present": bool(leaf),
            "leaf_hash_matches_packet_artifact": bool(leaf)
            and leaf.get("artifact_sha256") == expected_artifact_sha
            and leaf.get("leaf_sha256") == computed_leaf_sha,
            "proof_steps_valid": proof_steps_valid,
            "proof_root_matches_tree": bool(computed_root)
            and computed_root == tree.get("root_sha256"),
            "proof_root_matches_packet": bool(computed_root)
            and computed_root == roots.get("artifact_merkle_root_sha256"),
            "packet_merkle_root_matches_tree": roots.get("artifact_merkle_root_sha256")
            == tree.get("root_sha256"),
        }
    )
    checks["inclusion_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_path": str(resolved_artifact_path),
        "artifact_key": artifact_key,
        "artifact_sha256": actual_artifact_sha,
        "packet_artifact_sha256": expected_artifact_sha,
        "leaf_sha256": computed_leaf_sha,
        "computed_merkle_root_sha256": computed_root,
        "packet_merkle_root_sha256": roots.get("artifact_merkle_root_sha256", ""),
        "proof_length": len(proof),
        "checks": checks,
    }


def evidence_source_binding(
    packet_path: Path,
    packet: dict[str, Any],
    output_dir: Path,
    artifact_name: str,
) -> dict[str, object]:
    roots = dict(packet.get("roots", {}))
    artifact_hashes = dict(packet.get("artifact_hashes", {}))
    source_path = output_dir / artifact_name
    source_present = source_path.exists()
    actual_sha256 = hash_file(source_path) if source_present else ""
    expected_sha256 = ""
    anchor = "unbound"
    merkle_inclusion_verified = False

    if artifact_name in artifact_hashes:
        anchor = "artifact_merkle_tree"
        expected_sha256 = str(artifact_hashes.get(artifact_name, ""))
        inclusion = verify_artifact_inclusion(
            packet_path,
            Path(artifact_name),
            artifact_dir=output_dir,
        )
        merkle_inclusion_verified = bool(
            dict(inclusion["checks"]).get("inclusion_verified")
        )
    elif artifact_name == "showcase-verifier-result.json":
        anchor = "forensic_source_verifier_sha256"
        expected_sha256 = str(roots.get(anchor, ""))
    elif artifact_name == "showcase-verifier-red-team-result.json":
        anchor = "forensic_source_red_team_sha256"
        expected_sha256 = str(roots.get(anchor, ""))

    source_hash_matches_packet = (
        bool(expected_sha256) and actual_sha256 == expected_sha256
    )
    source_sealed = source_hash_matches_packet and (
        anchor != "artifact_merkle_tree" or merkle_inclusion_verified
    )
    return {
        "source_hash_anchor": anchor,
        "source_sha256": actual_sha256,
        "expected_source_sha256": expected_sha256,
        "source_hash_matches_packet": source_hash_matches_packet,
        "artifact_merkle_inclusion_verified": merkle_inclusion_verified,
        "source_sealed": source_sealed,
    }


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def build_claim_certificate(sweep: dict[str, object]) -> dict[str, object]:
    claims: list[dict[str, object]] = []
    evidence_links: list[dict[str, object]] = []
    for claim in list(sweep.get("claims", [])):
        claim_checks = dict(claim.get("checks", {}))
        anchors: dict[str, int] = {}
        claim_links = []
        for link in list(claim.get("evidence", [])):
            anchor = str(link.get("source_hash_anchor", "unbound"))
            anchors[anchor] = anchors.get(anchor, 0) + 1
            compact_link = {
                "claim_id": claim.get("claim_id", ""),
                "check": link.get("check", ""),
                "artifact": link.get("artifact", ""),
                "json_path": link.get("json_path", ""),
                "source_hash_anchor": anchor,
                "source_sha256": link.get("source_sha256", ""),
                "source_sealed": bool(link.get("source_sealed")),
                "resolved_matches_expected": bool(
                    link.get("resolved_matches_expected")
                ),
            }
            claim_links.append(compact_link)
            evidence_links.append(compact_link)
        claims.append(
            {
                "claim_id": claim.get("claim_id", ""),
                "description": claim.get("description", ""),
                "verified": bool(claim_checks.get("claim_verified")),
                "evidence_link_count": int(claim.get("evidence_link_count", 0)),
                "source_anchor_counts": anchors,
                "checks": claim_checks,
                "evidence": claim_links,
            }
        )

    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_claim_certificate",
        "packet_path": sweep.get("packet_path", ""),
        "packet_root_sha256": sweep.get("packet_root_sha256", ""),
        "claim_ledger_root_sha256": sweep.get("claim_ledger_root_sha256", ""),
        "claim_sweep_result_path": sweep.get("result_path", ""),
        "claim_sweep_verified": bool(
            dict(sweep.get("checks", {})).get("claim_sweep_verified")
        ),
        "claim_count": int(sweep.get("claim_count", 0)),
        "verified_claim_count": int(sweep.get("verified_claim_count", 0)),
        "evidence_link_count": int(sweep.get("evidence_link_count", 0)),
        "sealed_source_count": int(sweep.get("sealed_source_count", 0)),
        "source_anchor_counts": sweep.get("source_anchor_counts", {}),
        "failed_claims": sweep.get("failed_claims", []),
        "claims": claims,
        "evidence_links": evidence_links,
    }
    return {**body, "certificate_sha256": canonical_object_sha256(body)}


def claim_certificate_markdown(certificate: dict[str, object]) -> str:
    claim_count = int(certificate.get("claim_count", 0))
    verified_claim_count = int(certificate.get("verified_claim_count", 0))
    evidence_link_count = int(certificate.get("evidence_link_count", 0))
    sealed_source_count = int(certificate.get("sealed_source_count", 0))
    lines = [
        "# PeTTaChainer Claim Certificate",
        "",
        f"- Certificate SHA-256: `{certificate.get('certificate_sha256', '')}`",
        f"- Packet root: `{certificate.get('packet_root_sha256', '')}`",
        f"- Claim ledger root: `{certificate.get('claim_ledger_root_sha256', '')}`",
        "- Claim sweep: "
        f"`{'PASS' if certificate.get('claim_sweep_verified') else 'FAIL'}`",
        f"- Claims verified: `{verified_claim_count}/{claim_count}`",
        f"- Evidence sources sealed: `{sealed_source_count}/{evidence_link_count}`",
        "- Source anchors: "
        f"`{json.dumps(certificate.get('source_anchor_counts', {}), sort_keys=True)}`",
        "",
        "## Claims",
        "",
        "| Claim | Verified | Evidence Links | Source Anchors | Description |",
        "|---|---:|---:|---|---|",
    ]
    for claim in list(certificate.get("claims", [])):
        lines.append(
            "| "
            f"{markdown_cell(claim.get('claim_id', ''))} | "
            f"{'yes' if claim.get('verified') else 'no'} | "
            f"{claim.get('evidence_link_count', 0)} | "
            f"`{json.dumps(claim.get('source_anchor_counts', {}), sort_keys=True)}` | "
            f"{markdown_cell(claim.get('description', ''))} |"
        )

    lines.extend(
        [
            "",
            "## Evidence Links",
            "",
            "| Claim | Check | Source | Pointer | Anchor | Sealed | Source SHA-256 |",
            "|---|---|---|---|---|---:|---|",
        ]
    )
    for link in list(certificate.get("evidence_links", [])):
        lines.append(
            "| "
            f"{markdown_cell(link.get('claim_id', ''))} | "
            f"{markdown_cell(link.get('check', ''))} | "
            f"{markdown_cell(link.get('artifact', ''))} | "
            f"`{markdown_cell(link.get('json_path', ''))}` | "
            f"`{markdown_cell(link.get('source_hash_anchor', ''))}` | "
            f"{'yes' if link.get('source_sealed') else 'no'} | "
            f"`{markdown_cell(link.get('source_sha256', ''))}` |"
        )
    return "\n".join(lines) + "\n"


def write_claim_certificate(
    sweep: dict[str, object],
    certificate_json_path: Path,
    certificate_markdown_path: Path,
) -> dict[str, object]:
    certificate = build_claim_certificate(sweep)
    write_json(certificate_json_path, certificate)
    certificate_markdown_path.write_text(
        claim_certificate_markdown(certificate),
        encoding="utf-8",
    )
    return certificate


def verify_claim_certificate(
    packet_path: Path,
    certificate_path: Path,
    *,
    artifact_dir: Path | None = None,
    certificate_markdown_path: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {
        "certificate_present": certificate_path.exists(),
        "packet_present": packet_path.exists(),
    }
    if not checks["certificate_present"] or not checks["packet_present"]:
        checks["claim_certificate_verified"] = False
        return {
            "packet_path": str(packet_path),
            "certificate_path": str(certificate_path),
            "checks": checks,
        }

    certificate = load_json(certificate_path)
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else certificate_path.resolve().parent
    )
    markdown_path = (
        certificate_markdown_path
        if certificate_markdown_path is not None
        else certificate_path.with_suffix(".md")
    )
    certificate_body = {
        key: value for key, value in certificate.items() if key != "certificate_sha256"
    }
    recomputed_sha = canonical_object_sha256(certificate_body)
    expected_sweep = verify_all_claims(packet_path, artifact_dir=output_dir)
    expected_sweep["packet_path"] = certificate.get("packet_path", str(packet_path))
    expected_sweep["result_path"] = certificate.get("claim_sweep_result_path", "")
    expected_certificate = build_claim_certificate(expected_sweep)
    markdown_text = (
        markdown_path.read_text(encoding="utf-8") if markdown_path.exists() else ""
    )
    expected_markdown = claim_certificate_markdown(certificate)
    checks.update(
        {
            "certificate_kind_matches": certificate.get("artifact_kind")
            == "pettachainer_showcase_claim_certificate",
            "certificate_hash_matches": certificate.get("certificate_sha256")
            == recomputed_sha,
            "certificate_matches_packet_sweep": certificate == expected_certificate,
            "markdown_present": markdown_path.exists(),
            "markdown_matches_certificate": bool(markdown_text)
            and markdown_text == expected_markdown,
            "claim_sweep_verified": bool(certificate.get("claim_sweep_verified")),
            "all_claims_verified": int(certificate.get("claim_count", 0)) > 0
            and certificate.get("claim_count")
            == certificate.get("verified_claim_count"),
            "all_sources_sealed": int(certificate.get("evidence_link_count", 0)) > 0
            and certificate.get("evidence_link_count")
            == certificate.get("sealed_source_count"),
        }
    )
    checks["claim_certificate_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "certificate_path": str(certificate_path),
        "certificate_markdown_path": str(markdown_path),
        "certificate_sha256": certificate.get("certificate_sha256", ""),
        "recomputed_certificate_sha256": recomputed_sha,
        "claim_count": certificate.get("claim_count", 0),
        "verified_claim_count": certificate.get("verified_claim_count", 0),
        "evidence_link_count": certificate.get("evidence_link_count", 0),
        "sealed_source_count": certificate.get("sealed_source_count", 0),
        "source_anchor_counts": certificate.get("source_anchor_counts", {}),
        "checks": checks,
    }


def run_claim_certificate_red_team(
    packet_path: Path,
    certificate_path: Path,
    *,
    artifact_dir: Path | None = None,
    certificate_markdown_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    packet_path = packet_path.resolve()
    certificate_path = certificate_path.resolve()
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else certificate_path.parent.resolve()
    )
    markdown_path = (
        certificate_markdown_path.resolve()
        if certificate_markdown_path is not None
        else certificate_path.with_suffix(".md")
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir / "claim-certificate-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    baseline = verify_claim_certificate(
        packet_path,
        certificate_path,
        artifact_dir=output_dir,
        certificate_markdown_path=markdown_path,
    )
    baseline_verified = bool(baseline["checks"].get("claim_certificate_verified"))

    specs = {
        "certificate_hash_forgery": {
            "mutate_json": lambda cert: cert.__setitem__(
                "certificate_sha256", "0" * 64
            ),
            "expected_failed_checks": ["certificate_hash_matches"],
        },
        "claim_count_forgery": {
            "mutate_json": lambda cert: cert.__setitem__(
                "verified_claim_count", int(cert.get("verified_claim_count", 0)) - 1
            ),
            "recompute_certificate_hash": True,
            "expected_failed_checks": [
                "certificate_matches_packet_sweep",
                "markdown_matches_certificate",
                "all_claims_verified",
            ],
        },
        "source_seal_forgery": {
            "mutate_json": lambda cert: cert.__setitem__(
                "sealed_source_count", int(cert.get("sealed_source_count", 0)) - 1
            ),
            "recompute_certificate_hash": True,
            "expected_failed_checks": [
                "certificate_matches_packet_sweep",
                "markdown_matches_certificate",
                "all_sources_sealed",
            ],
        },
        "evidence_anchor_forgery": {
            "mutate_json": lambda cert: cert["evidence_links"][0].__setitem__(
                "source_hash_anchor", "unbound"
            ),
            "recompute_certificate_hash": True,
            "expected_failed_checks": [
                "certificate_matches_packet_sweep",
                "markdown_matches_certificate",
            ],
        },
        "markdown_forgery": {
            "mutate_markdown": lambda text: text.replace(
                "Claims verified: `",
                "Claims verified: `forged ",
                1,
            ),
            "expected_failed_checks": ["markdown_matches_certificate"],
        },
    }

    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        forged_json_path = red_team_dir / f"{name}.json"
        forged_markdown_path = red_team_dir / f"{name}.md"
        forged_certificate = load_json(certificate_path)
        forged_markdown = markdown_path.read_text(encoding="utf-8")
        if "mutate_json" in spec:
            spec["mutate_json"](forged_certificate)
        if bool(spec.get("recompute_certificate_hash")):
            forged_body = {
                key: value
                for key, value in forged_certificate.items()
                if key != "certificate_sha256"
            }
            forged_certificate["certificate_sha256"] = canonical_object_sha256(
                forged_body
            )
        if "mutate_markdown" in spec:
            forged_markdown = spec["mutate_markdown"](forged_markdown)
        write_json(forged_json_path, forged_certificate)
        forged_markdown_path.write_text(forged_markdown, encoding="utf-8")
        details = verify_claim_certificate(
            packet_path,
            forged_json_path,
            artifact_dir=output_dir,
            certificate_markdown_path=forged_markdown_path,
        )
        checks = dict(details["checks"])
        expected_failed = list(spec["expected_failed_checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and not bool(checks.get("claim_certificate_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "certificate_path": str(forged_json_path),
            "certificate_markdown_path": str(forged_markdown_path),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "claim_certificate_verified": bool(
                checks.get("claim_certificate_verified")
            ),
            "rejected": rejected,
        }

    summary = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "certificate_path": str(certificate_path),
        "certificate_markdown_path": str(markdown_path),
        "red_team_dir": str(red_team_dir),
        "baseline_claim_certificate_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "claim_certificate_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-claim-certificate-red-team-result.json"),
    }
    write_json(Path(summary["result_path"]), summary)
    return summary


def optional_hash(path_value: object) -> str:
    if not str(path_value):
        return ""
    path = Path(str(path_value))
    return hash_file(path) if path.exists() and path.is_file() else ""


def build_audit_verdict(
    packet_details: dict[str, object],
    *,
    packet_red_team: dict[str, object] | None,
    evidence_index_red_team: dict[str, object] | None,
    claim_sweep: dict[str, object] | None,
    claim_certificate: dict[str, object] | None,
    claim_certificate_red_team: dict[str, object] | None,
) -> dict[str, object]:
    packet_checks = dict(packet_details.get("checks", {}))
    claim_sweep_checks = (
        dict(claim_sweep.get("checks", {})) if claim_sweep is not None else {}
    )
    certificate_checks = (
        dict(claim_certificate.get("checks", {}))
        if claim_certificate is not None
        else {}
    )
    component_checks = {
        "packet_verified": bool(packet_checks.get("packet_verified")),
        "forensic_packet_red_team_pass": bool(packet_red_team)
        and bool(packet_red_team.get("packet_red_team_pass")),
        "evidence_index_red_team_pass": bool(evidence_index_red_team)
        and bool(evidence_index_red_team.get("evidence_index_red_team_pass")),
        "claim_sweep_verified": bool(claim_sweep_checks.get("claim_sweep_verified")),
        "claim_certificate_verified": bool(
            certificate_checks.get("claim_certificate_verified")
        ),
        "claim_certificate_red_team_pass": bool(claim_certificate_red_team)
        and bool(
            claim_certificate_red_team.get("claim_certificate_red_team_pass")
        ),
    }
    failed_checks = [
        name for name, passed in component_checks.items() if not bool(passed)
    ]
    red_team_case_counts = {
        "forensic_packet": int(packet_red_team.get("case_count", 0))
        if packet_red_team is not None
        else 0,
        "evidence_index": int(evidence_index_red_team.get("case_count", 0))
        if evidence_index_red_team is not None
        else 0,
        "claim_certificate": int(claim_certificate_red_team.get("case_count", 0))
        if claim_certificate_red_team is not None
        else 0,
    }
    component_hashes = {
        "packet_json_sha256": optional_hash(packet_details.get("packet_path", "")),
        "evidence_index_json_sha256": packet_details.get(
            "evidence_index_sha256", ""
        ),
        "evidence_index_markdown_sha256": packet_details.get(
            "evidence_index_markdown_sha256", ""
        ),
        "claim_sweep_json_sha256": optional_hash(claim_sweep.get("result_path", ""))
        if claim_sweep is not None
        else "",
        "claim_certificate_json_sha256": optional_hash(
            claim_certificate.get("certificate_path", "")
        )
        if claim_certificate is not None
        else "",
        "claim_certificate_markdown_sha256": optional_hash(
            claim_certificate.get("certificate_markdown_path", "")
        )
        if claim_certificate is not None
        else "",
        "packet_red_team_json_sha256": optional_hash(packet_red_team.get("result_path", ""))
        if packet_red_team is not None
        else "",
        "evidence_index_red_team_json_sha256": optional_hash(
            evidence_index_red_team.get("result_path", "")
        )
        if evidence_index_red_team is not None
        else "",
        "claim_certificate_red_team_json_sha256": optional_hash(
            claim_certificate_red_team.get("result_path", "")
        )
        if claim_certificate_red_team is not None
        else "",
    }
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_verdict",
        "packet_path": packet_details.get("packet_path", ""),
        "artifact_dir": packet_details.get("artifact_dir", ""),
        "packet_root_sha256": packet_details.get("packet_root_sha256", ""),
        "claim_certificate_sha256": claim_certificate.get("certificate_sha256", "")
        if claim_certificate is not None
        else "",
        "verdict": "PASS" if not failed_checks else "FAIL",
        "component_checks": component_checks,
        "failed_checks": failed_checks,
        "claim_count": int(claim_sweep.get("claim_count", 0))
        if claim_sweep is not None
        else 0,
        "verified_claim_count": int(claim_sweep.get("verified_claim_count", 0))
        if claim_sweep is not None
        else 0,
        "evidence_link_count": int(claim_sweep.get("evidence_link_count", 0))
        if claim_sweep is not None
        else 0,
        "sealed_source_count": int(claim_sweep.get("sealed_source_count", 0))
        if claim_sweep is not None
        else 0,
        "source_anchor_counts": claim_sweep.get("source_anchor_counts", {})
        if claim_sweep is not None
        else {},
        "red_team_case_counts": red_team_case_counts,
        "red_team_case_count_total": sum(red_team_case_counts.values()),
        "component_hashes": component_hashes,
    }
    return {**body, "audit_verdict_sha256": canonical_object_sha256(body)}


def audit_verdict_markdown(verdict: dict[str, object]) -> str:
    component_checks = dict(verdict.get("component_checks", {}))
    red_team_case_counts = dict(verdict.get("red_team_case_counts", {}))
    component_hashes = dict(verdict.get("component_hashes", {}))
    lines = [
        "# PeTTaChainer Audit Verdict",
        "",
        f"- Verdict: `{verdict.get('verdict', 'FAIL')}`",
        f"- Audit verdict SHA-256: `{verdict.get('audit_verdict_sha256', '')}`",
        f"- Packet root: `{verdict.get('packet_root_sha256', '')}`",
        f"- Claim certificate SHA-256: `{verdict.get('claim_certificate_sha256', '')}`",
        f"- Claims verified: `{verdict.get('verified_claim_count', 0)}/{verdict.get('claim_count', 0)}`",
        f"- Evidence sources sealed: `{verdict.get('sealed_source_count', 0)}/{verdict.get('evidence_link_count', 0)}`",
        f"- Red-team cases: `{verdict.get('red_team_case_count_total', 0)}`",
        "",
        "## Component Checks",
        "",
        "| Check | Status |",
        "|---|---:|",
    ]
    for name, passed in sorted(component_checks.items()):
        lines.append(f"| {markdown_cell(name)} | {'PASS' if passed else 'FAIL'} |")
    lines.extend(
        [
            "",
            "## Red-Team Cases",
            "",
            "| Family | Cases |",
            "|---|---:|",
        ]
    )
    for name, count in sorted(red_team_case_counts.items()):
        lines.append(f"| {markdown_cell(name)} | {count} |")
    lines.extend(
        [
            "",
            "## Component Hashes",
            "",
            "| Artifact | SHA-256 |",
            "|---|---|",
        ]
    )
    for name, digest in sorted(component_hashes.items()):
        lines.append(f"| {markdown_cell(name)} | `{markdown_cell(digest)}` |")
    return "\n".join(lines) + "\n"


def write_audit_verdict(
    packet_details: dict[str, object],
    *,
    packet_red_team: dict[str, object] | None,
    evidence_index_red_team: dict[str, object] | None,
    claim_sweep: dict[str, object] | None,
    claim_certificate: dict[str, object] | None,
    claim_certificate_red_team: dict[str, object] | None,
    result_path: Path,
    markdown_path: Path,
) -> dict[str, object]:
    verdict = build_audit_verdict(
        packet_details,
        packet_red_team=packet_red_team,
        evidence_index_red_team=evidence_index_red_team,
        claim_sweep=claim_sweep,
        claim_certificate=claim_certificate,
        claim_certificate_red_team=claim_certificate_red_team,
    )
    verdict["result_path"] = str(result_path)
    verdict["markdown_path"] = str(markdown_path)
    write_json(result_path, verdict)
    markdown_path.write_text(audit_verdict_markdown(verdict), encoding="utf-8")
    return verdict


def audit_verdict_hash_body(verdict: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in verdict.items()
        if key
        not in {
            "audit_verdict_sha256",
            "result_path",
            "markdown_path",
        }
    }


def audit_verdict_compare_body(
    body: dict[str, object], *, packet_path: Path
) -> dict[str, object]:
    comparable = dict(body)
    raw_packet_path = comparable.get("packet_path", "")
    if raw_packet_path:
        try:
            if Path(str(raw_packet_path)).resolve() == packet_path.resolve():
                comparable["packet_path"] = str(packet_path.resolve())
        except OSError:
            pass
    return comparable


def verify_audit_verdict(
    packet_path: Path,
    verdict_path: Path,
    *,
    artifact_dir: Path | None = None,
    markdown_path: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {
        "audit_verdict_present": verdict_path.exists(),
        "packet_present": packet_path.exists(),
    }
    if not checks["audit_verdict_present"] or not checks["packet_present"]:
        checks["audit_verdict_verified"] = False
        return {
            "packet_path": str(packet_path),
            "audit_verdict_path": str(verdict_path),
            "checks": checks,
        }

    verdict = load_json(verdict_path)
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else verdict_path.resolve().parent
    )
    verdict_markdown_path = (
        markdown_path if markdown_path is not None else verdict_path.with_suffix(".md")
    )
    packet_details = verify_forensic_packet_details(packet_path, artifact_dir=output_dir)
    packet_red_team_path = output_dir / "showcase-forensic-packet-red-team-result.json"
    evidence_index_red_team_path = (
        output_dir / "showcase-evidence-index-red-team-result.json"
    )
    claim_sweep_path = output_dir / "showcase-claim-sweep-result.json"
    claim_certificate_path = output_dir / "showcase-claim-certificate.json"
    claim_certificate_markdown_path = output_dir / "showcase-claim-certificate.md"
    claim_certificate_red_team_path = (
        output_dir / "showcase-claim-certificate-red-team-result.json"
    )
    packet_red_team = (
        load_json(packet_red_team_path) if packet_red_team_path.exists() else {}
    )
    evidence_index_red_team = (
        load_json(evidence_index_red_team_path)
        if evidence_index_red_team_path.exists()
        else {}
    )
    claim_sweep = load_json(claim_sweep_path) if claim_sweep_path.exists() else {}
    claim_certificate = verify_claim_certificate(
        packet_path,
        claim_certificate_path,
        artifact_dir=output_dir,
        certificate_markdown_path=claim_certificate_markdown_path,
    )
    claim_certificate_red_team = (
        load_json(claim_certificate_red_team_path)
        if claim_certificate_red_team_path.exists()
        else {}
    )
    expected = build_audit_verdict(
        packet_details,
        packet_red_team=packet_red_team,
        evidence_index_red_team=evidence_index_red_team,
        claim_sweep=claim_sweep,
        claim_certificate=claim_certificate,
        claim_certificate_red_team=claim_certificate_red_team,
    )
    verdict_body = audit_verdict_hash_body(verdict)
    expected_body = audit_verdict_hash_body(expected)
    verdict_compare_body = audit_verdict_compare_body(
        verdict_body, packet_path=packet_path
    )
    expected_compare_body = audit_verdict_compare_body(
        expected_body, packet_path=packet_path
    )
    mismatch_keys = [
        key
        for key in sorted(set(verdict_compare_body) | set(expected_compare_body))
        if verdict_compare_body.get(key) != expected_compare_body.get(key)
    ]
    recomputed_sha = canonical_object_sha256(verdict_body)
    markdown_text = (
        verdict_markdown_path.read_text(encoding="utf-8")
        if verdict_markdown_path.exists()
        else ""
    )
    expected_markdown = audit_verdict_markdown(verdict)
    expected_hashes = dict(verdict.get("component_hashes", {}))
    component_hash_checks = {
        name: bool(expected_hash) and optional_hash(path) == expected_hash
        for name, path, expected_hash in [
            (
                "packet_json_sha256",
                packet_path,
                expected_hashes.get("packet_json_sha256", ""),
            ),
            (
                "evidence_index_json_sha256",
                output_dir / "showcase-evidence-index.json",
                expected_hashes.get("evidence_index_json_sha256", ""),
            ),
            (
                "evidence_index_markdown_sha256",
                output_dir / "showcase-evidence-index.md",
                expected_hashes.get("evidence_index_markdown_sha256", ""),
            ),
            (
                "claim_sweep_json_sha256",
                claim_sweep_path,
                expected_hashes.get("claim_sweep_json_sha256", ""),
            ),
            (
                "claim_certificate_json_sha256",
                claim_certificate_path,
                expected_hashes.get("claim_certificate_json_sha256", ""),
            ),
            (
                "claim_certificate_markdown_sha256",
                claim_certificate_markdown_path,
                expected_hashes.get("claim_certificate_markdown_sha256", ""),
            ),
            (
                "packet_red_team_json_sha256",
                packet_red_team_path,
                expected_hashes.get("packet_red_team_json_sha256", ""),
            ),
            (
                "evidence_index_red_team_json_sha256",
                evidence_index_red_team_path,
                expected_hashes.get("evidence_index_red_team_json_sha256", ""),
            ),
            (
                "claim_certificate_red_team_json_sha256",
                claim_certificate_red_team_path,
                expected_hashes.get("claim_certificate_red_team_json_sha256", ""),
            ),
        ]
    }
    checks.update(
        {
            "audit_verdict_kind_matches": verdict.get("artifact_kind")
            == "pettachainer_showcase_audit_verdict",
            "audit_verdict_hash_matches": verdict.get("audit_verdict_sha256")
            == recomputed_sha,
            "audit_verdict_matches_components": verdict_compare_body
            == expected_compare_body,
            "markdown_present": verdict_markdown_path.exists(),
            "markdown_matches_verdict": bool(markdown_text)
            and markdown_text == expected_markdown,
            "component_hashes_match_files": bool(component_hash_checks)
            and all(component_hash_checks.values()),
            "verdict_passes": verdict.get("verdict") == "PASS",
            "all_component_checks_pass": all(
                bool(value)
                for value in dict(verdict.get("component_checks", {})).values()
            ),
            "claim_counts_pass": int(verdict.get("claim_count", 0)) > 0
            and verdict.get("claim_count") == verdict.get("verified_claim_count"),
            "source_counts_pass": int(verdict.get("evidence_link_count", 0)) > 0
            and verdict.get("evidence_link_count")
            == verdict.get("sealed_source_count"),
        }
    )
    checks["audit_verdict_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "audit_verdict_path": str(verdict_path),
        "audit_verdict_markdown_path": str(verdict_markdown_path),
        "audit_verdict_sha256": verdict.get("audit_verdict_sha256", ""),
        "recomputed_audit_verdict_sha256": recomputed_sha,
        "verdict": verdict.get("verdict", "FAIL"),
        "claim_count": verdict.get("claim_count", 0),
        "verified_claim_count": verdict.get("verified_claim_count", 0),
        "evidence_link_count": verdict.get("evidence_link_count", 0),
        "sealed_source_count": verdict.get("sealed_source_count", 0),
        "red_team_case_count_total": verdict.get("red_team_case_count_total", 0),
        "mismatch_keys": mismatch_keys,
        "component_hash_checks": component_hash_checks,
        "checks": checks,
    }


def run_audit_verdict_red_team(
    packet_path: Path,
    verdict_path: Path,
    *,
    artifact_dir: Path | None = None,
    markdown_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    packet_path = packet_path.resolve()
    verdict_path = verdict_path.resolve()
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else verdict_path.parent.resolve()
    )
    verdict_markdown_path = (
        markdown_path.resolve() if markdown_path is not None else verdict_path.with_suffix(".md")
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir / "audit-verdict-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    baseline = verify_audit_verdict(
        packet_path,
        verdict_path,
        artifact_dir=output_dir,
        markdown_path=verdict_markdown_path,
    )
    baseline_verified = bool(baseline["checks"].get("audit_verdict_verified"))
    specs = {
        "audit_hash_forgery": {
            "mutate_json": lambda verdict: verdict.__setitem__(
                "audit_verdict_sha256", "0" * 64
            ),
            "expected_failed_checks": ["audit_verdict_hash_matches"],
        },
        "component_check_forgery": {
            "mutate_json": lambda verdict: verdict["component_checks"].__setitem__(
                "packet_verified", False
            ),
            "recompute_audit_hash": True,
            "expected_failed_checks": [
                "audit_verdict_matches_components",
                "markdown_matches_verdict",
                "all_component_checks_pass",
            ],
        },
        "claim_count_forgery": {
            "mutate_json": lambda verdict: verdict.__setitem__(
                "verified_claim_count", int(verdict.get("verified_claim_count", 0)) - 1
            ),
            "recompute_audit_hash": True,
            "expected_failed_checks": [
                "audit_verdict_matches_components",
                "markdown_matches_verdict",
                "claim_counts_pass",
            ],
        },
        "component_hash_forgery": {
            "mutate_json": lambda verdict: verdict["component_hashes"].__setitem__(
                "packet_json_sha256", "0" * 64
            ),
            "recompute_audit_hash": True,
            "expected_failed_checks": [
                "audit_verdict_matches_components",
                "markdown_matches_verdict",
                "component_hashes_match_files",
            ],
        },
        "markdown_forgery": {
            "mutate_markdown": lambda text: text.replace(
                "Verdict: `PASS`",
                "Verdict: `FORGED`",
                1,
            ),
            "expected_failed_checks": ["markdown_matches_verdict"],
        },
    }
    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        forged_json_path = red_team_dir / f"{name}.json"
        forged_markdown_path = red_team_dir / f"{name}.md"
        forged_verdict = load_json(verdict_path)
        forged_markdown = verdict_markdown_path.read_text(encoding="utf-8")
        if "mutate_json" in spec:
            spec["mutate_json"](forged_verdict)
        if bool(spec.get("recompute_audit_hash")):
            forged_verdict["audit_verdict_sha256"] = canonical_object_sha256(
                audit_verdict_hash_body(forged_verdict)
            )
        if "mutate_markdown" in spec:
            forged_markdown = spec["mutate_markdown"](forged_markdown)
        write_json(forged_json_path, forged_verdict)
        forged_markdown_path.write_text(forged_markdown, encoding="utf-8")
        details = verify_audit_verdict(
            packet_path,
            forged_json_path,
            artifact_dir=output_dir,
            markdown_path=forged_markdown_path,
        )
        checks = dict(details["checks"])
        expected_failed = list(spec["expected_failed_checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and not bool(checks.get("audit_verdict_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "audit_verdict_path": str(forged_json_path),
            "audit_verdict_markdown_path": str(forged_markdown_path),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "audit_verdict_verified": bool(checks.get("audit_verdict_verified")),
            "rejected": rejected,
        }

    summary = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "audit_verdict_path": str(verdict_path),
        "audit_verdict_markdown_path": str(verdict_markdown_path),
        "red_team_dir": str(red_team_dir),
        "baseline_audit_verdict_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "audit_verdict_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-audit-verdict-red-team-result.json"),
    }
    write_json(Path(summary["result_path"]), summary)
    return summary


def build_audit_proof_graph(
    packet_details: dict[str, object],
    certificate: dict[str, object],
    verdict: dict[str, object],
) -> dict[str, object]:
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []

    def add_node(node_id: str, kind: str, **attrs: object) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, **attrs})

    def add_edge(source: str, target: str, relation: str, **attrs: object) -> None:
        edges.append({"from": source, "to": target, "relation": relation, **attrs})

    verdict_sha = str(verdict.get("audit_verdict_sha256", ""))
    certificate_sha = str(certificate.get("certificate_sha256", ""))
    packet_root = str(packet_details.get("packet_root_sha256", ""))
    claim_root = str(certificate.get("claim_ledger_root_sha256", ""))
    verdict_id = f"audit_verdict:{verdict_sha}"
    certificate_id = f"claim_certificate:{certificate_sha}"
    packet_id = f"forensic_packet:{packet_root}"
    claim_ledger_id = f"claim_ledger:{claim_root}"

    add_node(
        verdict_id,
        "audit_verdict",
        verdict=verdict.get("verdict", "FAIL"),
        sha256=verdict_sha,
    )
    add_node(packet_id, "forensic_packet", packet_root_sha256=packet_root)
    add_node(
        certificate_id,
        "claim_certificate",
        certificate_sha256=certificate_sha,
        claim_count=int(certificate.get("claim_count", 0)),
    )
    add_node(claim_ledger_id, "claim_ledger", claim_ledger_root_sha256=claim_root)
    add_edge(packet_id, verdict_id, "packet_attests_verdict")
    add_edge(certificate_id, verdict_id, "certificate_supports_verdict")
    add_edge(packet_id, certificate_id, "packet_anchors_certificate")
    add_edge(claim_ledger_id, certificate_id, "ledger_anchors_certificate")

    for name, digest in sorted(dict(verdict.get("component_hashes", {})).items()):
        component_id = f"component:{name}"
        add_node(
            component_id,
            "component_hash",
            component=name,
            sha256=str(digest),
        )
        add_edge(component_id, verdict_id, "component_hash_bound")

    source_nodes: set[str] = set()
    for claim in sorted(
        list(certificate.get("claims", [])), key=lambda item: str(item.get("claim_id", ""))
    ):
        claim_id_text = str(claim.get("claim_id", ""))
        claim_id = f"claim:{claim_id_text}"
        add_node(
            claim_id,
            "claim",
            claim_id=claim_id_text,
            description=claim.get("description", ""),
            verified=bool(claim.get("verified")),
            evidence_link_count=int(claim.get("evidence_link_count", 0)),
        )
        add_edge(claim_id, certificate_id, "claim_listed_in_certificate")
        for index, link in enumerate(list(claim.get("evidence", []))):
            check = str(link.get("check", ""))
            evidence_id = f"evidence:{claim_id_text}:{index}:{check}"
            artifact = str(link.get("artifact", ""))
            anchor = str(link.get("source_hash_anchor", "unbound"))
            source_sha = str(link.get("source_sha256", ""))
            source_id = f"source:{artifact}:{anchor}:{source_sha}"
            if source_id not in source_nodes:
                add_node(
                    source_id,
                    "sealed_source",
                    artifact=artifact,
                    source_hash_anchor=anchor,
                    source_sha256=source_sha,
                    source_sealed=bool(link.get("source_sealed")),
                )
                source_nodes.add(source_id)
            add_node(
                evidence_id,
                "evidence_link",
                claim_id=claim_id_text,
                check=check,
                artifact=artifact,
                json_path=link.get("json_path", ""),
                source_hash_anchor=anchor,
                source_sha256=source_sha,
                source_sealed=bool(link.get("source_sealed")),
                resolved_matches_expected=bool(
                    link.get("resolved_matches_expected")
                ),
            )
            add_edge(source_id, evidence_id, "source_resolves_evidence")
            add_edge(evidence_id, claim_id, "evidence_supports_claim")

    sorted_nodes = sorted(nodes.values(), key=lambda node: str(node["id"]))
    sorted_edges = sorted(
        edges,
        key=lambda edge: (
            str(edge["from"]),
            str(edge["to"]),
            str(edge["relation"]),
            str(edge.get("check", "")),
        ),
    )
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_proof_graph",
        "graph_version": 1,
        "packet_root_sha256": packet_root,
        "audit_verdict_sha256": verdict_sha,
        "claim_certificate_sha256": certificate_sha,
        "claim_ledger_root_sha256": claim_root,
        "verdict": verdict.get("verdict", "FAIL"),
        "claim_count": int(certificate.get("claim_count", 0)),
        "verified_claim_count": int(certificate.get("verified_claim_count", 0)),
        "evidence_link_count": int(certificate.get("evidence_link_count", 0)),
        "sealed_source_count": int(certificate.get("sealed_source_count", 0)),
        "node_count": len(sorted_nodes),
        "edge_count": len(sorted_edges),
        "nodes": sorted_nodes,
        "edges": sorted_edges,
    }
    return {**body, "proof_graph_sha256": canonical_object_sha256(body)}


def audit_proof_graph_hash_body(graph: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in graph.items()
        if key not in {"proof_graph_sha256", "result_path", "markdown_path", "dot_path"}
    }


def audit_proof_graph_markdown(graph: dict[str, object]) -> str:
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    kind_counts: dict[str, int] = {}
    for node in nodes:
        kind = str(node.get("kind", "unknown"))
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    lines = [
        "# PeTTaChainer Audit Proof Graph",
        "",
        f"- Verdict: `{graph.get('verdict', 'FAIL')}`",
        f"- Proof graph SHA-256: `{graph.get('proof_graph_sha256', '')}`",
        f"- Audit verdict SHA-256: `{graph.get('audit_verdict_sha256', '')}`",
        f"- Packet root: `{graph.get('packet_root_sha256', '')}`",
        f"- Claim certificate SHA-256: `{graph.get('claim_certificate_sha256', '')}`",
        f"- Claims verified: `{graph.get('verified_claim_count', 0)}/{graph.get('claim_count', 0)}`",
        f"- Evidence sources sealed: `{graph.get('sealed_source_count', 0)}/{graph.get('evidence_link_count', 0)}`",
        f"- Nodes: `{graph.get('node_count', 0)}`",
        f"- Edges: `{graph.get('edge_count', 0)}`",
        "",
        "## Node Kinds",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    for kind, count in sorted(kind_counts.items()):
        lines.append(f"| {markdown_cell(kind)} | {count} |")
    lines.extend(
        [
            "",
            "## Claims",
            "",
            "| Claim | Verified | Evidence Links |",
            "|---|---:|---:|",
        ]
    )
    for node in nodes:
        if node.get("kind") != "claim":
            continue
        lines.append(
            "| "
            f"{markdown_cell(node.get('claim_id', ''))} | "
            f"{'yes' if node.get('verified') else 'no'} | "
            f"{node.get('evidence_link_count', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Edges",
            "",
            "| From | Relation | To |",
            "|---|---|---|",
        ]
    )
    for edge in edges:
        lines.append(
            "| "
            f"`{markdown_cell(edge.get('from', ''))}` | "
            f"{markdown_cell(edge.get('relation', ''))} | "
            f"`{markdown_cell(edge.get('to', ''))}` |"
        )
    return "\n".join(lines) + "\n"


def dot_quote(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def audit_proof_graph_dot(graph: dict[str, object]) -> str:
    color_by_kind = {
        "audit_verdict": "#e6f4ea",
        "forensic_packet": "#e8f0fe",
        "claim_certificate": "#fff4e5",
        "claim_ledger": "#fce8e6",
        "claim": "#f1f3f4",
        "evidence_link": "#e0f2f1",
        "sealed_source": "#f3e8fd",
        "component_hash": "#fef7e0",
    }
    lines = [
        "digraph PeTTaChainerAuditProofGraph {",
        "  graph [rankdir=LR, labelloc=\"t\", label=\"PeTTaChainer audit proof graph\"];",
        "  node [shape=box, style=\"rounded,filled\", fontname=\"monospace\", fontsize=10];",
        "  edge [fontname=\"monospace\", fontsize=9];",
    ]
    for node in list(graph.get("nodes", [])):
        node_id = str(node.get("id", ""))
        kind = str(node.get("kind", "unknown"))
        fill = color_by_kind.get(kind, "#ffffff")
        if kind == "claim":
            label = f"claim\\n{node.get('claim_id', '')}\\nverified={bool(node.get('verified'))}"
        elif kind == "evidence_link":
            label = (
                f"evidence\\n{node.get('claim_id', '')}\\n"
                f"{node.get('check', '')}"
            )
        elif kind == "sealed_source":
            label = (
                f"source\\n{node.get('artifact', '')}\\n"
                f"{node.get('source_hash_anchor', '')}"
            )
        elif kind == "component_hash":
            label = f"component\\n{node.get('component', '')}"
        else:
            label = f"{kind}\\n{node_id.split(':', 1)[-1][:16]}"
        lines.append(
            "  "
            f"{dot_quote(node_id)} [label={dot_quote(label)}, fillcolor={dot_quote(fill)}];"
        )
    for edge in list(graph.get("edges", [])):
        lines.append(
            "  "
            f"{dot_quote(edge.get('from', ''))} -> "
            f"{dot_quote(edge.get('to', ''))} "
            f"[label={dot_quote(edge.get('relation', ''))}];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_audit_proof_graph(
    packet_path: Path,
    audit_verdict_path: Path,
    claim_certificate_path: Path,
    *,
    artifact_dir: Path | None = None,
    result_path: Path,
    markdown_path: Path,
    dot_path: Path | None = None,
) -> dict[str, object]:
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else audit_verdict_path.resolve().parent
    )
    graph = build_audit_proof_graph(
        verify_forensic_packet_details(packet_path, artifact_dir=output_dir),
        load_json(claim_certificate_path),
        load_json(audit_verdict_path),
    )
    graph["result_path"] = str(result_path)
    graph["markdown_path"] = str(markdown_path)
    dot_path = dot_path if dot_path is not None else result_path.with_suffix(".dot")
    graph["dot_path"] = str(dot_path)
    write_json(result_path, graph)
    markdown_path.write_text(audit_proof_graph_markdown(graph), encoding="utf-8")
    dot_path.write_text(audit_proof_graph_dot(graph), encoding="utf-8")
    return graph


def verify_audit_proof_graph(
    packet_path: Path,
    graph_path: Path,
    *,
    artifact_dir: Path | None = None,
    audit_verdict_path: Path | None = None,
    audit_verdict_markdown_path: Path | None = None,
    claim_certificate_path: Path | None = None,
    claim_certificate_markdown_path: Path | None = None,
    graph_markdown_path: Path | None = None,
    graph_dot_path: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {
        "proof_graph_present": graph_path.exists(),
        "packet_present": packet_path.exists(),
    }
    if not checks["proof_graph_present"] or not checks["packet_present"]:
        checks["audit_proof_graph_verified"] = False
        return {
            "packet_path": str(packet_path),
            "audit_proof_graph_path": str(graph_path),
            "checks": checks,
        }

    output_dir = (
        artifact_dir.resolve() if artifact_dir is not None else graph_path.resolve().parent
    )
    audit_verdict_path = (
        audit_verdict_path
        if audit_verdict_path is not None
        else output_dir / "showcase-audit-verdict.json"
    )
    claim_certificate_path = (
        claim_certificate_path
        if claim_certificate_path is not None
        else output_dir / "showcase-claim-certificate.json"
    )
    graph_markdown_path = (
        graph_markdown_path if graph_markdown_path is not None else graph_path.with_suffix(".md")
    )
    graph_dot_path = (
        graph_dot_path if graph_dot_path is not None else graph_path.with_suffix(".dot")
    )
    audit_verdict_markdown_path = (
        audit_verdict_markdown_path
        if audit_verdict_markdown_path is not None
        else audit_verdict_path.with_suffix(".md")
    )
    claim_certificate_markdown_path = (
        claim_certificate_markdown_path
        if claim_certificate_markdown_path is not None
        else claim_certificate_path.with_suffix(".md")
    )
    graph = load_json(graph_path)
    verdict = load_json(audit_verdict_path) if audit_verdict_path.exists() else {}
    certificate = (
        load_json(claim_certificate_path) if claim_certificate_path.exists() else {}
    )
    expected = build_audit_proof_graph(
        verify_forensic_packet_details(packet_path, artifact_dir=output_dir),
        certificate,
        verdict,
    )
    graph_body = audit_proof_graph_hash_body(graph)
    expected_body = audit_proof_graph_hash_body(expected)
    recomputed_sha = canonical_object_sha256(graph_body)
    markdown_text = (
        graph_markdown_path.read_text(encoding="utf-8")
        if graph_markdown_path.exists()
        else ""
    )
    expected_markdown = audit_proof_graph_markdown(graph)
    dot_text = (
        graph_dot_path.read_text(encoding="utf-8")
        if graph_dot_path.exists()
        else ""
    )
    expected_dot = audit_proof_graph_dot(graph)
    audit_verdict = verify_audit_verdict(
        packet_path,
        audit_verdict_path,
        artifact_dir=output_dir,
        markdown_path=audit_verdict_markdown_path,
    )
    claim_certificate = verify_claim_certificate(
        packet_path,
        claim_certificate_path,
        artifact_dir=output_dir,
        certificate_markdown_path=claim_certificate_markdown_path,
    )
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    node_ids = {str(node.get("id", "")) for node in nodes}
    claim_nodes = [node for node in nodes if node.get("kind") == "claim"]
    evidence_nodes = [node for node in nodes if node.get("kind") == "evidence_link"]
    claim_support_counts: dict[str, int] = {}
    for edge in edges:
        if edge.get("relation") == "evidence_supports_claim":
            target = str(edge.get("to", ""))
            claim_support_counts[target] = claim_support_counts.get(target, 0) + 1
    checks.update(
        {
            "proof_graph_kind_matches": graph.get("artifact_kind")
            == "pettachainer_showcase_audit_proof_graph",
            "proof_graph_hash_matches": graph.get("proof_graph_sha256")
            == recomputed_sha,
            "proof_graph_matches_components": graph_body == expected_body,
            "markdown_present": graph_markdown_path.exists(),
            "markdown_matches_graph": bool(markdown_text)
            and markdown_text == expected_markdown,
            "dot_present": graph_dot_path.exists(),
            "dot_matches_graph": bool(dot_text) and dot_text == expected_dot,
            "audit_verdict_verified": bool(
                audit_verdict["checks"].get("audit_verdict_verified")
            ),
            "claim_certificate_verified": bool(
                claim_certificate["checks"].get("claim_certificate_verified")
            ),
            "graph_node_edge_counts_match": int(graph.get("node_count", -1))
            == len(nodes)
            and int(graph.get("edge_count", -1)) == len(edges),
            "graph_edges_resolve_nodes": bool(edges)
            and all(
                str(edge.get("from", "")) in node_ids
                and str(edge.get("to", "")) in node_ids
                for edge in edges
            ),
            "all_claim_nodes_verified": bool(claim_nodes)
            and len(claim_nodes) == int(graph.get("claim_count", 0))
            and all(bool(node.get("verified")) for node in claim_nodes),
            "claim_edges_complete": bool(claim_nodes)
            and all(
                claim_support_counts.get(str(node.get("id", "")), 0)
                == int(node.get("evidence_link_count", 0))
                for node in claim_nodes
            ),
            "all_evidence_links_resolve": bool(evidence_nodes)
            and len(evidence_nodes) == int(graph.get("evidence_link_count", 0))
            and all(
                bool(node.get("resolved_matches_expected"))
                and bool(node.get("source_sealed"))
                for node in evidence_nodes
            ),
            "source_counts_pass": int(graph.get("evidence_link_count", 0)) > 0
            and graph.get("evidence_link_count") == graph.get("sealed_source_count"),
            "verdict_passes": graph.get("verdict") == "PASS",
        }
    )
    checks["audit_proof_graph_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "audit_proof_graph_path": str(graph_path),
        "audit_proof_graph_markdown_path": str(graph_markdown_path),
        "audit_proof_graph_dot_path": str(graph_dot_path),
        "audit_verdict_path": str(audit_verdict_path),
        "claim_certificate_path": str(claim_certificate_path),
        "proof_graph_sha256": graph.get("proof_graph_sha256", ""),
        "recomputed_proof_graph_sha256": recomputed_sha,
        "mismatch_keys": [
            key
            for key in sorted(set(graph_body) | set(expected_body))
            if graph_body.get(key) != expected_body.get(key)
        ],
        "claim_count": graph.get("claim_count", 0),
        "verified_claim_count": graph.get("verified_claim_count", 0),
        "evidence_link_count": graph.get("evidence_link_count", 0),
        "sealed_source_count": graph.get("sealed_source_count", 0),
        "node_count": graph.get("node_count", 0),
        "edge_count": graph.get("edge_count", 0),
        "checks": checks,
    }


def run_audit_proof_graph_red_team(
    packet_path: Path,
    graph_path: Path,
    *,
    artifact_dir: Path | None = None,
    audit_verdict_path: Path | None = None,
    audit_verdict_markdown_path: Path | None = None,
    claim_certificate_path: Path | None = None,
    claim_certificate_markdown_path: Path | None = None,
    graph_markdown_path: Path | None = None,
    graph_dot_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    packet_path = packet_path.resolve()
    graph_path = graph_path.resolve()
    output_dir = (
        artifact_dir.resolve() if artifact_dir is not None else graph_path.parent.resolve()
    )
    graph_markdown_path = (
        graph_markdown_path.resolve()
        if graph_markdown_path is not None
        else graph_path.with_suffix(".md")
    )
    graph_dot_path = (
        graph_dot_path.resolve()
        if graph_dot_path is not None
        else graph_path.with_suffix(".dot")
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir / "audit-proof-graph-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    baseline = verify_audit_proof_graph(
        packet_path,
        graph_path,
        artifact_dir=output_dir,
        audit_verdict_path=audit_verdict_path,
        audit_verdict_markdown_path=audit_verdict_markdown_path,
        claim_certificate_path=claim_certificate_path,
        claim_certificate_markdown_path=claim_certificate_markdown_path,
        graph_markdown_path=graph_markdown_path,
        graph_dot_path=graph_dot_path,
    )
    baseline_verified = bool(
        baseline["checks"].get("audit_proof_graph_verified")
    )

    def recompute_graph_hash(graph: dict[str, object]) -> None:
        graph["proof_graph_sha256"] = canonical_object_sha256(
            audit_proof_graph_hash_body(graph)
        )

    def mutate_first_node(
        graph: dict[str, object], kind: str, field: str, value: object
    ) -> None:
        for node in list(graph.get("nodes", [])):
            if node.get("kind") == kind:
                node[field] = value
                return

    def remove_first_claim_edge(graph: dict[str, object]) -> None:
        edges = list(graph.get("edges", []))
        for index, edge in enumerate(edges):
            if edge.get("relation") == "evidence_supports_claim":
                del edges[index]
                graph["edges"] = edges
                graph["edge_count"] = len(edges)
                return

    specs = {
        "proof_graph_hash_forgery": {
            "mutate_json": lambda graph: graph.__setitem__(
                "proof_graph_sha256", "0" * 64
            ),
            "expected_failed_checks": ["proof_graph_hash_matches"],
        },
        "claim_node_forgery": {
            "mutate_json": lambda graph: mutate_first_node(
                graph, "claim", "verified", False
            ),
            "recompute_graph_hash": True,
            "expected_failed_checks": [
                "proof_graph_matches_components",
                "markdown_matches_graph",
                "all_claim_nodes_verified",
            ],
        },
        "evidence_seal_forgery": {
            "mutate_json": lambda graph: mutate_first_node(
                graph, "evidence_link", "source_sealed", False
            ),
            "recompute_graph_hash": True,
            "expected_failed_checks": [
                "proof_graph_matches_components",
                "markdown_matches_graph",
                "all_evidence_links_resolve",
            ],
        },
        "claim_edge_forgery": {
            "mutate_json": remove_first_claim_edge,
            "recompute_graph_hash": True,
            "expected_failed_checks": [
                "proof_graph_matches_components",
                "markdown_matches_graph",
                "claim_edges_complete",
            ],
        },
        "markdown_forgery": {
            "mutate_markdown": lambda text: text.replace(
                "Verdict: `PASS`", "Verdict: `FORGED`", 1
            ),
            "expected_failed_checks": ["markdown_matches_graph"],
        },
        "dot_forgery": {
            "mutate_dot": lambda text: text.replace(
                "audit proof graph", "forged proof graph", 1
            ),
            "expected_failed_checks": ["dot_matches_graph"],
        },
    }
    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        forged_json_path = red_team_dir / f"{name}.json"
        forged_markdown_path = red_team_dir / f"{name}.md"
        forged_dot_path = red_team_dir / f"{name}.dot"
        forged_graph = load_json(graph_path)
        forged_markdown = graph_markdown_path.read_text(encoding="utf-8")
        forged_dot = graph_dot_path.read_text(encoding="utf-8")
        if "mutate_json" in spec:
            spec["mutate_json"](forged_graph)
        if bool(spec.get("recompute_graph_hash")):
            recompute_graph_hash(forged_graph)
        if "mutate_markdown" in spec:
            forged_markdown = spec["mutate_markdown"](forged_markdown)
        if "mutate_dot" in spec:
            forged_dot = spec["mutate_dot"](forged_dot)
        write_json(forged_json_path, forged_graph)
        forged_markdown_path.write_text(forged_markdown, encoding="utf-8")
        forged_dot_path.write_text(forged_dot, encoding="utf-8")
        details = verify_audit_proof_graph(
            packet_path,
            forged_json_path,
            artifact_dir=output_dir,
            audit_verdict_path=audit_verdict_path,
            audit_verdict_markdown_path=audit_verdict_markdown_path,
            claim_certificate_path=claim_certificate_path,
            claim_certificate_markdown_path=claim_certificate_markdown_path,
            graph_markdown_path=forged_markdown_path,
            graph_dot_path=forged_dot_path,
        )
        checks = dict(details["checks"])
        expected_failed = list(spec["expected_failed_checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and not bool(checks.get("audit_proof_graph_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "audit_proof_graph_path": str(forged_json_path),
            "audit_proof_graph_markdown_path": str(forged_markdown_path),
            "audit_proof_graph_dot_path": str(forged_dot_path),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "audit_proof_graph_verified": bool(
                checks.get("audit_proof_graph_verified")
            ),
            "rejected": rejected,
        }

    summary = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "audit_proof_graph_path": str(graph_path),
        "audit_proof_graph_markdown_path": str(graph_markdown_path),
        "audit_proof_graph_dot_path": str(graph_dot_path),
        "red_team_dir": str(red_team_dir),
        "baseline_audit_proof_graph_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "audit_proof_graph_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-audit-proof-graph-red-team-result.json"),
    }
    write_json(Path(summary["result_path"]), summary)
    return summary


AUDIT_CAPSULE_REQUIRED_ROLES = {
    "forensic_packet",
    "claim_certificate",
    "audit_verdict",
    "audit_proof_graph",
    "audit_proof_graph_dot",
    "standalone_verifier",
    "standalone_archive_verifier",
    "transparency_log",
    "audit_dashboard",
    "one_command_verifier",
    "checksum_manifest",
    "provenance_attestation",
    "audit_receipt",
    "audit_policy",
    "runtime_manifest",
}

AUDIT_CAPSULE_STANDALONE_VERIFIER = "showcase-standalone-verifier.py"
AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER = (
    "showcase-standalone-archive-verifier.py"
)
AUDIT_CAPSULE_TRANSPARENCY_LOG = "showcase-transparency-log.jsonl"
AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN = "showcase-transparency-log.md"
AUDIT_CAPSULE_AUDIT_DASHBOARD = "showcase-audit-dashboard.html"
AUDIT_CAPSULE_ONE_COMMAND_VERIFIER = "showcase-verify-all.py"
AUDIT_CAPSULE_CHECKSUM_MANIFEST = "showcase-checksums.sha256"
AUDIT_CAPSULE_PROVENANCE_ATTESTATION = "showcase-provenance.intoto.json"
AUDIT_CAPSULE_AUDIT_RECEIPT = "showcase-audit-receipt.json"
AUDIT_CAPSULE_AUDIT_POLICY = "showcase-audit-policy.json"
AUDIT_CAPSULE_RUNTIME_MANIFEST = "showcase-runtime-manifest.json"
AUDIT_DECISION_CERTIFICATE = "showcase-audit-decision.json"
AUDIT_DECISION_STANDALONE_VERIFIER = "showcase-audit-decision-verifier.py"
AUDIT_DECISION_GAUNTLET = "showcase-audit-gauntlet.py"
AUDIT_CHALLENGE_TRANSCRIPT_JSON = "showcase-audit-challenge-transcript.json"
AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN = "showcase-audit-challenge-transcript.md"
AUDIT_BOARD_JSON = "showcase-audit-board.json"
AUDIT_BOARD_MARKDOWN = "showcase-audit-board.md"
AUDIT_FACTS_JSON = "showcase-audit-facts.json"
AUDIT_FACTS_METTA = "showcase-audit-facts.metta"


def audit_capsule_verification_commands() -> list[str]:
    return [
        ".venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --strict",
        "python artifacts/showcase/showcase-standalone-verifier.py artifacts/showcase",
        "python artifacts/showcase/showcase-standalone-archive-verifier.py artifacts/showcase/showcase-audit-capsule.zip",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_audit_transparency_log; raise SystemExit(0 if verify_audit_transparency_log('artifacts/showcase')['checks']['transparency_log_verified'] else 1)\"",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_audit_dashboard; raise SystemExit(0 if verify_audit_dashboard('artifacts/showcase')['checks']['audit_dashboard_verified'] else 1)\"",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_audit_policy; raise SystemExit(0 if verify_audit_policy('artifacts/showcase')['checks']['audit_policy_verified'] else 1)\"",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_runtime_manifest; raise SystemExit(0 if verify_runtime_manifest('artifacts/showcase')['checks']['runtime_manifest_verified'] else 1)\"",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_audit_receipt; raise SystemExit(0 if verify_audit_receipt('artifacts/showcase')['checks']['audit_receipt_verified'] else 1)\"",
        ".venv/bin/python -c \"from pettachainer.benchmarks.verify_showcase import verify_audit_provenance_attestation; raise SystemExit(0 if verify_audit_provenance_attestation('artifacts/showcase')['checks']['provenance_attestation_verified'] else 1)\"",
        "python artifacts/showcase/showcase-verify-all.py artifacts/showcase",
        "cd artifacts/showcase && sha256sum -c showcase-checksums.sha256",
        "dot -Tsvg artifacts/showcase/showcase-audit-proof-graph.dot > artifacts/showcase/showcase-audit-proof-graph.svg",
    ]


def audit_capsule_hash_body(capsule: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in capsule.items()
        if key not in {"audit_capsule_sha256", "result_path", "markdown_path"}
    }


def audit_capsule_relative_path(path: Path, output_dir: Path) -> str:
    try:
        return path.resolve().relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def audit_capsule_candidate_paths(
    output_dir: Path,
    *,
    include_transparency_log: bool = True,
    include_checksum_manifest: bool = True,
    include_provenance_attestation: bool = True,
    include_audit_receipt: bool = True,
    include_audit_policy: bool = True,
) -> list[Path]:
    suffixes = {
        ".json",
        ".jsonl",
        ".md",
        ".dot",
        ".svg",
        ".log",
        ".py",
        ".html",
        ".sha256",
    }
    excluded_prefixes = {
        "audit-decision",
        "audit-capsule",
        "showcase-audit-board",
        "showcase-audit-challenge-transcript",
        "showcase-audit-decision",
        "showcase-audit-facts",
        "showcase-audit-gauntlet",
        "showcase-audit-capsule",
    }
    if not include_transparency_log:
        excluded_prefixes.add("showcase-transparency-log")
    if not include_checksum_manifest:
        excluded_prefixes.add("showcase-checksums")
    if not include_provenance_attestation:
        excluded_prefixes.add("showcase-provenance")
    if not include_audit_receipt:
        excluded_prefixes.add("showcase-audit-receipt")
    if not include_audit_policy:
        excluded_prefixes.add("showcase-audit-policy")
    paths: list[Path] = []
    for path in output_dir.iterdir() if output_dir.exists() else []:
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if any(path.name.startswith(prefix) for prefix in excluded_prefixes):
            continue
        paths.append(path)
    return sorted(paths, key=lambda item: item.name)


def audit_capsule_roles(output_dir: Path, files: list[dict[str, object]]) -> dict[str, str]:
    roles: dict[str, str] = {}
    kind_roles = {
        "pettachainer_showcase_forensic_packet": "forensic_packet",
        "pettachainer_showcase_claim_certificate": "claim_certificate",
        "pettachainer_showcase_audit_verdict": "audit_verdict",
        "pettachainer_showcase_audit_proof_graph": "audit_proof_graph",
    }
    for file_entry in files:
        relative_path = str(file_entry.get("path", ""))
        path = output_dir / relative_path
        if relative_path == AUDIT_CAPSULE_STANDALONE_VERIFIER:
            roles["standalone_verifier"] = relative_path
        if relative_path == AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER:
            roles["standalone_archive_verifier"] = relative_path
        if relative_path == AUDIT_CAPSULE_TRANSPARENCY_LOG:
            roles["transparency_log"] = relative_path
        if relative_path == AUDIT_CAPSULE_AUDIT_DASHBOARD:
            roles["audit_dashboard"] = relative_path
        if relative_path == AUDIT_CAPSULE_ONE_COMMAND_VERIFIER:
            roles["one_command_verifier"] = relative_path
        if relative_path == AUDIT_CAPSULE_CHECKSUM_MANIFEST:
            roles["checksum_manifest"] = relative_path
        if relative_path == AUDIT_CAPSULE_PROVENANCE_ATTESTATION:
            roles["provenance_attestation"] = relative_path
        if relative_path == AUDIT_CAPSULE_AUDIT_RECEIPT:
            roles["audit_receipt"] = relative_path
        if relative_path == AUDIT_CAPSULE_AUDIT_POLICY:
            roles["audit_policy"] = relative_path
        if relative_path == AUDIT_CAPSULE_RUNTIME_MANIFEST:
            roles["runtime_manifest"] = relative_path
        if path.suffix != ".json" or not path.exists():
            continue
        try:
            payload = load_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(payload, dict):
            continue
        role = kind_roles.get(str(payload.get("artifact_kind", "")))
        if role is not None:
            roles[role] = relative_path
        if role == "audit_proof_graph":
            dot_path = payload.get("dot_path", "")
            if dot_path:
                dot_relative = audit_capsule_relative_path(
                    Path(str(dot_path)), output_dir
                )
                if (output_dir / dot_relative).exists():
                    roles["audit_proof_graph_dot"] = dot_relative
    return dict(sorted(roles.items()))


def audit_dashboard_load_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    payload = load_json(path)
    return payload if isinstance(payload, dict) else {}


def audit_dashboard_bool_label(value: object) -> str:
    return "PASS" if bool(value) else "FAIL"


def audit_dashboard_html_cell(value: object) -> str:
    return html.escape(str(value), quote=True)


def audit_dashboard_badge(label: str, value: object) -> str:
    status = audit_dashboard_bool_label(value)
    css_class = "pass" if bool(value) else "fail"
    return (
        f'<span class="badge {css_class}">'
        f"{audit_dashboard_html_cell(label)}: {status}</span>"
    )


def audit_dashboard_model(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    packet = audit_dashboard_load_json(output_dir / "showcase-forensic-packet.json")
    verdict = audit_dashboard_load_json(output_dir / "showcase-audit-verdict.json")
    graph = audit_dashboard_load_json(output_dir / "showcase-audit-proof-graph.json")
    claim_certificate = audit_dashboard_load_json(
        output_dir / "showcase-claim-certificate.json"
    )
    audit_verdict_red_team = audit_dashboard_load_json(
        output_dir / "showcase-audit-verdict-red-team-result.json"
    )
    proof_graph_red_team = audit_dashboard_load_json(
        output_dir / "showcase-audit-proof-graph-red-team-result.json"
    )
    packet_verdict = dict(packet.get("verdict", {}))
    red_team = dict(packet.get("red_team", {}))
    source_paths = [
        "showcase-forensic-packet.json",
        "showcase-claim-certificate.json",
        "showcase-audit-verdict.json",
        "showcase-audit-proof-graph.json",
        "showcase-audit-proof-graph.dot",
        "showcase-audit-proof-graph.svg",
        "showcase-audit-verdict-red-team-result.json",
        "showcase-audit-proof-graph-red-team-result.json",
    ]
    source_hashes = [
        {
            "path": relative_path,
            "sha256": hash_file(output_dir / relative_path)
            if (output_dir / relative_path).exists()
            else "",
            "bytes": (output_dir / relative_path).stat().st_size
            if (output_dir / relative_path).exists()
            else 0,
        }
        for relative_path in source_paths
    ]
    return {
        "packet_root_sha256": packet.get("packet_root_sha256", ""),
        "packet_verified": bool(packet_verdict.get("verifier_checks_pass"))
        and bool(packet_verdict.get("red_team_rejections_pass")),
        "packet_claim_count": len(dict(packet.get("claim_ledger", {}))),
        "packet_artifact_count": len(dict(packet.get("artifact_hashes", {}))),
        "packet_red_team_case_count": len(dict(red_team.get("cases", {}))),
        "audit_verdict_sha256": verdict.get("audit_verdict_sha256", ""),
        "audit_verdict_pass": verdict.get("verdict") == "PASS",
        "verified_claim_count": verdict.get("verified_claim_count", 0),
        "claim_count": verdict.get("claim_count", 0),
        "sealed_source_count": verdict.get("sealed_source_count", 0),
        "evidence_link_count": verdict.get("evidence_link_count", 0),
        "claim_certificate_sha256": claim_certificate.get(
            "claim_certificate_sha256", ""
        ),
        "proof_graph_sha256": graph.get("proof_graph_sha256", ""),
        "proof_graph_pass": graph.get("verdict") == "PASS",
        "proof_graph_nodes": graph.get("node_count", 0),
        "proof_graph_edges": graph.get("edge_count", 0),
        "audit_verdict_red_team_pass": bool(
            audit_verdict_red_team.get("audit_verdict_red_team_pass")
        ),
        "audit_verdict_red_team_cases": audit_verdict_red_team.get("case_count", 0),
        "audit_proof_graph_red_team_pass": bool(
            proof_graph_red_team.get("audit_proof_graph_red_team_pass")
        ),
        "audit_proof_graph_red_team_cases": proof_graph_red_team.get(
            "case_count", 0
        ),
        "source_hashes": source_hashes,
    }


def audit_dashboard_html(output_dir: Path) -> str:
    model = audit_dashboard_model(output_dir)
    source_rows = []
    for item in list(model["source_hashes"]):
        source_rows.append(
            "<tr>"
            f"<td><code>{audit_dashboard_html_cell(item.get('path', ''))}</code></td>"
            f"<td>{audit_dashboard_html_cell(item.get('bytes', 0))}</td>"
            f"<td><code>{audit_dashboard_html_cell(item.get('sha256', ''))}</code></td>"
            "</tr>"
        )
    badges = [
        audit_dashboard_badge("packet", model["packet_verified"]),
        audit_dashboard_badge("verdict", model["audit_verdict_pass"]),
        audit_dashboard_badge("proof graph", model["proof_graph_pass"]),
        audit_dashboard_badge(
            "verdict red-team",
            model["audit_verdict_red_team_pass"],
        ),
        audit_dashboard_badge(
            "graph red-team",
            model["audit_proof_graph_red_team_pass"],
        ),
    ]
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>PeTTaChainer Audit Dashboard</title>\n"
        "<style>\n"
        ":root{color-scheme:light dark;font-family:Inter,Segoe UI,Arial,sans-serif;}"
        "body{margin:0;background:#f6f7f9;color:#18202a;}"
        "main{max-width:1180px;margin:0 auto;padding:32px 20px 44px;}"
        "h1{font-size:32px;line-height:1.1;margin:0 0 8px;}"
        "h2{font-size:18px;margin:0 0 14px;}"
        ".sub{color:#526070;margin:0 0 22px;}"
        ".badges{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 24px;}"
        ".badge{border-radius:999px;padding:7px 11px;font-size:13px;font-weight:700;}"
        ".pass{background:#d9f4e8;color:#0b6a3d;}"
        ".fail{background:#fce0df;color:#a32119;}"
        ".grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;}"
        ".card{background:#fff;border:1px solid #dce2ea;border-radius:8px;padding:16px;}"
        ".metric{font-size:28px;font-weight:800;margin:2px 0 4px;}"
        ".label{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#667386;}"
        "section{margin-top:18px;}"
        "table{width:100%;border-collapse:collapse;font-size:13px;}"
        "th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #e3e8ef;vertical-align:top;}"
        "th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#667386;}"
        "code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all;}"
        "@media (max-width:760px){.grid{grid-template-columns:1fr 1fr;}main{padding:22px 12px;}}"
        "@media (prefers-color-scheme:dark){body{background:#11161d;color:#edf2f7;}"
        ".sub,.label,th{color:#a6b3c2;}.card{background:#18202a;border-color:#2b3948;}"
        "th,td{border-color:#2b3948;}.pass{background:#123d2b;color:#9ce5bf;}"
        ".fail{background:#4b1c1b;color:#ffb8b4;}}\n"
        "</style>\n"
        "</head>\n"
        "<body><main>\n"
        "<h1>PeTTaChainer Audit Dashboard</h1>\n"
        '<p class="sub">Deterministic sealed summary of the forensic packet, audit verdict, proof graph, and adversarial checks.</p>\n'
        f'<div class="badges">{"".join(badges)}</div>\n'
        '<section class="grid">\n'
        f'<div class="card"><div class="label">Claims verified</div><div class="metric">{audit_dashboard_html_cell(model["verified_claim_count"])}/{audit_dashboard_html_cell(model["claim_count"])}</div></div>\n'
        f'<div class="card"><div class="label">Sealed sources</div><div class="metric">{audit_dashboard_html_cell(model["sealed_source_count"])}</div></div>\n'
        f'<div class="card"><div class="label">Proof graph</div><div class="metric">{audit_dashboard_html_cell(model["proof_graph_nodes"])} / {audit_dashboard_html_cell(model["proof_graph_edges"])}</div></div>\n'
        f'<div class="card"><div class="label">Red-team cases</div><div class="metric">{audit_dashboard_html_cell(int(model["packet_red_team_case_count"]) + int(model["audit_verdict_red_team_cases"]) + int(model["audit_proof_graph_red_team_cases"]))}</div></div>\n'
        "</section>\n"
        '<section class="card">\n'
        "<h2>Cryptographic Handles</h2>\n"
        "<table><tbody>\n"
        f'<tr><th>Forensic packet root</th><td><code>{audit_dashboard_html_cell(model["packet_root_sha256"])}</code></td></tr>\n'
        f'<tr><th>Audit verdict SHA-256</th><td><code>{audit_dashboard_html_cell(model["audit_verdict_sha256"])}</code></td></tr>\n'
        f'<tr><th>Claim certificate SHA-256</th><td><code>{audit_dashboard_html_cell(model["claim_certificate_sha256"])}</code></td></tr>\n'
        f'<tr><th>Proof graph SHA-256</th><td><code>{audit_dashboard_html_cell(model["proof_graph_sha256"])}</code></td></tr>\n'
        "</tbody></table>\n"
        "</section>\n"
        '<section class="card">\n'
        "<h2>Sealed Source Files</h2>\n"
        "<table><thead><tr><th>Path</th><th>Bytes</th><th>SHA-256</th></tr></thead><tbody>\n"
        f"{''.join(source_rows)}\n"
        "</tbody></table>\n"
        "</section>\n"
        "</main></body></html>\n"
    )


def write_audit_dashboard(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    dashboard_path = output_dir / AUDIT_CAPSULE_AUDIT_DASHBOARD
    dashboard_path.write_text(audit_dashboard_html(output_dir), encoding="utf-8")
    return {
        "path": str(dashboard_path),
        "sha256": hash_file(dashboard_path),
        "bytes": dashboard_path.stat().st_size,
    }


def verify_audit_dashboard(
    output_dir: str | Path,
    dashboard_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    dashboard_path = (
        Path(dashboard_path).resolve()
        if dashboard_path is not None
        else output_dir / AUDIT_CAPSULE_AUDIT_DASHBOARD
    )
    expected_html = audit_dashboard_html(output_dir)
    actual_html = (
        dashboard_path.read_text(encoding="utf-8") if dashboard_path.exists() else ""
    )
    checks = {
        "audit_dashboard_present": dashboard_path.exists(),
        "audit_dashboard_matches_sources": bool(actual_html)
        and actual_html == expected_html,
    }
    checks["audit_dashboard_verified"] = all(checks.values())
    return {
        "audit_dashboard_path": str(dashboard_path),
        "audit_dashboard_sha256": hash_file(dashboard_path)
        if dashboard_path.exists()
        else "",
        "checks": checks,
    }


def runtime_manifest_hash_body(manifest: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in manifest.items()
        if key != "runtime_manifest_sha256"
    }


def runtime_manifest_source_paths() -> list[Path]:
    return [
        REPO_ROOT / "pettachainer" / "benchmarks" / "verify_showcase.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "showcase.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "context_showcase.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "complementary_evidence.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "impressive_incident_response.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "verify_context_showcase.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "verify_complementary_evidence.py",
    ]


def runtime_manifest_generated_tool_paths(output_dir: Path) -> list[Path]:
    return [
        output_dir / AUDIT_CAPSULE_STANDALONE_VERIFIER,
        output_dir / AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER,
        output_dir / AUDIT_CAPSULE_ONE_COMMAND_VERIFIER,
        output_dir / AUDIT_CAPSULE_AUDIT_DASHBOARD,
        output_dir / AUDIT_CAPSULE_AUDIT_POLICY,
    ]


def runtime_manifest_file_entry(path: Path, *, base_dir: Path | None = None) -> dict[str, object]:
    relative_path = (
        path.resolve().relative_to(base_dir.resolve()).as_posix()
        if base_dir is not None and path.exists()
        else path.as_posix()
    )
    return {
        "path": relative_path,
        "present": path.is_file(),
        "sha256": hash_binary_file(path) if path.is_file() else "",
        "bytes": path.stat().st_size if path.is_file() else 0,
    }


def runtime_manifest_executable_entry(label: str, path_text: str | None) -> dict[str, object]:
    if not path_text:
        return {
            "label": label,
            "present": False,
            "path": "",
            "resolved_path": "",
            "sha256": "",
            "bytes": 0,
        }
    path = Path(path_text)
    resolved_path = path.resolve()
    return {
        "label": label,
        "present": resolved_path.is_file(),
        "path": path.as_posix(),
        "resolved_path": resolved_path.as_posix(),
        "sha256": hash_binary_file(resolved_path) if resolved_path.is_file() else "",
        "bytes": resolved_path.stat().st_size if resolved_path.is_file() else 0,
    }


def build_runtime_manifest(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    source_files = [
        runtime_manifest_file_entry(path, base_dir=REPO_ROOT)
        for path in runtime_manifest_source_paths()
    ]
    generated_tools = [
        runtime_manifest_file_entry(path, base_dir=output_dir)
        for path in runtime_manifest_generated_tool_paths(output_dir)
    ]
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_runtime_manifest",
        "manifest_version": 1,
        "subject_base": "capsule-relative",
        "python": {
            "implementation": sys.implementation.name,
            "version": sys.version,
            "version_info": list(sys.version_info[:5]),
            "executable": sys.executable,
            "prefix": sys.prefix,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_compiler": platform.python_compiler(),
        },
        "executables": [
            runtime_manifest_executable_entry("python", sys.executable),
            runtime_manifest_executable_entry("petta", shutil.which("petta")),
            runtime_manifest_executable_entry("swipl", shutil.which("swipl")),
            runtime_manifest_executable_entry("dot", shutil.which("dot")),
            runtime_manifest_executable_entry("sha256sum", shutil.which("sha256sum")),
        ],
        "source_files": sorted(source_files, key=lambda item: str(item["path"])),
        "generated_tools": sorted(generated_tools, key=lambda item: str(item["path"])),
    }
    return {**body, "runtime_manifest_sha256": canonical_object_sha256(body)}


def write_runtime_manifest(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    manifest_path = output_dir / AUDIT_CAPSULE_RUNTIME_MANIFEST
    manifest = build_runtime_manifest(output_dir)
    write_json(manifest_path, manifest)
    return {
        "path": str(manifest_path),
        "sha256": hash_binary_file(manifest_path),
        "bytes": manifest_path.stat().st_size,
        "runtime_manifest_sha256": manifest["runtime_manifest_sha256"],
    }


def verify_runtime_manifest(
    output_dir: str | Path,
    manifest_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    manifest_path = (
        Path(manifest_path).resolve()
        if manifest_path is not None
        else output_dir / AUDIT_CAPSULE_RUNTIME_MANIFEST
    )
    expected = build_runtime_manifest(output_dir)
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if manifest_path.exists():
            loaded = load_json(manifest_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    actual_body = runtime_manifest_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    checks = {
        "runtime_manifest_present": manifest_path.exists(),
        "runtime_manifest_json_valid": json_valid,
        "runtime_manifest_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_runtime_manifest",
        "runtime_manifest_hash_matches": actual.get("runtime_manifest_sha256")
        == actual_hash,
        "runtime_manifest_matches_current_runtime": bool(actual)
        and actual == expected,
    }
    checks["runtime_manifest_verified"] = all(checks.values())
    return {
        "runtime_manifest_path": str(manifest_path),
        "runtime_manifest_file_sha256": hash_binary_file(manifest_path)
        if manifest_path.exists()
        else "",
        "runtime_manifest_sha256": actual.get("runtime_manifest_sha256", ""),
        "expected_runtime_manifest_sha256": expected.get(
            "runtime_manifest_sha256", ""
        ),
        "checks": checks,
    }


def audit_policy_hash_body(policy: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in policy.items() if key != "audit_policy_sha256"}


def audit_policy_required_capsule_checks() -> list[str]:
    return [
        "audit_capsule_kind_matches",
        "audit_capsule_hash_matches",
        "file_manifest_root_matches",
        "declared_file_hashes_match",
        "declared_file_sizes_match",
        "required_roles_declared",
        "required_roles_bound",
        "required_role_files_declared",
        "verification_commands_match_expected",
        "transparency_log_verified",
        "audit_dashboard_verified",
        "audit_policy_verified",
        "runtime_manifest_verified",
        "audit_receipt_verified",
        "provenance_attestation_verified",
        "one_command_verifier_verified",
        "checksum_manifest_verified",
        "markdown_matches_capsule",
    ]


def audit_policy_required_artifacts() -> list[str]:
    return [
        AUDIT_CAPSULE_AUDIT_DASHBOARD,
        AUDIT_CAPSULE_AUDIT_POLICY,
        AUDIT_CAPSULE_RUNTIME_MANIFEST,
        AUDIT_CAPSULE_AUDIT_RECEIPT,
        AUDIT_CAPSULE_CHECKSUM_MANIFEST,
        AUDIT_CAPSULE_ONE_COMMAND_VERIFIER,
        AUDIT_CAPSULE_PROVENANCE_ATTESTATION,
        AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER,
        AUDIT_CAPSULE_STANDALONE_VERIFIER,
        AUDIT_CAPSULE_TRANSPARENCY_LOG,
        AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN,
    ]


def audit_policy_required_red_team_cases() -> dict[str, list[str]]:
    return {
        "audit_capsule": [
            "artifact_drift_forgery",
            "audit_dashboard_forgery",
            "audit_policy_forgery",
            "audit_receipt_forgery",
            "capsule_hash_forgery",
            "checksum_manifest_forgery",
            "command_forgery",
            "file_hash_forgery",
            "markdown_forgery",
            "one_command_verifier_forgery",
            "provenance_attestation_forgery",
            "role_omission_forgery",
            "runtime_manifest_forgery",
            "transparency_log_forgery",
        ],
        "audit_capsule_archive": [
            "archive_duplicate_entry",
            "archive_entry_drift",
            "archive_entry_omission",
            "archive_extra_entry",
            "archive_metadata_forgery",
        ],
    }


def build_audit_policy() -> dict[str, object]:
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_policy",
        "policy_version": 1,
        "subject_base": "capsule-relative",
        "required_roles": sorted(AUDIT_CAPSULE_REQUIRED_ROLES),
        "required_artifacts": audit_policy_required_artifacts(),
        "required_capsule_checks": audit_policy_required_capsule_checks(),
        "required_verification_commands": audit_capsule_verification_commands(),
        "minimum_counts": {
            "files": 8,
            "transparency_log_entries": 1,
            "audit_receipt_subjects": 1,
            "provenance_subjects": 1,
        },
        "required_red_team_cases": audit_policy_required_red_team_cases(),
    }
    return {**body, "audit_policy_sha256": canonical_object_sha256(body)}


def write_audit_policy(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    policy_path = output_dir / AUDIT_CAPSULE_AUDIT_POLICY
    policy = build_audit_policy()
    write_json(policy_path, policy)
    return {
        "path": str(policy_path),
        "sha256": hash_binary_file(policy_path),
        "bytes": policy_path.stat().st_size,
        "audit_policy_sha256": policy["audit_policy_sha256"],
    }


def verify_audit_policy(
    output_dir: str | Path,
    policy_path: str | Path | None = None,
    *,
    capsule: dict[str, object] | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    policy_path = (
        Path(policy_path).resolve()
        if policy_path is not None
        else output_dir / AUDIT_CAPSULE_AUDIT_POLICY
    )
    expected = build_audit_policy()
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if policy_path.exists():
            loaded = load_json(policy_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    actual_body = audit_policy_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    checks = {
        "audit_policy_present": policy_path.exists(),
        "audit_policy_json_valid": json_valid,
        "audit_policy_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_policy",
        "audit_policy_hash_matches": actual.get("audit_policy_sha256")
        == actual_hash,
        "audit_policy_matches_expected": bool(actual) and actual == expected,
    }
    if capsule is not None and actual:
        roles = dict(capsule.get("artifact_roles", {}))
        required_roles = set(str(role) for role in actual.get("required_roles", []))
        required_artifacts = set(
            str(path) for path in actual.get("required_artifacts", [])
        )
        minimum_counts = dict(actual.get("minimum_counts", {}))
        capsule_files = set(
            str(entry.get("path", ""))
            for entry in list(capsule.get("files", []))
            if isinstance(entry, dict)
        )
        checks.update(
            {
                "audit_policy_required_roles_declared_by_capsule": required_roles.issubset(
                    set(str(role) for role in capsule.get("required_roles", []))
                ),
                "audit_policy_required_roles_bound_by_capsule": required_roles.issubset(
                    set(roles)
                ),
                "audit_policy_required_artifacts_declared": required_artifacts.issubset(
                    capsule_files
                ),
                "audit_policy_verification_commands_match_capsule": capsule.get(
                    "verification_commands", []
                )
                == actual.get("required_verification_commands", []),
                "audit_policy_file_count_minimum_met": int(
                    capsule.get("file_count", -1)
                )
                >= int(minimum_counts.get("files", 0)),
                "audit_policy_transparency_entries_minimum_met": int(
                    capsule.get("transparency_log_entry_count", -1)
                )
                >= int(minimum_counts.get("transparency_log_entries", 0)),
                "audit_policy_receipt_subjects_minimum_met": int(
                    capsule.get("audit_receipt_subject_count", -1)
                )
                >= int(minimum_counts.get("audit_receipt_subjects", 0)),
                "audit_policy_provenance_subjects_minimum_met": int(
                    capsule.get("provenance_subject_count", -1)
                )
                >= int(minimum_counts.get("provenance_subjects", 0)),
            }
        )
    checks["audit_policy_verified"] = all(checks.values())
    return {
        "audit_policy_path": str(policy_path),
        "audit_policy_file_sha256": hash_binary_file(policy_path)
        if policy_path.exists()
        else "",
        "audit_policy_sha256": actual.get("audit_policy_sha256", ""),
        "expected_audit_policy_sha256": expected.get("audit_policy_sha256", ""),
        "checks": checks,
    }


def audit_receipt_hash_body(receipt: dict[str, object]) -> dict[str, object]:
    return {
        key: value for key, value in receipt.items() if key != "audit_receipt_sha256"
    }


def audit_receipt_subject_paths(output_dir: Path) -> list[Path]:
    return audit_capsule_candidate_paths(
        output_dir,
        include_transparency_log=False,
        include_checksum_manifest=False,
        include_provenance_attestation=False,
        include_audit_receipt=False,
    )


def audit_receipt_subjects(output_dir: Path) -> list[dict[str, object]]:
    output_dir = output_dir.resolve()
    subjects = [
        {
            "path": audit_capsule_relative_path(path, output_dir),
            "sha256": hash_binary_file(path),
            "bytes": path.stat().st_size,
        }
        for path in audit_receipt_subject_paths(output_dir)
    ]
    return sorted(subjects, key=lambda item: str(item["path"]))


def build_audit_receipt(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    subjects = audit_receipt_subjects(output_dir)
    artifact_hashes = {
        str(subject["path"]): str(subject["sha256"]) for subject in subjects
    }
    merkle_tree = build_artifact_merkle_tree(artifact_hashes)
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_receipt",
        "receipt_version": 1,
        "subject_base": "capsule-relative",
        "subject_count": len(subjects),
        "subjects": subjects,
        "subject_merkle_root_sha256": merkle_tree["root_sha256"],
        "artifact_merkle_tree": merkle_tree,
    }
    return {**body, "audit_receipt_sha256": canonical_object_sha256(body)}


def write_audit_receipt(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    receipt_path = output_dir / AUDIT_CAPSULE_AUDIT_RECEIPT
    receipt = build_audit_receipt(output_dir)
    write_json(receipt_path, receipt)
    return {
        "path": str(receipt_path),
        "sha256": hash_binary_file(receipt_path),
        "bytes": receipt_path.stat().st_size,
        "subject_count": receipt["subject_count"],
        "subject_merkle_root_sha256": receipt["subject_merkle_root_sha256"],
    }


def verify_audit_receipt(
    output_dir: str | Path,
    receipt_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    receipt_path = (
        Path(receipt_path).resolve()
        if receipt_path is not None
        else output_dir / AUDIT_CAPSULE_AUDIT_RECEIPT
    )
    expected = build_audit_receipt(output_dir)
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if receipt_path.exists():
            loaded = load_json(receipt_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    actual_body = audit_receipt_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    actual_tree = dict(actual.get("artifact_merkle_tree", {})) if actual else {}
    expected_tree = dict(expected.get("artifact_merkle_tree", {}))
    actual_subjects = list(actual.get("subjects", [])) if actual else []
    expected_subjects = list(expected.get("subjects", []))
    checks = {
        "audit_receipt_present": receipt_path.exists(),
        "audit_receipt_json_valid": json_valid,
        "audit_receipt_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_receipt",
        "audit_receipt_hash_matches": actual.get("audit_receipt_sha256")
        == actual_hash,
        "audit_receipt_subjects_match_files": actual_subjects == expected_subjects,
        "audit_receipt_merkle_tree_matches_subjects": actual_tree == expected_tree,
        "audit_receipt_merkle_proofs_verify": bool(actual_tree)
        and verify_artifact_merkle_proofs(actual_tree),
        "audit_receipt_root_matches_tree": actual.get("subject_merkle_root_sha256")
        == actual_tree.get("root_sha256"),
        "audit_receipt_matches_expected": bool(actual) and actual == expected,
    }
    checks["audit_receipt_verified"] = all(checks.values())
    return {
        "audit_receipt_path": str(receipt_path),
        "audit_receipt_file_sha256": hash_binary_file(receipt_path)
        if receipt_path.exists()
        else "",
        "audit_receipt_sha256": actual.get("audit_receipt_sha256", ""),
        "expected_audit_receipt_sha256": expected.get("audit_receipt_sha256", ""),
        "subject_merkle_root_sha256": actual.get(
            "subject_merkle_root_sha256", ""
        ),
        "expected_subject_merkle_root_sha256": expected.get(
            "subject_merkle_root_sha256", ""
        ),
        "subject_count": len(actual_subjects),
        "expected_subject_count": len(expected_subjects),
        "checks": checks,
    }


def audit_provenance_hash_body(attestation: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in attestation.items()
        if key != "provenance_sha256"
    }


def audit_provenance_subject_paths(output_dir: Path) -> list[Path]:
    return audit_capsule_candidate_paths(
        output_dir,
        include_transparency_log=False,
        include_checksum_manifest=False,
        include_provenance_attestation=False,
    )


def audit_provenance_source_materials() -> list[dict[str, object]]:
    paths = [
        REPO_ROOT / "pettachainer" / "benchmarks" / "verify_showcase.py",
        REPO_ROOT / "pettachainer" / "benchmarks" / "showcase.py",
    ]
    materials = []
    for path in paths:
        if not path.exists():
            continue
        materials.append(
            {
                "uri": f"local:{path}",
                "digest": {"sha256": hash_binary_file(path)},
                "bytes": path.stat().st_size,
            }
        )
    return materials


def build_audit_provenance_attestation(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    subjects = [
        {
            "name": audit_capsule_relative_path(path, output_dir),
            "digest": {"sha256": hash_binary_file(path)},
            "bytes": path.stat().st_size,
        }
        for path in audit_provenance_subject_paths(output_dir)
    ]
    subjects = sorted(subjects, key=lambda item: str(item["name"]))
    body: dict[str, object] = {
        "_type": "https://in-toto.io/Statement/v1",
        "artifact_kind": "pettachainer_showcase_provenance_attestation",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": subjects,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://pettachainer.local/audit-capsule/v1",
                "externalParameters": {
                    "artifact_dir": str(output_dir),
                    "verification_commands": audit_capsule_verification_commands(),
                },
                "internalParameters": {
                    "required_roles": sorted(AUDIT_CAPSULE_REQUIRED_ROLES),
                    "subject_count": len(subjects),
                },
                "resolvedDependencies": audit_provenance_source_materials(),
            },
            "runDetails": {
                "builder": {
                    "id": "https://pettachainer.local/benchmarks/verify_showcase.py"
                },
                "metadata": {
                    "deterministic": True,
                    "reproducible": True,
                },
            },
        },
    }
    return {**body, "provenance_sha256": canonical_object_sha256(body)}


def write_audit_provenance_attestation(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    attestation_path = output_dir / AUDIT_CAPSULE_PROVENANCE_ATTESTATION
    attestation = build_audit_provenance_attestation(output_dir)
    write_json(attestation_path, attestation)
    return {
        "path": str(attestation_path),
        "sha256": hash_binary_file(attestation_path),
        "bytes": attestation_path.stat().st_size,
        "subject_count": len(list(attestation.get("subject", []))),
        "provenance_sha256": attestation["provenance_sha256"],
    }


def verify_audit_provenance_attestation(
    output_dir: str | Path,
    attestation_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    attestation_path = (
        Path(attestation_path).resolve()
        if attestation_path is not None
        else output_dir / AUDIT_CAPSULE_PROVENANCE_ATTESTATION
    )
    expected = build_audit_provenance_attestation(output_dir)
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if attestation_path.exists():
            loaded = load_json(attestation_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    actual_body = audit_provenance_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    actual_subjects = list(actual.get("subject", [])) if actual else []
    expected_subjects = list(expected.get("subject", []))
    checks = {
        "provenance_attestation_present": attestation_path.exists(),
        "provenance_attestation_json_valid": json_valid,
        "provenance_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_provenance_attestation",
        "provenance_statement_type_matches": actual.get("_type")
        == "https://in-toto.io/Statement/v1",
        "provenance_predicate_type_matches": actual.get("predicateType")
        == "https://slsa.dev/provenance/v1",
        "provenance_hash_matches": actual.get("provenance_sha256")
        == actual_hash,
        "provenance_subjects_match_files": actual_subjects == expected_subjects,
        "provenance_matches_expected": bool(actual) and actual == expected,
    }
    checks["provenance_attestation_verified"] = all(checks.values())
    return {
        "provenance_attestation_path": str(attestation_path),
        "provenance_attestation_sha256": hash_binary_file(attestation_path)
        if attestation_path.exists()
        else "",
        "provenance_sha256": actual.get("provenance_sha256", ""),
        "expected_provenance_sha256": expected.get("provenance_sha256", ""),
        "subject_count": len(actual_subjects),
        "expected_subject_count": len(expected_subjects),
        "checks": checks,
    }


def audit_checksum_manifest_paths(output_dir: Path) -> list[Path]:
    return audit_capsule_candidate_paths(
        output_dir,
        include_transparency_log=False,
        include_checksum_manifest=False,
    )


def audit_checksum_manifest_text(output_dir: Path) -> str:
    output_dir = output_dir.resolve()
    lines = []
    for path in audit_checksum_manifest_paths(output_dir):
        relative_path = audit_capsule_relative_path(path, output_dir)
        lines.append(f"{hash_binary_file(path)}  {relative_path}\n")
    return "".join(lines)


def write_audit_checksum_manifest(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    manifest_path = output_dir / AUDIT_CAPSULE_CHECKSUM_MANIFEST
    manifest_path.write_text(audit_checksum_manifest_text(output_dir), encoding="utf-8")
    return {
        "path": str(manifest_path),
        "sha256": hash_file(manifest_path),
        "bytes": manifest_path.stat().st_size,
        "entry_count": len(audit_checksum_manifest_paths(output_dir)),
    }


def verify_audit_checksum_manifest(
    output_dir: str | Path,
    manifest_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    manifest_path = (
        Path(manifest_path).resolve()
        if manifest_path is not None
        else output_dir / AUDIT_CAPSULE_CHECKSUM_MANIFEST
    )
    expected_text = audit_checksum_manifest_text(output_dir)
    actual_text = (
        manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
    )
    checks = {
        "checksum_manifest_present": manifest_path.exists(),
        "checksum_manifest_matches_expected": bool(actual_text)
        and actual_text == expected_text,
    }
    checks["checksum_manifest_verified"] = all(checks.values())
    return {
        "checksum_manifest_path": str(manifest_path),
        "checksum_manifest_sha256": hash_file(manifest_path)
        if manifest_path.exists()
        else "",
        "entry_count": expected_text.count("\n"),
        "checks": checks,
    }


def audit_transparency_covered_paths_from_files(
    files: list[dict[str, object]],
) -> list[str]:
    excluded = {
        AUDIT_CAPSULE_TRANSPARENCY_LOG,
        AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN,
    }
    return sorted(
        str(file_entry.get("path", ""))
        for file_entry in files
        if str(file_entry.get("path", "")) and str(file_entry.get("path", "")) not in excluded
    )


def build_audit_transparency_log_entries(
    output_dir: Path,
    paths: list[Path],
) -> list[dict[str, object]]:
    output_dir = output_dir.resolve()
    previous_hash = "0" * 64
    entries: list[dict[str, object]] = []
    for index, path in enumerate(
        sorted(paths, key=lambda item: audit_capsule_relative_path(item, output_dir))
    ):
        body: dict[str, object] = {
            "index": index,
            "path": audit_capsule_relative_path(path, output_dir),
            "sha256": hash_file(path),
            "bytes": path.stat().st_size,
            "previous_hash": previous_hash,
        }
        entry_hash = canonical_object_sha256(body)
        entries.append({**body, "entry_hash": entry_hash})
        previous_hash = entry_hash
    return entries


def audit_transparency_log_root(entries: list[dict[str, object]]) -> str:
    if not entries:
        return canonical_object_sha256([])
    return str(entries[-1].get("entry_hash", ""))


def audit_transparency_log_markdown(entries: list[dict[str, object]]) -> str:
    root = audit_transparency_log_root(entries)
    lines = [
        "# PeTTaChainer Audit Transparency Log",
        "",
        f"- Transparency log root: `{root}`",
        f"- Entries: `{len(entries)}`",
        "",
        "| Index | Path | Bytes | SHA-256 | Entry hash |",
        "|---:|---|---:|---|---|",
    ]
    for entry in entries:
        lines.append(
            "| "
            f"{entry.get('index', 0)} | "
            f"`{markdown_cell(entry.get('path', ''))}` | "
            f"{entry.get('bytes', 0)} | "
            f"`{markdown_cell(entry.get('sha256', ''))}` | "
            f"`{markdown_cell(entry.get('entry_hash', ''))}` |"
        )
    return "\n".join(lines) + "\n"


def write_audit_transparency_log(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    entries = build_audit_transparency_log_entries(
        output_dir,
        audit_capsule_candidate_paths(output_dir, include_transparency_log=False),
    )
    log_path = output_dir / AUDIT_CAPSULE_TRANSPARENCY_LOG
    markdown_path = output_dir / AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN
    log_path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )
    markdown_path.write_text(audit_transparency_log_markdown(entries), encoding="utf-8")
    return {
        "path": str(log_path),
        "markdown_path": str(markdown_path),
        "entry_count": len(entries),
        "transparency_log_root_sha256": audit_transparency_log_root(entries),
    }


def load_audit_transparency_log(log_path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def verify_audit_transparency_log(
    output_dir: str | Path,
    log_path: str | Path | None = None,
    *,
    markdown_path: str | Path | None = None,
    expected_paths: list[str] | None = None,
    expected_root: str | None = None,
    expected_entry_count: int | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    log_path = (
        Path(log_path).resolve()
        if log_path is not None
        else output_dir / AUDIT_CAPSULE_TRANSPARENCY_LOG
    )
    markdown_path = (
        Path(markdown_path).resolve()
        if markdown_path is not None
        else output_dir / AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN
    )
    if expected_paths is None:
        expected_paths = [
            audit_capsule_relative_path(path, output_dir)
            for path in audit_capsule_candidate_paths(
                output_dir,
                include_transparency_log=False,
            )
        ]
    expected_paths = sorted(expected_paths)
    checks: dict[str, bool] = {
        "transparency_log_present": log_path.exists(),
    }
    entries: list[dict[str, object]] = []
    entry_chain_checks: dict[str, bool] = {}
    entry_file_hash_checks: dict[str, bool] = {}
    entry_file_size_checks: dict[str, bool] = {}
    try:
        if checks["transparency_log_present"]:
            entries = load_audit_transparency_log(log_path)
    except (json.JSONDecodeError, OSError):
        checks["transparency_log_jsonl_valid"] = False
    else:
        checks["transparency_log_jsonl_valid"] = True
    previous_hash = "0" * 64
    entry_paths: list[str] = []
    for expected_index, entry in enumerate(entries):
        relative_path = str(entry.get("path", ""))
        entry_paths.append(relative_path)
        body = {
            key: value for key, value in entry.items() if key != "entry_hash"
        }
        entry_chain_checks[relative_path or f"<entry-{expected_index}>"] = (
            int(entry.get("index", -1)) == expected_index
            and str(entry.get("previous_hash", "")) == previous_hash
            and str(entry.get("entry_hash", "")) == canonical_object_sha256(body)
        )
        previous_hash = str(entry.get("entry_hash", ""))
        path = output_dir / relative_path
        entry_file_hash_checks[relative_path] = (
            path.is_file() and hash_file(path) == str(entry.get("sha256", ""))
        )
        entry_file_size_checks[relative_path] = (
            path.is_file() and path.stat().st_size == int(entry.get("bytes", -1))
        )
    root = audit_transparency_log_root(entries)
    markdown_text = (
        markdown_path.read_text(encoding="utf-8") if markdown_path.exists() else ""
    )
    checks.update(
        {
            "transparency_log_has_entries": bool(entries),
            "transparency_log_paths_match_expected": sorted(entry_paths)
            == expected_paths,
            "transparency_log_entry_chain_valid": bool(entry_chain_checks)
            and all(entry_chain_checks.values()),
            "transparency_log_entry_hashes_match_files": bool(
                entry_file_hash_checks
            )
            and all(entry_file_hash_checks.values()),
            "transparency_log_entry_sizes_match_files": bool(
                entry_file_size_checks
            )
            and all(entry_file_size_checks.values()),
            "transparency_log_root_matches_expected": expected_root is None
            or root == expected_root,
            "transparency_log_entry_count_matches_expected": expected_entry_count
            is None
            or len(entries) == expected_entry_count,
            "transparency_log_markdown_matches": bool(markdown_text)
            and markdown_text == audit_transparency_log_markdown(entries),
        }
    )
    checks["transparency_log_verified"] = all(checks.values())
    return {
        "transparency_log_path": str(log_path),
        "transparency_log_markdown_path": str(markdown_path),
        "transparency_log_root_sha256": root,
        "entry_count": len(entries),
        "expected_entry_count": len(expected_paths),
        "missing_paths": sorted(set(expected_paths) - set(entry_paths)),
        "unexpected_paths": sorted(set(entry_paths) - set(expected_paths)),
        "failed_entry_chain": [
            path for path, passed in entry_chain_checks.items() if not bool(passed)
        ],
        "failed_entry_hashes": [
            path for path, passed in entry_file_hash_checks.items() if not bool(passed)
        ],
        "failed_entry_sizes": [
            path for path, passed in entry_file_size_checks.items() if not bool(passed)
        ],
        "checks": checks,
    }


def build_audit_capsule(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    files = [
        {
            "path": audit_capsule_relative_path(path, output_dir),
            "sha256": hash_file(path),
            "bytes": path.stat().st_size,
        }
        for path in audit_capsule_candidate_paths(output_dir)
    ]
    files = sorted(files, key=lambda item: str(item["path"]))
    roles = audit_capsule_roles(output_dir, files)
    transparency_details = verify_audit_transparency_log(
        output_dir,
        output_dir / str(roles.get("transparency_log", "")),
        expected_paths=audit_transparency_covered_paths_from_files(files),
    )
    provenance_details = verify_audit_provenance_attestation(
        output_dir,
        output_dir / str(roles.get("provenance_attestation", "")),
    )
    receipt_details = verify_audit_receipt(
        output_dir,
        output_dir / str(roles.get("audit_receipt", "")),
    )
    policy_details = verify_audit_policy(
        output_dir,
        output_dir / str(roles.get("audit_policy", "")),
    )
    runtime_details = verify_runtime_manifest(
        output_dir,
        output_dir / str(roles.get("runtime_manifest", "")),
    )
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_capsule",
        "capsule_version": 1,
        "artifact_dir": str(output_dir),
        "file_count": len(files),
        "files": files,
        "file_manifest_root_sha256": canonical_object_sha256(files),
        "artifact_roles": roles,
        "required_roles": sorted(AUDIT_CAPSULE_REQUIRED_ROLES),
        "verification_commands": audit_capsule_verification_commands(),
        "transparency_log_root_sha256": transparency_details.get(
            "transparency_log_root_sha256", ""
        ),
        "transparency_log_entry_count": transparency_details.get("entry_count", 0),
        "provenance_attestation_sha256": provenance_details.get(
            "provenance_sha256", ""
        ),
        "provenance_subject_count": provenance_details.get("subject_count", 0),
        "audit_receipt_sha256": receipt_details.get("audit_receipt_sha256", ""),
        "audit_receipt_subject_merkle_root_sha256": receipt_details.get(
            "subject_merkle_root_sha256", ""
        ),
        "audit_receipt_subject_count": receipt_details.get("subject_count", 0),
        "audit_policy_sha256": policy_details.get("audit_policy_sha256", ""),
        "runtime_manifest_sha256": runtime_details.get(
            "runtime_manifest_sha256", ""
        ),
    }
    return {**body, "audit_capsule_sha256": canonical_object_sha256(body)}


def audit_capsule_markdown(capsule: dict[str, object]) -> str:
    roles = dict(capsule.get("artifact_roles", {}))
    lines = [
        "# PeTTaChainer Audit Capsule",
        "",
        f"- Audit capsule SHA-256: `{capsule.get('audit_capsule_sha256', '')}`",
        f"- File manifest root: `{capsule.get('file_manifest_root_sha256', '')}`",
        f"- Transparency log root: `{capsule.get('transparency_log_root_sha256', '')}`",
        f"- Provenance attestation SHA-256: `{capsule.get('provenance_attestation_sha256', '')}`",
        f"- Audit policy SHA-256: `{capsule.get('audit_policy_sha256', '')}`",
        f"- Runtime manifest SHA-256: `{capsule.get('runtime_manifest_sha256', '')}`",
        f"- Audit receipt SHA-256: `{capsule.get('audit_receipt_sha256', '')}`",
        f"- Audit receipt Merkle root: `{capsule.get('audit_receipt_subject_merkle_root_sha256', '')}`",
        f"- Files: `{capsule.get('file_count', 0)}`",
        f"- Transparency log entries: `{capsule.get('transparency_log_entry_count', 0)}`",
        f"- Provenance subjects: `{capsule.get('provenance_subject_count', 0)}`",
        f"- Receipt subjects: `{capsule.get('audit_receipt_subject_count', 0)}`",
        "",
        "## Required Roles",
        "",
        "| Role | Path |",
        "|---|---|",
    ]
    for role in sorted(capsule.get("required_roles", [])):
        lines.append(f"| {markdown_cell(role)} | `{markdown_cell(roles.get(role, ''))}` |")
    lines.extend(
        [
            "",
            "## Verification Commands",
            "",
        ]
    )
    for command in list(capsule.get("verification_commands", [])):
        lines.append(f"```bash\n{command}\n```")
    lines.extend(
        [
            "",
            "## Files",
            "",
            "| Path | Bytes | SHA-256 |",
            "|---|---:|---|",
        ]
    )
    for file_entry in list(capsule.get("files", [])):
        lines.append(
            "| "
            f"`{markdown_cell(file_entry.get('path', ''))}` | "
            f"{file_entry.get('bytes', 0)} | "
            f"`{markdown_cell(file_entry.get('sha256', ''))}` |"
        )
    return "\n".join(lines) + "\n"


def audit_capsule_standalone_verifier_text() -> str:
    return '''#!/usr/bin/env python3
"""Standalone verifier for a PeTTaChainer audit capsule directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED_ROLES = {
    "audit_receipt",
    "audit_policy",
    "audit_dashboard",
    "audit_proof_graph",
    "audit_proof_graph_dot",
    "audit_verdict",
    "claim_certificate",
    "checksum_manifest",
    "forensic_packet",
    "one_command_verifier",
    "provenance_attestation",
    "runtime_manifest",
    "standalone_archive_verifier",
    "standalone_verifier",
    "transparency_log",
}

TRANSPARENCY_LOG = "showcase-transparency-log.jsonl"
TRANSPARENCY_LOG_MARKDOWN = "showcase-transparency-log.md"
CHECKSUM_MANIFEST = "showcase-checksums.sha256"
PROVENANCE_ATTESTATION = "showcase-provenance.intoto.json"
AUDIT_RECEIPT = "showcase-audit-receipt.json"
AUDIT_POLICY = "showcase-audit-policy.json"
AUDIT_CAPSULE_RED_TEAM_RESULT = "showcase-audit-capsule-red-team-result.json"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("jsonl entry is not an object")
        entries.append(payload)
    return entries


def capsule_body(capsule: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in capsule.items()
        if key not in {"audit_capsule_sha256", "result_path", "markdown_path"}
    }


def receipt_body(receipt: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in receipt.items() if key != "audit_receipt_sha256"}


def policy_body(policy: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in policy.items() if key != "audit_policy_sha256"}


def merkle_leaf_hash(path: str, artifact_sha256: str) -> str:
    return canonical_sha256({"kind": "artifact_leaf", "path": path, "sha256": artifact_sha256})


def merkle_parent_hash(left_sha256: str, right_sha256: str) -> str:
    return canonical_sha256({"kind": "artifact_node", "left": left_sha256, "right": right_sha256})


def build_merkle_tree(artifact_hashes: dict[str, str]) -> dict[str, object]:
    leaves = [
        {
            "path": path,
            "artifact_sha256": artifact_sha256,
            "leaf_sha256": merkle_leaf_hash(path, artifact_sha256),
        }
        for path, artifact_sha256 in sorted(artifact_hashes.items())
    ]
    if not leaves:
        return {
            "tree_version": 1,
            "artifact_kind": "pettachainer_artifact_merkle_tree",
            "leaf_count": 0,
            "root_sha256": canonical_sha256([]),
            "leaves": [],
            "proofs": {},
        }
    levels: list[list[str]] = [[str(leaf["leaf_sha256"]) for leaf in leaves]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[str] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(merkle_parent_hash(left, right))
        levels.append(next_level)
    proofs: dict[str, list[dict[str, str]]] = {}
    for leaf_index, leaf in enumerate(leaves):
        index = leaf_index
        proof: list[dict[str, str]] = []
        for level in levels[:-1]:
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            sibling_sha = level[sibling_index] if sibling_index < len(level) else level[index]
            proof.append({"side": "right" if index % 2 == 0 else "left", "sha256": sibling_sha})
            index //= 2
        proofs[str(leaf["path"])] = proof
    return {
        "tree_version": 1,
        "artifact_kind": "pettachainer_artifact_merkle_tree",
        "leaf_count": len(leaves),
        "root_sha256": levels[-1][0],
        "leaves": leaves,
        "proofs": proofs,
    }


def verify_merkle_proofs(tree: dict[str, object]) -> bool:
    root = str(tree.get("root_sha256", ""))
    leaves = list(tree.get("leaves", []))
    proofs = dict(tree.get("proofs", {}))
    if not root or not leaves:
        return False
    for leaf in leaves:
        if not isinstance(leaf, dict):
            return False
        path = str(leaf.get("path", ""))
        current = merkle_leaf_hash(path, str(leaf.get("artifact_sha256", "")))
        if current != leaf.get("leaf_sha256"):
            return False
        for step in list(proofs.get(path, [])):
            sibling = str(step.get("sha256", ""))
            if step.get("side") == "left":
                current = merkle_parent_hash(sibling, current)
            elif step.get("side") == "right":
                current = merkle_parent_hash(current, sibling)
            else:
                return False
        if current != root:
            return False
    return True


def receipt_subjects(directory: Path, files: list[object]) -> list[dict[str, object]]:
    excluded = {
        TRANSPARENCY_LOG,
        TRANSPARENCY_LOG_MARKDOWN,
        CHECKSUM_MANIFEST,
        PROVENANCE_ATTESTATION,
        AUDIT_RECEIPT,
    }
    subjects: list[dict[str, object]] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        relative_path = str(entry.get("path", ""))
        if not relative_path or relative_path in excluded:
            continue
        path = directory / relative_path
        if path.is_file():
            subjects.append(
                {
                    "path": relative_path,
                    "sha256": file_sha256(path),
                    "bytes": path.stat().st_size,
                }
            )
    return sorted(subjects, key=lambda item: str(item["path"]))


def expected_receipt(directory: Path, files: list[object]) -> dict[str, object]:
    subjects = receipt_subjects(directory, files)
    tree = build_merkle_tree({str(item["path"]): str(item["sha256"]) for item in subjects})
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_receipt",
        "receipt_version": 1,
        "subject_base": "capsule-relative",
        "subject_count": len(subjects),
        "subjects": subjects,
        "subject_merkle_root_sha256": tree["root_sha256"],
        "artifact_merkle_tree": tree,
    }
    return {**body, "audit_receipt_sha256": canonical_sha256(body)}


def verify_audit_receipt(
    directory: Path,
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    receipt_path = directory / str(roles.get("audit_receipt", ""))
    if not receipt_path.is_file():
        return ["audit_receipt_missing"]
    try:
        receipt_obj = load_json(receipt_path)
    except (OSError, json.JSONDecodeError):
        return ["audit_receipt_json"]
    if not isinstance(receipt_obj, dict):
        return ["audit_receipt_not_object"]
    receipt = receipt_obj
    expected = expected_receipt(directory, files)
    tree = receipt.get("artifact_merkle_tree", {})
    if not isinstance(tree, dict):
        failures.append("audit_receipt_tree_shape")
        tree = {}
    if receipt.get("artifact_kind") != "pettachainer_showcase_audit_receipt":
        failures.append("audit_receipt_kind")
    if receipt.get("audit_receipt_sha256") != canonical_sha256(receipt_body(receipt)):
        failures.append("audit_receipt_hash")
    if receipt.get("subjects") != expected.get("subjects"):
        failures.append("audit_receipt_subjects")
    if tree != expected.get("artifact_merkle_tree"):
        failures.append("audit_receipt_tree")
    if not verify_merkle_proofs(tree):
        failures.append("audit_receipt_proofs")
    if receipt.get("subject_merkle_root_sha256") != tree.get("root_sha256"):
        failures.append("audit_receipt_root")
    if receipt != expected:
        failures.append("audit_receipt_expected")
    if capsule.get("audit_receipt_sha256") != receipt.get("audit_receipt_sha256"):
        failures.append("audit_receipt_capsule_hash")
    if capsule.get("audit_receipt_subject_merkle_root_sha256") != receipt.get("subject_merkle_root_sha256"):
        failures.append("audit_receipt_capsule_root")
    if int(capsule.get("audit_receipt_subject_count", -1)) != int(receipt.get("subject_count", -2)):
        failures.append("audit_receipt_capsule_count")
    return failures


def verify_audit_policy(
    directory: Path,
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
    declared_roles: set[str],
) -> list[str]:
    failures: list[str] = []
    policy_path = directory / str(roles.get("audit_policy", ""))
    if not policy_path.is_file():
        return ["audit_policy_missing"]
    try:
        policy_obj = load_json(policy_path)
    except (OSError, json.JSONDecodeError):
        return ["audit_policy_json"]
    if not isinstance(policy_obj, dict):
        return ["audit_policy_not_object"]
    policy = policy_obj
    declared_paths = {
        str(entry.get("path", ""))
        for entry in files
        if isinstance(entry, dict)
    }
    required_roles = set(str(role) for role in policy.get("required_roles", []))
    required_artifacts = set(str(path) for path in policy.get("required_artifacts", []))
    minimum_counts = dict(policy.get("minimum_counts", {}))
    if policy.get("artifact_kind") != "pettachainer_showcase_audit_policy":
        failures.append("audit_policy_kind")
    if policy.get("audit_policy_sha256") != canonical_sha256(policy_body(policy)):
        failures.append("audit_policy_hash")
    if capsule.get("audit_policy_sha256") != policy.get("audit_policy_sha256"):
        failures.append("audit_policy_capsule_hash")
    if set(REQUIRED_ROLES) != required_roles:
        failures.append("audit_policy_required_roles")
    if not required_roles.issubset(declared_roles):
        failures.append("audit_policy_roles_declared")
    if not required_roles.issubset(set(roles)):
        failures.append("audit_policy_roles_bound")
    if not required_artifacts.issubset(declared_paths):
        failures.append("audit_policy_artifacts")
    if capsule.get("verification_commands", []) != policy.get("required_verification_commands", []):
        failures.append("audit_policy_commands")
    if int(capsule.get("file_count", -1)) < int(minimum_counts.get("files", 0)):
        failures.append("audit_policy_file_count")
    if int(capsule.get("transparency_log_entry_count", -1)) < int(minimum_counts.get("transparency_log_entries", 0)):
        failures.append("audit_policy_transparency_count")
    if int(capsule.get("audit_receipt_subject_count", -1)) < int(minimum_counts.get("audit_receipt_subjects", 0)):
        failures.append("audit_policy_receipt_count")
    if int(capsule.get("provenance_subject_count", -1)) < int(minimum_counts.get("provenance_subjects", 0)):
        failures.append("audit_policy_provenance_count")
    if AUDIT_CAPSULE_RED_TEAM_RESULT in declared_paths:
        try:
            red_team = load_json(directory / AUDIT_CAPSULE_RED_TEAM_RESULT)
        except (OSError, json.JSONDecodeError):
            failures.append("audit_policy_red_team_json")
        else:
            cases = dict(red_team.get("cases", {})) if isinstance(red_team, dict) else {}
            required_cases = list(
                dict(policy.get("required_red_team_cases", {})).get("audit_capsule", [])
            )
            if not all(case in cases for case in required_cases):
                failures.append("audit_policy_red_team_cases")
            if not all(bool(dict(cases.get(case, {})).get("rejected")) for case in required_cases):
                failures.append("audit_policy_red_team_rejections")
            if int(red_team.get("case_count", -1)) < len(required_cases):
                failures.append("audit_policy_red_team_count")
            if not bool(red_team.get("audit_capsule_red_team_pass")):
                failures.append("audit_policy_red_team_pass")
    return failures


def transparency_root(entries: list[dict[str, object]]) -> str:
    if not entries:
        return canonical_sha256([])
    return str(entries[-1].get("entry_hash", ""))


def verify_transparency_log(
    directory: Path,
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    log_path = directory / str(roles.get("transparency_log", ""))
    if not log_path.is_file():
        return ["transparency_log_missing"]
    try:
        entries = load_jsonl(log_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return ["transparency_log_jsonl"]
    expected_paths = sorted(
        str(entry.get("path", ""))
        for entry in files
        if isinstance(entry, dict)
        and str(entry.get("path", ""))
        not in {TRANSPARENCY_LOG, TRANSPARENCY_LOG_MARKDOWN}
    )
    entry_paths: list[str] = []
    previous_hash = "0" * 64
    for expected_index, entry in enumerate(entries):
        relative_path = str(entry.get("path", ""))
        entry_paths.append(relative_path)
        body = {key: value for key, value in entry.items() if key != "entry_hash"}
        if int(entry.get("index", -1)) != expected_index:
            failures.append(f"transparency_index:{relative_path}")
        if str(entry.get("previous_hash", "")) != previous_hash:
            failures.append(f"transparency_previous:{relative_path}")
        if str(entry.get("entry_hash", "")) != canonical_sha256(body):
            failures.append(f"transparency_entry_hash:{relative_path}")
        previous_hash = str(entry.get("entry_hash", ""))
        path = directory / relative_path
        if not path.is_file():
            failures.append(f"transparency_missing:{relative_path}")
            continue
        if file_sha256(path) != str(entry.get("sha256", "")):
            failures.append(f"transparency_hash:{relative_path}")
        if path.stat().st_size != int(entry.get("bytes", -1)):
            failures.append(f"transparency_bytes:{relative_path}")
    if sorted(entry_paths) != expected_paths:
        failures.append("transparency_paths")
    if transparency_root(entries) != str(capsule.get("transparency_log_root_sha256", "")):
        failures.append("transparency_root")
    if len(entries) != int(capsule.get("transparency_log_entry_count", -1)):
        failures.append("transparency_entry_count")
    return failures


def verify(directory: Path, capsule_path: Path) -> tuple[bool, list[str]]:
    failures: list[str] = []
    capsule_obj = load_json(capsule_path)
    if not isinstance(capsule_obj, dict):
        return False, ["capsule_not_json_object"]
    capsule = capsule_obj
    files = list(capsule.get("files", []))
    roles = dict(capsule.get("artifact_roles", {}))
    declared_roles = set(str(role) for role in capsule.get("required_roles", []))
    if capsule.get("artifact_kind") != "pettachainer_showcase_audit_capsule":
        failures.append("kind")
    if capsule.get("audit_capsule_sha256") != canonical_sha256(capsule_body(capsule)):
        failures.append("capsule_hash")
    if capsule.get("file_manifest_root_sha256") != canonical_sha256(files):
        failures.append("file_manifest_root")
    if int(capsule.get("file_count", -1)) != len(files):
        failures.append("file_count")
    if not REQUIRED_ROLES.issubset(declared_roles):
        failures.append("required_roles_declared")
    if not REQUIRED_ROLES.issubset(set(roles)):
        failures.append("required_roles_bound")
    declared_paths = {str(entry.get("path", "")) for entry in files}
    for role in REQUIRED_ROLES:
        if roles.get(role, "") not in declared_paths:
            failures.append(f"role_file:{role}")
    failures.extend(verify_audit_policy(directory, capsule, files, roles, declared_roles))
    failures.extend(verify_audit_receipt(directory, capsule, files, roles))
    failures.extend(verify_transparency_log(directory, capsule, files, roles))
    for entry in files:
        relative_path = str(entry.get("path", ""))
        path = directory / relative_path
        if not path.is_file():
            failures.append(f"missing:{relative_path}")
            continue
        if file_sha256(path) != str(entry.get("sha256", "")):
            failures.append(f"hash:{relative_path}")
        if path.stat().st_size != int(entry.get("bytes", -1)):
            failures.append(f"bytes:{relative_path}")
    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("."))
    parser.add_argument(
        "--capsule",
        type=Path,
        default=None,
        help="Capsule JSON path; defaults to <directory>/showcase-audit-capsule.json",
    )
    args = parser.parse_args()
    directory = args.directory.resolve()
    capsule_path = (
        args.capsule.resolve()
        if args.capsule is not None
        else directory / "showcase-audit-capsule.json"
    )
    ok, failures = verify(directory, capsule_path)
    if ok:
        print("PASS audit capsule standalone verification")
        return 0
    print("FAIL audit capsule standalone verification", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def audit_capsule_standalone_archive_verifier_text() -> str:
    return '''#!/usr/bin/env python3
"""Standalone verifier for a PeTTaChainer audit capsule ZIP archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import PurePosixPath


REQUIRED_ROLES = {
    "audit_receipt",
    "audit_policy",
    "audit_dashboard",
    "audit_proof_graph",
    "audit_proof_graph_dot",
    "audit_verdict",
    "claim_certificate",
    "checksum_manifest",
    "forensic_packet",
    "one_command_verifier",
    "provenance_attestation",
    "runtime_manifest",
    "standalone_archive_verifier",
    "standalone_verifier",
    "transparency_log",
}

ZIP_FIXED_DATE = (1980, 1, 1, 0, 0, 0)
ZIP_FIXED_EXTERNAL_ATTR = 0o100644 << 16
TRANSPARENCY_LOG = "showcase-transparency-log.jsonl"
TRANSPARENCY_LOG_MARKDOWN = "showcase-transparency-log.md"
CHECKSUM_MANIFEST = "showcase-checksums.sha256"
PROVENANCE_ATTESTATION = "showcase-provenance.intoto.json"
AUDIT_RECEIPT = "showcase-audit-receipt.json"
AUDIT_POLICY = "showcase-audit-policy.json"
AUDIT_CAPSULE_RED_TEAM_RESULT = "showcase-audit-capsule-red-team-result.json"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def text_payload_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload.decode("utf-8").encode("utf-8")).hexdigest()


def capsule_body(capsule: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in capsule.items()
        if key not in {"audit_capsule_sha256", "result_path", "markdown_path"}
    }


def receipt_body(receipt: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in receipt.items() if key != "audit_receipt_sha256"}


def policy_body(policy: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in policy.items() if key != "audit_policy_sha256"}


def merkle_leaf_hash(path: str, artifact_sha256: str) -> str:
    return canonical_sha256({"kind": "artifact_leaf", "path": path, "sha256": artifact_sha256})


def merkle_parent_hash(left_sha256: str, right_sha256: str) -> str:
    return canonical_sha256({"kind": "artifact_node", "left": left_sha256, "right": right_sha256})


def build_merkle_tree(artifact_hashes: dict[str, str]) -> dict[str, object]:
    leaves = [
        {
            "path": path,
            "artifact_sha256": artifact_sha256,
            "leaf_sha256": merkle_leaf_hash(path, artifact_sha256),
        }
        for path, artifact_sha256 in sorted(artifact_hashes.items())
    ]
    if not leaves:
        return {
            "tree_version": 1,
            "artifact_kind": "pettachainer_artifact_merkle_tree",
            "leaf_count": 0,
            "root_sha256": canonical_sha256([]),
            "leaves": [],
            "proofs": {},
        }
    levels: list[list[str]] = [[str(leaf["leaf_sha256"]) for leaf in leaves]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[str] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(merkle_parent_hash(left, right))
        levels.append(next_level)
    proofs: dict[str, list[dict[str, str]]] = {}
    for leaf_index, leaf in enumerate(leaves):
        index = leaf_index
        proof: list[dict[str, str]] = []
        for level in levels[:-1]:
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            sibling_sha = level[sibling_index] if sibling_index < len(level) else level[index]
            proof.append({"side": "right" if index % 2 == 0 else "left", "sha256": sibling_sha})
            index //= 2
        proofs[str(leaf["path"])] = proof
    return {
        "tree_version": 1,
        "artifact_kind": "pettachainer_artifact_merkle_tree",
        "leaf_count": len(leaves),
        "root_sha256": levels[-1][0],
        "leaves": leaves,
        "proofs": proofs,
    }


def verify_merkle_proofs(tree: dict[str, object]) -> bool:
    root = str(tree.get("root_sha256", ""))
    leaves = list(tree.get("leaves", []))
    proofs = dict(tree.get("proofs", {}))
    if not root or not leaves:
        return False
    for leaf in leaves:
        if not isinstance(leaf, dict):
            return False
        path = str(leaf.get("path", ""))
        current = merkle_leaf_hash(path, str(leaf.get("artifact_sha256", "")))
        if current != leaf.get("leaf_sha256"):
            return False
        for step in list(proofs.get(path, [])):
            sibling = str(step.get("sha256", ""))
            if step.get("side") == "left":
                current = merkle_parent_hash(sibling, current)
            elif step.get("side") == "right":
                current = merkle_parent_hash(current, sibling)
            else:
                return False
        if current != root:
            return False
    return True


def load_jsonl_bytes(payload: bytes) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in payload.decode("utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if not isinstance(entry, dict):
            raise ValueError("jsonl entry is not an object")
        entries.append(entry)
    return entries


def transparency_root(entries: list[dict[str, object]]) -> str:
    if not entries:
        return canonical_sha256([])
    return str(entries[-1].get("entry_hash", ""))


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\\\|")


def capsule_markdown(capsule: dict[str, object]) -> str:
    roles_obj = capsule.get("artifact_roles", {})
    roles = roles_obj if isinstance(roles_obj, dict) else {}
    lines = [
        "# PeTTaChainer Audit Capsule",
        "",
        f"- Audit capsule SHA-256: `{capsule.get('audit_capsule_sha256', '')}`",
        f"- File manifest root: `{capsule.get('file_manifest_root_sha256', '')}`",
        f"- Transparency log root: `{capsule.get('transparency_log_root_sha256', '')}`",
        f"- Provenance attestation SHA-256: `{capsule.get('provenance_attestation_sha256', '')}`",
        f"- Audit policy SHA-256: `{capsule.get('audit_policy_sha256', '')}`",
        f"- Runtime manifest SHA-256: `{capsule.get('runtime_manifest_sha256', '')}`",
        f"- Audit receipt SHA-256: `{capsule.get('audit_receipt_sha256', '')}`",
        f"- Audit receipt Merkle root: `{capsule.get('audit_receipt_subject_merkle_root_sha256', '')}`",
        f"- Files: `{capsule.get('file_count', 0)}`",
        f"- Transparency log entries: `{capsule.get('transparency_log_entry_count', 0)}`",
        f"- Provenance subjects: `{capsule.get('provenance_subject_count', 0)}`",
        f"- Receipt subjects: `{capsule.get('audit_receipt_subject_count', 0)}`",
        "",
        "## Required Roles",
        "",
        "| Role | Path |",
        "|---|---|",
    ]
    for role in sorted(capsule.get("required_roles", [])):
        lines.append(f"| {markdown_cell(role)} | `{markdown_cell(roles.get(role, ''))}` |")
    lines.extend(["", "## Verification Commands", ""])
    for command in list(capsule.get("verification_commands", [])):
        lines.append(f"```bash\\n{command}\\n```")
    lines.extend(
        [
            "",
            "## Files",
            "",
            "| Path | Bytes | SHA-256 |",
            "|---|---:|---|",
        ]
    )
    for file_entry in list(capsule.get("files", [])):
        if not isinstance(file_entry, dict):
            continue
        lines.append(
            "| "
            f"`{markdown_cell(file_entry.get('path', ''))}` | "
            f"{file_entry.get('bytes', 0)} | "
            f"`{markdown_cell(file_entry.get('sha256', ''))}` |"
        )
    return "\\n".join(lines) + "\\n"


def path_is_safe(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return bool(name) and not name.startswith("/") and ".." not in parts


def receipt_subjects(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    files: list[object],
) -> list[dict[str, object]]:
    excluded = {
        TRANSPARENCY_LOG,
        TRANSPARENCY_LOG_MARKDOWN,
        CHECKSUM_MANIFEST,
        PROVENANCE_ATTESTATION,
        AUDIT_RECEIPT,
    }
    subjects: list[dict[str, object]] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        relative_path = str(entry.get("path", ""))
        if not relative_path or relative_path in excluded or relative_path not in by_name:
            continue
        payload = archive.read(by_name[relative_path])
        subjects.append(
            {
                "path": relative_path,
                "sha256": text_payload_sha256(payload),
                "bytes": len(payload),
            }
        )
    return sorted(subjects, key=lambda item: str(item["path"]))


def expected_receipt(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    capsule: dict[str, object],
    files: list[object],
) -> dict[str, object]:
    subjects = receipt_subjects(archive, by_name, files)
    tree = build_merkle_tree({str(item["path"]): str(item["sha256"]) for item in subjects})
    body: dict[str, object] = {
        "artifact_kind": "pettachainer_showcase_audit_receipt",
        "receipt_version": 1,
        "subject_base": "capsule-relative",
        "subject_count": len(subjects),
        "subjects": subjects,
        "subject_merkle_root_sha256": tree["root_sha256"],
        "artifact_merkle_tree": tree,
    }
    return {**body, "audit_receipt_sha256": canonical_sha256(body)}


def verify_audit_receipt(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    receipt_name = str(roles.get("audit_receipt", ""))
    if receipt_name not in by_name:
        return ["audit_receipt_missing"]
    try:
        receipt_obj = json.loads(archive.read(by_name[receipt_name]).decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return ["audit_receipt_json"]
    if not isinstance(receipt_obj, dict):
        return ["audit_receipt_not_object"]
    receipt = receipt_obj
    expected = expected_receipt(archive, by_name, capsule, files)
    tree = receipt.get("artifact_merkle_tree", {})
    if not isinstance(tree, dict):
        failures.append("audit_receipt_tree_shape")
        tree = {}
    if receipt.get("artifact_kind") != "pettachainer_showcase_audit_receipt":
        failures.append("audit_receipt_kind")
    if receipt.get("audit_receipt_sha256") != canonical_sha256(receipt_body(receipt)):
        failures.append("audit_receipt_hash")
    if receipt.get("subjects") != expected.get("subjects"):
        failures.append("audit_receipt_subjects")
    if tree != expected.get("artifact_merkle_tree"):
        failures.append("audit_receipt_tree")
    if not verify_merkle_proofs(tree):
        failures.append("audit_receipt_proofs")
    if receipt.get("subject_merkle_root_sha256") != tree.get("root_sha256"):
        failures.append("audit_receipt_root")
    if receipt != expected:
        failures.append("audit_receipt_expected")
    if capsule.get("audit_receipt_sha256") != receipt.get("audit_receipt_sha256"):
        failures.append("audit_receipt_capsule_hash")
    if capsule.get("audit_receipt_subject_merkle_root_sha256") != receipt.get("subject_merkle_root_sha256"):
        failures.append("audit_receipt_capsule_root")
    if int(capsule.get("audit_receipt_subject_count", -1)) != int(receipt.get("subject_count", -2)):
        failures.append("audit_receipt_capsule_count")
    return failures


def load_json_entry(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    name: str,
) -> object:
    return json.loads(archive.read(by_name[name]).decode("utf-8"))


def verify_audit_policy(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
    declared_roles: set[str],
) -> list[str]:
    failures: list[str] = []
    policy_name = str(roles.get("audit_policy", ""))
    if policy_name not in by_name:
        return ["audit_policy_missing"]
    try:
        policy_obj = load_json_entry(archive, by_name, policy_name)
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
        return ["audit_policy_json"]
    if not isinstance(policy_obj, dict):
        return ["audit_policy_not_object"]
    policy = policy_obj
    declared_paths = {
        str(entry.get("path", ""))
        for entry in files
        if isinstance(entry, dict)
    }
    required_roles = set(str(role) for role in policy.get("required_roles", []))
    required_artifacts = set(str(path) for path in policy.get("required_artifacts", []))
    minimum_counts = dict(policy.get("minimum_counts", {}))
    if policy.get("artifact_kind") != "pettachainer_showcase_audit_policy":
        failures.append("audit_policy_kind")
    if policy.get("audit_policy_sha256") != canonical_sha256(policy_body(policy)):
        failures.append("audit_policy_hash")
    if capsule.get("audit_policy_sha256") != policy.get("audit_policy_sha256"):
        failures.append("audit_policy_capsule_hash")
    if set(REQUIRED_ROLES) != required_roles:
        failures.append("audit_policy_required_roles")
    if not required_roles.issubset(declared_roles):
        failures.append("audit_policy_roles_declared")
    if not required_roles.issubset(set(roles)):
        failures.append("audit_policy_roles_bound")
    if not required_artifacts.issubset(declared_paths):
        failures.append("audit_policy_artifacts")
    if capsule.get("verification_commands", []) != policy.get("required_verification_commands", []):
        failures.append("audit_policy_commands")
    if int(capsule.get("file_count", -1)) < int(minimum_counts.get("files", 0)):
        failures.append("audit_policy_file_count")
    if int(capsule.get("transparency_log_entry_count", -1)) < int(minimum_counts.get("transparency_log_entries", 0)):
        failures.append("audit_policy_transparency_count")
    if int(capsule.get("audit_receipt_subject_count", -1)) < int(minimum_counts.get("audit_receipt_subjects", 0)):
        failures.append("audit_policy_receipt_count")
    if int(capsule.get("provenance_subject_count", -1)) < int(minimum_counts.get("provenance_subjects", 0)):
        failures.append("audit_policy_provenance_count")
    if AUDIT_CAPSULE_RED_TEAM_RESULT in declared_paths and AUDIT_CAPSULE_RED_TEAM_RESULT in by_name:
        try:
            red_team_obj = load_json_entry(archive, by_name, AUDIT_CAPSULE_RED_TEAM_RESULT)
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
            failures.append("audit_policy_red_team_json")
        else:
            red_team = red_team_obj if isinstance(red_team_obj, dict) else {}
            cases = dict(red_team.get("cases", {}))
            required_cases = list(
                dict(policy.get("required_red_team_cases", {})).get("audit_capsule", [])
            )
            if not all(case in cases for case in required_cases):
                failures.append("audit_policy_red_team_cases")
            if not all(bool(dict(cases.get(case, {})).get("rejected")) for case in required_cases):
                failures.append("audit_policy_red_team_rejections")
            if int(red_team.get("case_count", -1)) < len(required_cases):
                failures.append("audit_policy_red_team_count")
            if not bool(red_team.get("audit_capsule_red_team_pass")):
                failures.append("audit_policy_red_team_pass")
    return failures


def verify_transparency_log(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    capsule: dict[str, object],
    files: list[object],
    roles: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    log_name = str(roles.get("transparency_log", ""))
    if log_name not in by_name:
        return ["transparency_log_missing"]
    try:
        entries = load_jsonl_bytes(archive.read(by_name[log_name]))
    except (KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return ["transparency_log_jsonl"]
    expected_paths = sorted(
        str(entry.get("path", ""))
        for entry in files
        if isinstance(entry, dict)
        and str(entry.get("path", ""))
        not in {TRANSPARENCY_LOG, TRANSPARENCY_LOG_MARKDOWN}
    )
    entry_paths: list[str] = []
    previous_hash = "0" * 64
    for expected_index, entry in enumerate(entries):
        relative_path = str(entry.get("path", ""))
        entry_paths.append(relative_path)
        body = {key: value for key, value in entry.items() if key != "entry_hash"}
        if int(entry.get("index", -1)) != expected_index:
            failures.append(f"transparency_index:{relative_path}")
        if str(entry.get("previous_hash", "")) != previous_hash:
            failures.append(f"transparency_previous:{relative_path}")
        if str(entry.get("entry_hash", "")) != canonical_sha256(body):
            failures.append(f"transparency_entry_hash:{relative_path}")
        previous_hash = str(entry.get("entry_hash", ""))
        if relative_path not in by_name:
            failures.append(f"transparency_missing:{relative_path}")
            continue
        payload = archive.read(by_name[relative_path])
        try:
            actual_sha = text_payload_sha256(payload)
        except UnicodeDecodeError:
            failures.append(f"transparency_utf8:{relative_path}")
            continue
        if actual_sha != str(entry.get("sha256", "")):
            failures.append(f"transparency_hash:{relative_path}")
        if len(payload) != int(entry.get("bytes", -1)):
            failures.append(f"transparency_bytes:{relative_path}")
    if sorted(entry_paths) != expected_paths:
        failures.append("transparency_paths")
    if transparency_root(entries) != str(capsule.get("transparency_log_root_sha256", "")):
        failures.append("transparency_root")
    if len(entries) != int(capsule.get("transparency_log_entry_count", -1)):
        failures.append("transparency_entry_count")
    return failures


def verify_archive(
    archive_path: str,
    capsule_name: str,
    capsule_markdown_name: str,
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    try:
        archive = zipfile.ZipFile(archive_path, "r")
    except (OSError, zipfile.BadZipFile):
        return False, ["archive_open"]
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        by_name = {info.filename: info for info in infos}
        if len(names) != len(set(names)):
            failures.append("duplicate_entries")
        for info in infos:
            if not path_is_safe(info.filename):
                failures.append(f"path:{info.filename}")
            if info.date_time != ZIP_FIXED_DATE:
                failures.append(f"timestamp:{info.filename}")
            if info.external_attr != ZIP_FIXED_EXTERNAL_ATTR:
                failures.append(f"mode:{info.filename}")
            if info.compress_type != zipfile.ZIP_DEFLATED:
                failures.append(f"compression:{info.filename}")
        if capsule_name not in by_name:
            return False, failures + ["capsule_missing"]
        try:
            capsule_payload = archive.read(by_name[capsule_name])
            capsule_obj = json.loads(capsule_payload.decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
            return False, failures + ["capsule_json"]
        if not isinstance(capsule_obj, dict):
            return False, failures + ["capsule_not_json_object"]
        capsule = capsule_obj
        files_obj = capsule.get("files", [])
        files = files_obj if isinstance(files_obj, list) else []
        roles_obj = capsule.get("artifact_roles", {})
        roles = roles_obj if isinstance(roles_obj, dict) else {}
        required_obj = capsule.get("required_roles", [])
        declared_roles = (
            set(str(role) for role in required_obj)
            if isinstance(required_obj, list)
            else set()
        )
        declared_paths: set[str] = set()
        if capsule.get("artifact_kind") != "pettachainer_showcase_audit_capsule":
            failures.append("kind")
        if capsule.get("audit_capsule_sha256") != canonical_sha256(capsule_body(capsule)):
            failures.append("capsule_hash")
        if capsule.get("file_manifest_root_sha256") != canonical_sha256(files):
            failures.append("file_manifest_root")
        if int(capsule.get("file_count", -1)) != len(files):
            failures.append("file_count")
        if not REQUIRED_ROLES.issubset(declared_roles):
            failures.append("required_roles_declared")
        if not REQUIRED_ROLES.issubset(set(roles)):
            failures.append("required_roles_bound")
        for entry in files:
            if not isinstance(entry, dict):
                failures.append("file_entry_shape")
                continue
            relative_path = str(entry.get("path", ""))
            if relative_path:
                declared_paths.add(relative_path)
            if not path_is_safe(relative_path):
                failures.append(f"file_path:{relative_path}")
            if relative_path not in by_name:
                failures.append(f"missing:{relative_path}")
                continue
            payload = archive.read(by_name[relative_path])
            try:
                actual_sha = text_payload_sha256(payload)
            except UnicodeDecodeError:
                failures.append(f"utf8:{relative_path}")
                continue
            if actual_sha != str(entry.get("sha256", "")):
                failures.append(f"hash:{relative_path}")
            if len(payload) != int(entry.get("bytes", -1)):
                failures.append(f"bytes:{relative_path}")
        for role in REQUIRED_ROLES:
            if str(roles.get(role, "")) not in declared_paths:
                failures.append(f"role_file:{role}")
        failures.extend(verify_audit_policy(archive, by_name, capsule, files, roles, declared_roles))
        failures.extend(verify_audit_receipt(archive, by_name, capsule, files, roles))
        failures.extend(verify_transparency_log(archive, by_name, capsule, files, roles))
        expected_names = sorted(declared_paths | {capsule_name, capsule_markdown_name})
        if names != expected_names:
            failures.append("entry_names")
        if capsule_markdown_name not in by_name:
            failures.append("capsule_markdown_missing")
        else:
            markdown_payload = archive.read(by_name[capsule_markdown_name])
            if markdown_payload != capsule_markdown(capsule).encode("utf-8"):
                failures.append("capsule_markdown")
    return not failures, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="Audit capsule ZIP archive")
    parser.add_argument(
        "--capsule",
        default="showcase-audit-capsule.json",
        help="Capsule JSON archive entry name",
    )
    parser.add_argument(
        "--capsule-markdown",
        default=None,
        help="Capsule Markdown archive entry name; defaults to capsule name with .md",
    )
    args = parser.parse_args()
    capsule_markdown = (
        args.capsule_markdown
        if args.capsule_markdown is not None
        else str(PurePosixPath(args.capsule).with_suffix(".md"))
    )
    ok, failures = verify_archive(args.archive, args.capsule, capsule_markdown)
    if ok:
        print("PASS audit capsule archive standalone verification")
        return 0
    print("FAIL audit capsule archive standalone verification", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def audit_capsule_one_command_verifier_text() -> str:
    return '''#!/usr/bin/env python3
"""Run all portable PeTTaChainer audit capsule checks with one command."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run_step(label: str, command: list[str]) -> bool:
    completed = subprocess.run(command, check=False, text=True)
    if completed.returncode == 0:
        print(f"PASS {label}")
        return True
    print(f"FAIL {label}", file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("."))
    parser.add_argument(
        "--capsule",
        default="showcase-audit-capsule.json",
        help="Capsule JSON path or directory-relative name",
    )
    parser.add_argument(
        "--archive",
        default="showcase-audit-capsule.zip",
        help="Archive ZIP path or directory-relative name",
    )
    args = parser.parse_args()
    directory = args.directory.resolve()
    capsule = Path(args.capsule)
    if not capsule.is_absolute():
        capsule = directory / capsule
    archive = Path(args.archive)
    if not archive.is_absolute():
        archive = directory / archive
    checks = [
        run_step(
            "audit capsule directory",
            [
                sys.executable,
                str(directory / "showcase-standalone-verifier.py"),
                str(directory),
                "--capsule",
                str(capsule),
            ],
        ),
        run_step(
            "audit capsule archive",
            [
                sys.executable,
                str(directory / "showcase-standalone-archive-verifier.py"),
                str(archive),
                "--capsule",
                capsule.name,
            ],
        ),
    ]
    if all(checks):
        print("PASS PeTTaChainer portable audit capsule")
        return 0
    print("FAIL PeTTaChainer portable audit capsule", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def audit_decision_standalone_verifier_text() -> str:
    return '''#!/usr/bin/env python3
"""Standalone verifier for a PeTTaChainer external audit decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


DECISION_CERTIFICATE = "showcase-audit-decision.json"
DECISION_VERIFIER = "showcase-audit-decision-verifier.py"
AUDIT_GAUNTLET = "showcase-audit-gauntlet.py"
CHALLENGE_TRANSCRIPT = "showcase-audit-challenge-transcript.json"
CHALLENGE_TRANSCRIPT_MARKDOWN = "showcase-audit-challenge-transcript.md"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def object_body(payload: dict[str, object], hash_key: str) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != hash_key}


def decision_body(decision: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in decision.items()
        if key not in {"audit_decision_sha256", "result_path"}
    }


def capsule_body(capsule: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in capsule.items()
        if key not in {"audit_capsule_sha256", "result_path", "markdown_path"}
    }


def resolve_path(directory: Path, value: object, default_name: str) -> Path:
    text = str(value or default_name)
    path = Path(text)
    return path if path.is_absolute() else directory / path


def json_object(path: Path) -> dict[str, object]:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a JSON object")
    return payload


def subject_checks(
    directory: Path,
    decision: dict[str, object],
) -> tuple[dict[str, bool], dict[str, dict[str, object]]]:
    subjects = list(decision.get("subjects", []))
    subject_by_path: dict[str, dict[str, object]] = {}
    all_present = bool(subjects)
    all_hashes = bool(subjects)
    all_sizes = bool(subjects)
    unique_paths = True
    for item in subjects:
        if not isinstance(item, dict):
            all_present = False
            all_hashes = False
            all_sizes = False
            continue
        relative_path = str(item.get("path", ""))
        if relative_path in subject_by_path:
            unique_paths = False
        subject_by_path[relative_path] = item
        path = directory / relative_path
        present = path.exists() and path.is_file()
        all_present = all_present and present and bool(item.get("present"))
        if present:
            all_hashes = all_hashes and file_sha256(path) == str(item.get("sha256", ""))
            all_sizes = all_sizes and path.stat().st_size == int(item.get("bytes", -1))
        else:
            all_hashes = False
            all_sizes = False
    checks = {
        "subject_count_matches": int(decision.get("subject_count", -1)) == len(subjects),
        "subject_paths_unique": unique_paths,
        "subject_manifest_hash_matches": decision.get("subject_manifest_sha256") == canonical_sha256(subjects),
        "subject_files_present": all_present,
        "subject_hashes_match": all_hashes,
        "subject_sizes_match": all_sizes,
        "decision_certificate_not_self_subject": DECISION_CERTIFICATE not in subject_by_path,
        "standalone_decision_verifier_is_subject": DECISION_VERIFIER in subject_by_path,
        "audit_gauntlet_is_subject": AUDIT_GAUNTLET in subject_by_path,
        "challenge_transcript_is_subject": CHALLENGE_TRANSCRIPT in subject_by_path,
        "challenge_transcript_markdown_is_subject": CHALLENGE_TRANSCRIPT_MARKDOWN in subject_by_path,
    }
    return checks, subject_by_path


def object_hash_matches(
    payload: dict[str, object],
    hash_key: str,
    expected: object,
) -> bool:
    return payload.get(hash_key) == canonical_sha256(object_body(payload, hash_key)) == expected


def red_team_matches(
    directory: Path,
    summary: dict[str, object],
    pass_key: str,
) -> bool:
    path = directory / str(summary.get("path", ""))
    if not path.exists():
        return False
    payload = json_object(path)
    cases = dict(payload.get("cases", {}))
    rejected_cases = sorted(
        name for name, case in cases.items() if isinstance(case, dict) and bool(case.get("rejected"))
    )
    failed_cases = sorted(
        name for name, case in cases.items() if isinstance(case, dict) and not bool(case.get("rejected"))
    )
    return (
        bool(payload.get(pass_key))
        and bool(summary.get("pass"))
        and int(summary.get("case_count", -1)) == int(payload.get("case_count", -2))
        and summary.get("rejected_cases") == rejected_cases
        and summary.get("failed_cases") == failed_cases
        and summary.get("sha256") == file_sha256(path)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("."))
    parser.add_argument(
        "--certificate",
        default=DECISION_CERTIFICATE,
        help="Decision certificate JSON path or directory-relative name",
    )
    parser.add_argument("--capsule", default="", help="Override audit capsule JSON")
    parser.add_argument("--archive", default="", help="Override audit capsule ZIP")
    parser.add_argument("--capsule-markdown", default="", help="Override capsule Markdown")
    args = parser.parse_args()
    directory = args.directory.resolve()
    certificate_path = resolve_path(directory, args.certificate, DECISION_CERTIFICATE)
    failures: list[str] = []
    try:
        decision = json_object(certificate_path)
        capsule_path = resolve_path(
            directory,
            args.capsule or decision.get("audit_capsule_path"),
            "showcase-audit-capsule.json",
        )
        archive_path = resolve_path(
            directory,
            args.archive or decision.get("audit_capsule_archive_path"),
            "showcase-audit-capsule.zip",
        )
        capsule_markdown_path = resolve_path(
            directory,
            args.capsule_markdown or decision.get("audit_capsule_markdown_path"),
            "showcase-audit-capsule.md",
        )
        capsule = json_object(capsule_path)
        roles = dict(capsule.get("artifact_roles", {}))
        policy = json_object(directory / str(roles.get("audit_policy", "showcase-audit-policy.json")))
        runtime = json_object(directory / str(roles.get("runtime_manifest", "showcase-runtime-manifest.json")))
        receipt = json_object(directory / str(roles.get("audit_receipt", "showcase-audit-receipt.json")))
        provenance = json_object(directory / str(roles.get("provenance_attestation", "showcase-provenance.intoto.json")))
        packet = json_object(directory / str(roles.get("forensic_packet", "showcase-forensic-packet.json")))
        transcript_path = resolve_path(
            directory,
            decision.get("audit_challenge_transcript_path"),
            CHALLENGE_TRANSCRIPT,
        )
        transcript_markdown_path = resolve_path(
            directory,
            decision.get("audit_challenge_transcript_markdown_path"),
            CHALLENGE_TRANSCRIPT_MARKDOWN,
        )
        transcript = json_object(transcript_path)
        transcript_families = {
            str(family.get("family", "")): family
            for family in list(transcript.get("families", []))
            if isinstance(family, dict)
        }
        red_team = dict(decision.get("red_team_summary", {}))
        decision_rejected_count = sum(
            len(list(dict(summary).get("rejected_cases", [])))
            for summary in red_team.values()
            if isinstance(summary, dict)
        )
        transcript_red_team_hashes_match = all(
            str(transcript_families.get(name, {}).get("result_sha256", ""))
            == str(summary.get("sha256", ""))
            for name, summary in red_team.items()
            if isinstance(summary, dict)
        )
        subject_result, subject_by_path = subject_checks(directory, decision)
        checks = {
            "decision_kind_matches": decision.get("artifact_kind") == "pettachainer_showcase_audit_decision",
            "decision_hash_matches": decision.get("audit_decision_sha256") == canonical_sha256(decision_body(decision)),
            "decision_verdict_pass": decision.get("verdict") == "PASS",
            "declared_checks_pass": all(bool(value) for value in dict(decision.get("checks", {})).values()),
            "capsule_hash_matches": (
                capsule.get("audit_capsule_sha256")
                == canonical_sha256(capsule_body(capsule))
                == decision.get("audit_capsule_sha256")
            ),
            "capsule_markdown_is_subject": capsule_markdown_path.name in subject_by_path,
            "archive_hash_matches": archive_path.exists() and file_sha256(archive_path) == decision.get("audit_capsule_archive_sha256"),
            "policy_hash_matches": object_hash_matches(policy, "audit_policy_sha256", decision.get("audit_policy_sha256")),
            "runtime_hash_matches": object_hash_matches(runtime, "runtime_manifest_sha256", decision.get("runtime_manifest_sha256")),
            "receipt_hash_matches": object_hash_matches(receipt, "audit_receipt_sha256", decision.get("audit_receipt_sha256")),
            "receipt_root_matches": receipt.get("subject_merkle_root_sha256") == decision.get("audit_receipt_subject_merkle_root_sha256"),
            "provenance_hash_matches": object_hash_matches(provenance, "provenance_sha256", decision.get("provenance_sha256")),
            "packet_root_matches": packet.get("packet_root_sha256") == canonical_sha256(object_body(packet, "packet_root_sha256")) == decision.get("packet_root_sha256"),
            "file_manifest_root_matches": capsule.get("file_manifest_root_sha256") == decision.get("file_manifest_root_sha256"),
            "transparency_root_matches": capsule.get("transparency_log_root_sha256") == decision.get("transparency_log_root_sha256"),
            "file_count_matches": int(capsule.get("file_count", -1)) == int(decision.get("file_count", -2)),
            "standalone_decision_verifier_hash_matches": (
                (directory / DECISION_VERIFIER).exists()
                and file_sha256(directory / DECISION_VERIFIER) == decision.get("standalone_decision_verifier_sha256")
            ),
            "audit_gauntlet_hash_matches": (
                (directory / AUDIT_GAUNTLET).exists()
                and file_sha256(directory / AUDIT_GAUNTLET) == decision.get("audit_gauntlet_sha256")
            ),
            "challenge_transcript_hash_matches": object_hash_matches(
                transcript,
                "audit_challenge_transcript_sha256",
                decision.get("audit_challenge_transcript_sha256"),
            ),
            "challenge_transcript_file_hash_matches": (
                transcript_path.exists()
                and file_sha256(transcript_path) == decision.get("audit_challenge_transcript_file_sha256")
            ),
            "challenge_transcript_markdown_present": transcript_markdown_path.exists(),
            "challenge_transcript_verdict_pass": transcript.get("verdict") == "PASS",
            "challenge_transcript_rejection_count_matches": int(
                transcript.get("rejected_case_count", -1)
            )
            == decision_rejected_count,
            "challenge_transcript_red_team_hashes_match": transcript_red_team_hashes_match,
            "audit_capsule_red_team_matches": red_team_matches(
                directory,
                dict(red_team.get("audit_capsule", {})),
                "audit_capsule_red_team_pass",
            ),
            "audit_capsule_archive_red_team_matches": red_team_matches(
                directory,
                dict(red_team.get("audit_capsule_archive", {})),
                "audit_capsule_archive_red_team_pass",
            ),
        }
        checks.update(subject_result)
        failures = [name for name, passed in checks.items() if not bool(passed)]
    except Exception as exc:  # noqa: BLE001 - standalone verifier reports any parse/fs failure.
        failures = [f"{type(exc).__name__}: {exc}"]
    if not failures:
        print("PASS audit decision standalone verification")
        return 0
    print("FAIL audit decision standalone verification", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def audit_decision_gauntlet_text() -> str:
    return '''#!/usr/bin/env python3
"""Portable tamper gauntlet for a PeTTaChainer audit handoff."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


CAPSULE_VERIFIER = "showcase-standalone-verifier.py"
ARCHIVE_VERIFIER = "showcase-standalone-archive-verifier.py"
DECISION_VERIFIER = "showcase-audit-decision-verifier.py"
ONE_COMMAND_VERIFIER = "showcase-verify-all.py"
DECISION_CERTIFICATE = "showcase-audit-decision.json"
CAPSULE = "showcase-audit-capsule.json"
ARCHIVE = "showcase-audit-capsule.zip"
CAPSULE_MARKDOWN = "showcase-audit-capsule.md"


def resolve_path(directory: Path, value: str, default_name: str) -> Path:
    path = Path(value or default_name)
    return path if path.is_absolute() else directory / path


def relative_name(directory: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(directory.resolve()).as_posix()
    except ValueError:
        return path.name


def run_command(label: str, command: list[str], *, expect_success: bool) -> bool:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    ok = completed.returncode == 0 if expect_success else completed.returncode != 0
    if ok:
        print(f"PASS {label}")
        return True
    print(f"FAIL {label}", file=sys.stderr)
    print(f"command: {' '.join(command)}", file=sys.stderr)
    print(f"returncode: {completed.returncode}", file=sys.stderr)
    if completed.stdout.strip():
        print(completed.stdout.strip(), file=sys.stderr)
    if completed.stderr.strip():
        print(completed.stderr.strip(), file=sys.stderr)
    return False


def mutate_json(path: Path, key: str, value: object) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} is not a JSON object")
    payload[key] = value
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def copy_case(source: Path, parent: Path, name: str) -> Path:
    target = parent / name
    shutil.copytree(source, target)
    return target


def decision_verifier_command(
    verifier: Path,
    directory: Path,
    certificate: Path,
    capsule: Path,
    archive: Path,
    capsule_markdown: Path,
) -> list[str]:
    return [
        sys.executable,
        str(verifier),
        str(directory),
        "--certificate",
        str(certificate),
        "--capsule",
        str(capsule),
        "--archive",
        str(archive),
        "--capsule-markdown",
        str(capsule_markdown),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--certificate", default=DECISION_CERTIFICATE)
    parser.add_argument("--capsule", default=CAPSULE)
    parser.add_argument("--archive", default=ARCHIVE)
    parser.add_argument("--capsule-markdown", default=CAPSULE_MARKDOWN)
    args = parser.parse_args()
    directory = args.directory.resolve()
    certificate = resolve_path(directory, args.certificate, DECISION_CERTIFICATE)
    capsule = resolve_path(directory, args.capsule, CAPSULE)
    archive = resolve_path(directory, args.archive, ARCHIVE)
    capsule_markdown = resolve_path(directory, args.capsule_markdown, CAPSULE_MARKDOWN)
    capsule_name = relative_name(directory, capsule)
    capsule_markdown_name = relative_name(directory, capsule_markdown)
    original_decision_verifier = directory / DECISION_VERIFIER

    checks = [
        run_command(
            "baseline capsule directory verifier",
            [
                sys.executable,
                str(directory / CAPSULE_VERIFIER),
                str(directory),
                "--capsule",
                str(capsule),
            ],
            expect_success=True,
        ),
        run_command(
            "baseline capsule archive verifier",
            [
                sys.executable,
                str(directory / ARCHIVE_VERIFIER),
                str(archive),
                "--capsule",
                capsule_name,
                "--capsule-markdown",
                capsule_markdown_name,
            ],
            expect_success=True,
        ),
        run_command(
            "baseline decision verifier",
            decision_verifier_command(
                original_decision_verifier,
                directory,
                certificate,
                capsule,
                archive,
                capsule_markdown,
            ),
            expect_success=True,
        ),
        run_command(
            "baseline portable capsule verifier",
            [
                sys.executable,
                str(directory / ONE_COMMAND_VERIFIER),
                str(directory),
                "--capsule",
                str(capsule),
                "--archive",
                str(archive),
            ],
            expect_success=True,
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="pettachainer-audit-gauntlet-") as tmp:
        tmp_path = Path(tmp)
        case = copy_case(directory, tmp_path, "forged-decision")
        mutate_json(case / relative_name(directory, certificate), "subject_count", 0)
        checks.append(
            run_command(
                "rejects forged decision certificate",
                decision_verifier_command(
                    original_decision_verifier,
                    case,
                    case / relative_name(directory, certificate),
                    case / capsule_name,
                    case / relative_name(directory, archive),
                    case / capsule_markdown_name,
                ),
                expect_success=False,
            )
        )

        case = copy_case(directory, tmp_path, "forged-decision-verifier")
        with (case / DECISION_VERIFIER).open("a", encoding="utf-8") as handle:
            handle.write("\\n# forged verifier drift\\n")
        checks.append(
            run_command(
                "rejects forged decision verifier",
                decision_verifier_command(
                    original_decision_verifier,
                    case,
                    case / relative_name(directory, certificate),
                    case / capsule_name,
                    case / relative_name(directory, archive),
                    case / capsule_markdown_name,
                ),
                expect_success=False,
            )
        )

        case = copy_case(directory, tmp_path, "forged-capsule")
        mutate_json(case / capsule_name, "file_count", 0)
        checks.append(
            run_command(
                "rejects forged capsule",
                [
                    sys.executable,
                    str(directory / CAPSULE_VERIFIER),
                    str(case),
                    "--capsule",
                    str(case / capsule_name),
                ],
                expect_success=False,
            )
        )
        checks.append(
            run_command(
                "rejects forged capsule via decision verifier",
                decision_verifier_command(
                    original_decision_verifier,
                    case,
                    case / relative_name(directory, certificate),
                    case / capsule_name,
                    case / relative_name(directory, archive),
                    case / capsule_markdown_name,
                ),
                expect_success=False,
            )
        )

        case = copy_case(directory, tmp_path, "forged-archive")
        with zipfile.ZipFile(case / relative_name(directory, archive), "a") as forged:
            forged.writestr("forged-gauntlet-entry.txt", b"forged\\n")
        checks.append(
            run_command(
                "rejects forged archive",
                [
                    sys.executable,
                    str(directory / ARCHIVE_VERIFIER),
                    str(case / relative_name(directory, archive)),
                    "--capsule",
                    capsule_name,
                    "--capsule-markdown",
                    capsule_markdown_name,
                ],
                expect_success=False,
            )
        )
        checks.append(
            run_command(
                "rejects forged archive via decision verifier",
                decision_verifier_command(
                    original_decision_verifier,
                    case,
                    case / relative_name(directory, certificate),
                    case / capsule_name,
                    case / relative_name(directory, archive),
                    case / capsule_markdown_name,
                ),
                expect_success=False,
            )
        )

    if all(checks):
        print("PASS PeTTaChainer portable audit gauntlet")
        return 0
    print("FAIL PeTTaChainer portable audit gauntlet", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def write_audit_capsule_standalone_verifier(output_dir: Path) -> Path:
    verifier_path = output_dir / AUDIT_CAPSULE_STANDALONE_VERIFIER
    verifier_path.write_text(
        audit_capsule_standalone_verifier_text(),
        encoding="utf-8",
    )
    verifier_path.chmod(0o755)
    return verifier_path


def write_audit_capsule_standalone_archive_verifier(output_dir: Path) -> Path:
    verifier_path = output_dir / AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER
    verifier_path.write_text(
        audit_capsule_standalone_archive_verifier_text(),
        encoding="utf-8",
    )
    verifier_path.chmod(0o755)
    return verifier_path


def write_audit_capsule_one_command_verifier(output_dir: Path) -> Path:
    verifier_path = output_dir / AUDIT_CAPSULE_ONE_COMMAND_VERIFIER
    verifier_path.write_text(
        audit_capsule_one_command_verifier_text(),
        encoding="utf-8",
    )
    verifier_path.chmod(0o755)
    return verifier_path


def write_audit_decision_standalone_verifier(output_dir: Path) -> Path:
    verifier_path = output_dir / AUDIT_DECISION_STANDALONE_VERIFIER
    verifier_path.write_text(
        audit_decision_standalone_verifier_text(),
        encoding="utf-8",
    )
    verifier_path.chmod(0o755)
    return verifier_path


def write_audit_decision_gauntlet(output_dir: Path) -> Path:
    gauntlet_path = output_dir / AUDIT_DECISION_GAUNTLET
    gauntlet_path.write_text(
        audit_decision_gauntlet_text(),
        encoding="utf-8",
    )
    gauntlet_path.chmod(0o755)
    return gauntlet_path


def verify_audit_capsule_one_command_verifier(
    output_dir: Path,
    verifier_path: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    verifier_path = (
        verifier_path.resolve()
        if verifier_path is not None
        else output_dir / AUDIT_CAPSULE_ONE_COMMAND_VERIFIER
    )
    expected_text = audit_capsule_one_command_verifier_text()
    actual_text = (
        verifier_path.read_text(encoding="utf-8") if verifier_path.exists() else ""
    )
    checks = {
        "one_command_verifier_present": verifier_path.exists(),
        "one_command_verifier_matches_expected": bool(actual_text)
        and actual_text == expected_text,
    }
    checks["one_command_verifier_verified"] = all(checks.values())
    return {
        "one_command_verifier_path": str(verifier_path),
        "one_command_verifier_sha256": hash_file(verifier_path)
        if verifier_path.exists()
        else "",
        "checks": checks,
    }


def write_audit_capsule(
    output_dir: Path,
    *,
    result_path: Path,
    markdown_path: Path,
) -> dict[str, object]:
    write_audit_capsule_standalone_verifier(output_dir)
    write_audit_capsule_standalone_archive_verifier(output_dir)
    write_audit_capsule_one_command_verifier(output_dir)
    write_audit_dashboard(output_dir)
    write_audit_policy(output_dir)
    write_runtime_manifest(output_dir)
    write_audit_receipt(output_dir)
    write_audit_provenance_attestation(output_dir)
    write_audit_checksum_manifest(output_dir)
    write_audit_transparency_log(output_dir)
    capsule = build_audit_capsule(output_dir)
    capsule["result_path"] = str(result_path)
    capsule["markdown_path"] = str(markdown_path)
    write_json(result_path, capsule)
    markdown_path.write_text(audit_capsule_markdown(capsule), encoding="utf-8")
    return capsule


def verify_audit_capsule(
    output_dir: Path,
    capsule_path: Path,
    *,
    capsule_markdown_path: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    checks: dict[str, bool] = {
        "audit_capsule_present": capsule_path.exists(),
        "artifact_dir_present": output_dir.exists(),
    }
    if not checks["audit_capsule_present"] or not checks["artifact_dir_present"]:
        checks["audit_capsule_verified"] = False
        return {
            "artifact_dir": str(output_dir),
            "audit_capsule_path": str(capsule_path),
            "checks": checks,
        }
    capsule = load_json(capsule_path)
    capsule_markdown_path = (
        capsule_markdown_path
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    files = list(capsule.get("files", []))
    roles = dict(capsule.get("artifact_roles", {}))
    required_roles = set(str(role) for role in capsule.get("required_roles", []))
    file_hash_checks: dict[str, bool] = {}
    file_size_checks: dict[str, bool] = {}
    for file_entry in files:
        relative_path = str(file_entry.get("path", ""))
        path = output_dir / relative_path
        file_hash_checks[relative_path] = (
            path.exists()
            and path.is_file()
            and hash_file(path) == str(file_entry.get("sha256", ""))
        )
        file_size_checks[relative_path] = (
            path.exists()
            and path.is_file()
            and path.stat().st_size == int(file_entry.get("bytes", -1))
        )
    capsule_body = audit_capsule_hash_body(capsule)
    recomputed_sha = canonical_object_sha256(capsule_body)
    markdown_text = (
        capsule_markdown_path.read_text(encoding="utf-8")
        if capsule_markdown_path.exists()
        else ""
    )
    expected_markdown = audit_capsule_markdown(capsule)
    transparency_details = verify_audit_transparency_log(
        output_dir,
        output_dir / str(roles.get("transparency_log", "")),
        markdown_path=output_dir / AUDIT_CAPSULE_TRANSPARENCY_LOG_MARKDOWN,
        expected_paths=audit_transparency_covered_paths_from_files(files),
        expected_root=str(capsule.get("transparency_log_root_sha256", "")),
        expected_entry_count=int(capsule.get("transparency_log_entry_count", -1)),
    )
    transparency_checks = dict(transparency_details.get("checks", {}))
    dashboard_details = verify_audit_dashboard(
        output_dir,
        output_dir / str(roles.get("audit_dashboard", "")),
    )
    dashboard_checks = dict(dashboard_details.get("checks", {}))
    one_command_details = verify_audit_capsule_one_command_verifier(
        output_dir,
        output_dir / str(roles.get("one_command_verifier", "")),
    )
    one_command_checks = dict(one_command_details.get("checks", {}))
    checksum_details = verify_audit_checksum_manifest(
        output_dir,
        output_dir / str(roles.get("checksum_manifest", "")),
    )
    checksum_checks = dict(checksum_details.get("checks", {}))
    provenance_details = verify_audit_provenance_attestation(
        output_dir,
        output_dir / str(roles.get("provenance_attestation", "")),
    )
    provenance_checks = dict(provenance_details.get("checks", {}))
    receipt_details = verify_audit_receipt(
        output_dir,
        output_dir / str(roles.get("audit_receipt", "")),
    )
    receipt_checks = dict(receipt_details.get("checks", {}))
    policy_details = verify_audit_policy(
        output_dir,
        output_dir / str(roles.get("audit_policy", "")),
        capsule=capsule,
    )
    policy_checks = dict(policy_details.get("checks", {}))
    runtime_details = verify_runtime_manifest(
        output_dir,
        output_dir / str(roles.get("runtime_manifest", "")),
    )
    runtime_checks = dict(runtime_details.get("checks", {}))
    checks.update(
        {
            "audit_capsule_kind_matches": capsule.get("artifact_kind")
            == "pettachainer_showcase_audit_capsule",
            "audit_capsule_hash_matches": capsule.get("audit_capsule_sha256")
            == recomputed_sha,
            "file_manifest_root_matches": capsule.get("file_manifest_root_sha256")
            == canonical_object_sha256(files),
            "file_count_matches": int(capsule.get("file_count", -1)) == len(files),
            "declared_files_present": bool(files) and all(
                (output_dir / str(file_entry.get("path", ""))).is_file()
                for file_entry in files
            ),
            "declared_file_hashes_match": bool(file_hash_checks)
            and all(file_hash_checks.values()),
            "declared_file_sizes_match": bool(file_size_checks)
            and all(file_size_checks.values()),
            "required_roles_declared": AUDIT_CAPSULE_REQUIRED_ROLES.issubset(
                required_roles
            ),
            "required_roles_bound": AUDIT_CAPSULE_REQUIRED_ROLES.issubset(
                set(roles)
            ),
            "required_role_files_declared": all(
                role in roles
                and any(str(file_entry.get("path", "")) == roles[role] for file_entry in files)
                for role in AUDIT_CAPSULE_REQUIRED_ROLES
            ),
            "verification_commands_match_expected": capsule.get(
                "verification_commands", []
            )
            == audit_capsule_verification_commands(),
            "transparency_log_verified": bool(
                transparency_checks.get("transparency_log_verified")
            ),
            "transparency_log_root_matches_capsule": str(
                capsule.get("transparency_log_root_sha256", "")
            )
            == str(transparency_details.get("transparency_log_root_sha256", "")),
            "transparency_log_entry_count_matches_capsule": int(
                capsule.get("transparency_log_entry_count", -1)
            )
            == int(transparency_details.get("entry_count", -2)),
            "audit_dashboard_verified": bool(
                dashboard_checks.get("audit_dashboard_verified")
            ),
            "one_command_verifier_verified": bool(
                one_command_checks.get("one_command_verifier_verified")
            ),
            "checksum_manifest_verified": bool(
                checksum_checks.get("checksum_manifest_verified")
            ),
            "audit_policy_verified": bool(
                policy_checks.get("audit_policy_verified")
            ),
            "audit_policy_sha256_matches_capsule": str(
                capsule.get("audit_policy_sha256", "")
            )
            == str(policy_details.get("audit_policy_sha256", "")),
            "runtime_manifest_verified": bool(
                runtime_checks.get("runtime_manifest_verified")
            ),
            "runtime_manifest_sha256_matches_capsule": str(
                capsule.get("runtime_manifest_sha256", "")
            )
            == str(runtime_details.get("runtime_manifest_sha256", "")),
            "provenance_attestation_verified": bool(
                provenance_checks.get("provenance_attestation_verified")
            ),
            "provenance_attestation_sha256_matches_capsule": str(
                capsule.get("provenance_attestation_sha256", "")
            )
            == str(provenance_details.get("provenance_sha256", "")),
            "provenance_subject_count_matches_capsule": int(
                capsule.get("provenance_subject_count", -1)
            )
            == int(provenance_details.get("subject_count", -2)),
            "audit_receipt_verified": bool(
                receipt_checks.get("audit_receipt_verified")
            ),
            "audit_receipt_sha256_matches_capsule": str(
                capsule.get("audit_receipt_sha256", "")
            )
            == str(receipt_details.get("audit_receipt_sha256", "")),
            "audit_receipt_merkle_root_matches_capsule": str(
                capsule.get("audit_receipt_subject_merkle_root_sha256", "")
            )
            == str(receipt_details.get("subject_merkle_root_sha256", "")),
            "audit_receipt_subject_count_matches_capsule": int(
                capsule.get("audit_receipt_subject_count", -1)
            )
            == int(receipt_details.get("subject_count", -2)),
            "markdown_present": capsule_markdown_path.exists(),
            "markdown_matches_capsule": bool(markdown_text)
            and markdown_text == expected_markdown,
        }
    )
    checks["audit_capsule_verified"] = all(checks.values())
    return {
        "artifact_dir": str(output_dir),
        "audit_capsule_path": str(capsule_path),
        "audit_capsule_markdown_path": str(capsule_markdown_path),
        "audit_capsule_sha256": capsule.get("audit_capsule_sha256", ""),
        "recomputed_audit_capsule_sha256": recomputed_sha,
        "file_manifest_root_sha256": capsule.get("file_manifest_root_sha256", ""),
        "transparency_log_root_sha256": capsule.get(
            "transparency_log_root_sha256", ""
        ),
        "transparency_log_details": transparency_details,
        "audit_dashboard_details": dashboard_details,
        "one_command_verifier_details": one_command_details,
        "checksum_manifest_details": checksum_details,
        "audit_policy_details": policy_details,
        "runtime_manifest_details": runtime_details,
        "provenance_attestation_details": provenance_details,
        "audit_receipt_details": receipt_details,
        "file_count": capsule.get("file_count", 0),
        "artifact_roles": roles,
        "failed_file_hashes": [
            path for path, passed in file_hash_checks.items() if not bool(passed)
        ],
        "checks": checks,
    }


def run_audit_capsule_red_team(
    output_dir: Path,
    capsule_path: Path,
    *,
    capsule_markdown_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    capsule_path = capsule_path.resolve()
    capsule_markdown_path = (
        capsule_markdown_path.resolve()
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir / "audit-capsule-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    baseline = verify_audit_capsule(
        output_dir,
        capsule_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    baseline_verified = bool(baseline["checks"].get("audit_capsule_verified"))

    def recompute_capsule_hash(capsule: dict[str, object]) -> None:
        capsule["file_manifest_root_sha256"] = canonical_object_sha256(
            list(capsule.get("files", []))
        )
        capsule["audit_capsule_sha256"] = canonical_object_sha256(
            audit_capsule_hash_body(capsule)
        )

    def copy_capsule_files(case_dir: Path, capsule: dict[str, object]) -> None:
        for file_entry in list(capsule.get("files", [])):
            relative_path = str(file_entry.get("path", ""))
            source = output_dir / relative_path
            target = case_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.exists() and source.is_file():
                shutil.copy2(source, target)

    def first_file(capsule: dict[str, object]) -> dict[str, object]:
        return list(capsule.get("files", []))[0]

    specs = {
        "capsule_hash_forgery": {
            "mutate_json": lambda capsule: capsule.__setitem__(
                "audit_capsule_sha256", "0" * 64
            ),
            "expected_failed_checks": ["audit_capsule_hash_matches"],
        },
        "file_hash_forgery": {
            "mutate_json": lambda capsule: first_file(capsule).__setitem__(
                "sha256", "0" * 64
            ),
            "recompute_capsule_hash": True,
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "markdown_matches_capsule",
            ],
        },
        "role_omission_forgery": {
            "mutate_json": lambda capsule: dict(capsule.get("artifact_roles", {})).pop(
                "audit_proof_graph_dot", None
            ),
            "custom_mutate_json": "omit_audit_proof_graph_dot_role",
            "recompute_capsule_hash": True,
            "expected_failed_checks": [
                "required_roles_bound",
                "required_role_files_declared",
                "markdown_matches_capsule",
            ],
        },
        "command_forgery": {
            "mutate_json": lambda capsule: list(
                capsule.get("verification_commands", [])
            ).append("echo forged"),
            "custom_mutate_json": "append_forged_command",
            "recompute_capsule_hash": True,
            "expected_failed_checks": [
                "verification_commands_match_expected",
                "markdown_matches_capsule",
            ],
        },
        "artifact_drift_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "audit_proof_graph_dot", first_file(capsule).get("path", "")
                    )
                )
            ).write_text("forged artifact drift\n", encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
            ],
        },
        "one_command_verifier_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "one_command_verifier",
                        AUDIT_CAPSULE_ONE_COMMAND_VERIFIER,
                    )
                )
            ).write_text("print('forged verifier')\n", encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "one_command_verifier_verified",
            ],
        },
        "checksum_manifest_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "checksum_manifest",
                        AUDIT_CAPSULE_CHECKSUM_MANIFEST,
                    )
                )
            ).write_text("0" * 64 + "  forged.txt\n", encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "checksum_manifest_verified",
            ],
        },
        "provenance_attestation_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "provenance_attestation",
                        AUDIT_CAPSULE_PROVENANCE_ATTESTATION,
                    )
                )
            ).write_text('{"forged": true}\n', encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "provenance_attestation_verified",
            ],
        },
        "audit_receipt_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "audit_receipt",
                        AUDIT_CAPSULE_AUDIT_RECEIPT,
                    )
                )
            ).write_text('{"forged": true}\n', encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "audit_receipt_verified",
            ],
        },
        "audit_policy_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "audit_policy",
                        AUDIT_CAPSULE_AUDIT_POLICY,
                    )
                )
            ).write_text('{"forged": true}\n', encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "audit_policy_verified",
            ],
        },
        "runtime_manifest_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "runtime_manifest",
                        AUDIT_CAPSULE_RUNTIME_MANIFEST,
                    )
                )
            ).write_text('{"forged": true}\n', encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "runtime_manifest_verified",
            ],
        },
        "audit_dashboard_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "audit_dashboard",
                        AUDIT_CAPSULE_AUDIT_DASHBOARD,
                    )
                )
            ).write_text("forged dashboard\n", encoding="utf-8"),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "audit_dashboard_verified",
            ],
        },
        "transparency_log_forgery": {
            "mutate_artifact": lambda case_dir, capsule: (
                case_dir
                / str(
                    dict(capsule.get("artifact_roles", {})).get(
                        "transparency_log",
                        AUDIT_CAPSULE_TRANSPARENCY_LOG,
                    )
                )
            ).write_text(
                (
                    case_dir
                    / str(
                        dict(capsule.get("artifact_roles", {})).get(
                            "transparency_log",
                            AUDIT_CAPSULE_TRANSPARENCY_LOG,
                        )
                    )
                ).read_text(encoding="utf-8")
                + '{"forged": true}\n',
                encoding="utf-8",
            ),
            "expected_failed_checks": [
                "declared_file_hashes_match",
                "declared_file_sizes_match",
                "transparency_log_verified",
            ],
        },
        "markdown_forgery": {
            "mutate_markdown": lambda text: text.replace(
                "PeTTaChainer Audit Capsule",
                "PeTTaChainer Forged Audit Capsule",
                1,
            ),
            "expected_failed_checks": ["markdown_matches_capsule"],
        },
    }

    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        case_dir = red_team_dir / name
        case_dir.mkdir(parents=True)
        forged_capsule = load_json(capsule_path)
        copy_capsule_files(case_dir, forged_capsule)
        forged_markdown = capsule_markdown_path.read_text(encoding="utf-8")
        if spec.get("custom_mutate_json") == "omit_audit_proof_graph_dot_role":
            roles = dict(forged_capsule.get("artifact_roles", {}))
            roles.pop("audit_proof_graph_dot", None)
            forged_capsule["artifact_roles"] = roles
        elif spec.get("custom_mutate_json") == "append_forged_command":
            commands = list(forged_capsule.get("verification_commands", []))
            commands.append("echo forged")
            forged_capsule["verification_commands"] = commands
        elif "mutate_json" in spec:
            spec["mutate_json"](forged_capsule)
        if bool(spec.get("recompute_capsule_hash")):
            recompute_capsule_hash(forged_capsule)
        if "mutate_artifact" in spec:
            spec["mutate_artifact"](case_dir, forged_capsule)
        if "mutate_markdown" in spec:
            forged_markdown = spec["mutate_markdown"](forged_markdown)
        forged_capsule_path = case_dir / capsule_path.name
        forged_markdown_path = case_dir / capsule_markdown_path.name
        write_json(forged_capsule_path, forged_capsule)
        forged_markdown_path.write_text(forged_markdown, encoding="utf-8")
        details = verify_audit_capsule(
            case_dir,
            forged_capsule_path,
            capsule_markdown_path=forged_markdown_path,
        )
        checks = dict(details["checks"])
        expected_failed = list(spec["expected_failed_checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and not bool(checks.get("audit_capsule_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "audit_capsule_path": str(forged_capsule_path),
            "audit_capsule_markdown_path": str(forged_markdown_path),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "audit_capsule_verified": bool(checks.get("audit_capsule_verified")),
            "rejected": rejected,
        }

    summary = {
        "artifact_dir": str(output_dir),
        "audit_capsule_path": str(capsule_path),
        "audit_capsule_markdown_path": str(capsule_markdown_path),
        "red_team_dir": str(red_team_dir),
        "baseline_audit_capsule_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "audit_capsule_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-audit-capsule-red-team-result.json"),
    }
    write_json(Path(summary["result_path"]), summary)
    return summary


ZIP_FIXED_DATE = (1980, 1, 1, 0, 0, 0)
ZIP_FIXED_EXTERNAL_ATTR = 0o100644 << 16


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def hash_binary_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def audit_capsule_archive_entries(
    output_dir: Path,
    capsule_path: Path,
    capsule_markdown_path: Path,
) -> list[tuple[str, Path]]:
    capsule = load_json(capsule_path)
    entries: dict[str, Path] = {}
    for file_entry in list(capsule.get("files", [])):
        relative_path = str(file_entry.get("path", ""))
        if relative_path:
            entries[relative_path] = output_dir / relative_path
    entries[audit_capsule_relative_path(capsule_path, output_dir)] = capsule_path
    entries[audit_capsule_relative_path(capsule_markdown_path, output_dir)] = (
        capsule_markdown_path
    )
    return sorted(entries.items(), key=lambda item: item[0])


def write_deterministic_zip(
    archive_path: Path,
    entries: list[tuple[str, Path]],
) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for archive_name, source_path in entries:
            info = zipfile.ZipInfo(archive_name, ZIP_FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ZIP_FIXED_EXTERNAL_ATTR
            archive.writestr(info, source_path.read_bytes())


def write_audit_capsule_archive(
    output_dir: Path,
    capsule_path: Path,
    archive_path: Path,
    *,
    capsule_markdown_path: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    capsule_path = capsule_path.resolve()
    capsule_markdown_path = (
        capsule_markdown_path.resolve()
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    entries = audit_capsule_archive_entries(
        output_dir,
        capsule_path,
        capsule_markdown_path,
    )
    write_deterministic_zip(archive_path, entries)
    archive_sha = hash_binary_file(archive_path)
    result = {
        "artifact_kind": "pettachainer_showcase_audit_capsule_archive",
        "artifact_dir": str(output_dir),
        "audit_capsule_path": str(capsule_path),
        "audit_capsule_markdown_path": str(capsule_markdown_path),
        "archive_path": str(archive_path),
        "archive_sha256": archive_sha,
        "entry_count": len(entries),
        "entries": [
            {
                "path": archive_name,
                "sha256": hash_binary_file(source_path),
                "bytes": source_path.stat().st_size,
            }
            for archive_name, source_path in entries
        ],
    }
    result["archive_manifest_sha256"] = canonical_object_sha256(result["entries"])
    return result


def verify_audit_capsule_archive(
    output_dir: Path,
    archive_path: Path,
    capsule_path: Path,
    *,
    capsule_markdown_path: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    capsule_path = capsule_path.resolve()
    archive_path = archive_path.resolve()
    capsule_markdown_path = (
        capsule_markdown_path.resolve()
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    checks: dict[str, bool] = {
        "archive_present": archive_path.exists(),
        "audit_capsule_present": capsule_path.exists(),
    }
    if not checks["archive_present"] or not checks["audit_capsule_present"]:
        checks["audit_capsule_archive_verified"] = False
        return {
            "artifact_dir": str(output_dir),
            "archive_path": str(archive_path),
            "audit_capsule_path": str(capsule_path),
            "checks": checks,
        }
    capsule_details = verify_audit_capsule(
        output_dir,
        capsule_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    expected_entries = audit_capsule_archive_entries(
        output_dir,
        capsule_path,
        capsule_markdown_path,
    )
    expected_names = [name for name, _ in expected_entries]
    expected_by_name = dict(expected_entries)
    entry_hash_checks: dict[str, bool] = {}
    entry_size_checks: dict[str, bool] = {}
    deterministic_metadata: dict[str, bool] = {}
    duplicate_entries = False
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            archive_names = [info.filename for info in infos]
            duplicate_entries = len(archive_names) != len(set(archive_names))
            for info in infos:
                source_path = expected_by_name.get(info.filename)
                if source_path is None:
                    entry_hash_checks[info.filename] = False
                    entry_size_checks[info.filename] = False
                else:
                    payload = archive.read(info.filename)
                    source_payload = source_path.read_bytes()
                    entry_hash_checks[info.filename] = payload == source_payload
                    entry_size_checks[info.filename] = len(payload) == len(
                        source_payload
                    )
                deterministic_metadata[info.filename] = (
                    info.date_time == ZIP_FIXED_DATE
                    and info.external_attr == ZIP_FIXED_EXTERNAL_ATTR
                )
    except zipfile.BadZipFile:
        archive_names = []
        entry_hash_checks["<bad-zip>"] = False
        entry_size_checks["<bad-zip>"] = False
        deterministic_metadata["<bad-zip>"] = False

    checks.update(
        {
            "audit_capsule_verified": bool(
                capsule_details["checks"].get("audit_capsule_verified")
            ),
            "archive_entry_names_match": archive_names == expected_names,
            "archive_has_no_duplicate_entries": not duplicate_entries,
            "archive_entry_hashes_match_files": bool(entry_hash_checks)
            and all(entry_hash_checks.values()),
            "archive_entry_sizes_match_files": bool(entry_size_checks)
            and all(entry_size_checks.values()),
            "archive_metadata_deterministic": bool(deterministic_metadata)
            and all(deterministic_metadata.values()),
        }
    )
    checks["audit_capsule_archive_verified"] = all(checks.values())
    entries = [
        {
            "path": name,
            "sha256": hash_binary_file(source_path),
            "bytes": source_path.stat().st_size,
        }
        for name, source_path in expected_entries
    ]
    return {
        "artifact_dir": str(output_dir),
        "archive_path": str(archive_path),
        "archive_sha256": hash_binary_file(archive_path),
        "archive_manifest_sha256": canonical_object_sha256(entries),
        "audit_capsule_path": str(capsule_path),
        "audit_capsule_markdown_path": str(capsule_markdown_path),
        "expected_entry_count": len(expected_entries),
        "archive_entry_count": len(archive_names),
        "missing_entries": sorted(set(expected_names) - set(archive_names)),
        "unexpected_entries": sorted(set(archive_names) - set(expected_names)),
        "failed_entry_hashes": [
            name for name, passed in entry_hash_checks.items() if not bool(passed)
        ],
        "checks": checks,
    }


def run_audit_capsule_archive_red_team(
    output_dir: Path,
    archive_path: Path,
    capsule_path: Path,
    *,
    capsule_markdown_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    archive_path = archive_path.resolve()
    capsule_path = capsule_path.resolve()
    capsule_markdown_path = (
        capsule_markdown_path.resolve()
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir / "audit-capsule-archive-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)
    baseline = verify_audit_capsule_archive(
        output_dir,
        archive_path,
        capsule_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    baseline_verified = bool(
        baseline["checks"].get("audit_capsule_archive_verified")
    )
    entries = audit_capsule_archive_entries(
        output_dir,
        capsule_path,
        capsule_markdown_path,
    )

    def write_archive_case(
        forged_archive_path: Path,
        *,
        omit_first: bool = False,
        mutate_first: bool = False,
        extra_entry: bool = False,
        forged_metadata: bool = False,
        duplicate_entry: bool = False,
    ) -> None:
        selected_entries = entries[1:] if omit_first else entries
        with zipfile.ZipFile(
            forged_archive_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for index, (archive_name, source_path) in enumerate(selected_entries):
                date_time = (2026, 1, 1, 0, 0, 0) if forged_metadata else ZIP_FIXED_DATE
                info = zipfile.ZipInfo(archive_name, date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ZIP_FIXED_EXTERNAL_ATTR
                payload = source_path.read_bytes()
                if mutate_first and index == 0:
                    payload = payload + b"\nforged archive drift\n"
                archive.writestr(info, payload)
                if duplicate_entry and index == 0:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        archive.writestr(info, payload)
            if extra_entry:
                info = zipfile.ZipInfo("forged-extra-entry.txt", ZIP_FIXED_DATE)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ZIP_FIXED_EXTERNAL_ATTR
                archive.writestr(info, b"forged\n")

    specs = {
        "archive_entry_drift": {
            "kwargs": {"mutate_first": True},
            "expected_failed_checks": [
                "archive_entry_hashes_match_files",
                "archive_entry_sizes_match_files",
            ],
        },
        "archive_entry_omission": {
            "kwargs": {"omit_first": True},
            "expected_failed_checks": ["archive_entry_names_match"],
        },
        "archive_extra_entry": {
            "kwargs": {"extra_entry": True},
            "expected_failed_checks": ["archive_entry_names_match"],
        },
        "archive_metadata_forgery": {
            "kwargs": {"forged_metadata": True},
            "expected_failed_checks": ["archive_metadata_deterministic"],
        },
        "archive_duplicate_entry": {
            "kwargs": {"duplicate_entry": True},
            "expected_failed_checks": [
                "archive_entry_names_match",
                "archive_has_no_duplicate_entries",
            ],
        },
    }
    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        forged_archive_path = red_team_dir / f"{name}.zip"
        write_archive_case(forged_archive_path, **dict(spec["kwargs"]))
        details = verify_audit_capsule_archive(
            output_dir,
            forged_archive_path,
            capsule_path,
            capsule_markdown_path=capsule_markdown_path,
        )
        checks = dict(details["checks"])
        expected_failed = list(spec["expected_failed_checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and not bool(checks.get("audit_capsule_archive_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "archive_path": str(forged_archive_path),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "audit_capsule_archive_verified": bool(
                checks.get("audit_capsule_archive_verified")
            ),
            "rejected": rejected,
        }
    summary = {
        "artifact_dir": str(output_dir),
        "archive_path": str(archive_path),
        "audit_capsule_path": str(capsule_path),
        "audit_capsule_markdown_path": str(capsule_markdown_path),
        "red_team_dir": str(red_team_dir),
        "baseline_audit_capsule_archive_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "audit_capsule_archive_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(
            output_dir / "showcase-audit-capsule-archive-red-team-result.json"
        ),
    }
    write_json(Path(summary["result_path"]), summary)
    return summary


def audit_decision_hash_body(certificate: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in certificate.items()
        if key not in {"audit_decision_sha256", "result_path"}
    }


def audit_decision_relative_path(path: Path, output_dir: Path) -> str:
    try:
        return path.resolve().relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def audit_decision_subject_entries(
    output_dir: Path,
    capsule_path: Path,
    archive_path: Path,
    capsule_markdown_path: Path,
) -> list[dict[str, object]]:
    output_dir = output_dir.resolve()
    paths: list[Path] = [capsule_path, capsule_markdown_path, archive_path]
    try:
        capsule = load_json(capsule_path)
    except (json.JSONDecodeError, OSError):
        capsule = {}
    roles = dict(capsule.get("artifact_roles", {})) if isinstance(capsule, dict) else {}
    for role in (
        "audit_policy",
        "runtime_manifest",
        "audit_receipt",
        "provenance_attestation",
    ):
        role_path = str(roles.get(role, ""))
        if role_path:
            paths.append(output_dir / role_path)
    paths.extend(
        [
            output_dir / AUDIT_DECISION_STANDALONE_VERIFIER,
            output_dir / AUDIT_DECISION_GAUNTLET,
            output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON,
            output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN,
            output_dir / "showcase-audit-capsule-red-team-result.json",
            output_dir / "showcase-audit-capsule-archive-red-team-result.json",
        ]
    )
    unique_paths = sorted({path.resolve() for path in paths}, key=lambda path: str(path))
    entries: list[dict[str, object]] = []
    for path in unique_paths:
        path_present = path.exists() and path.is_file()
        entries.append(
            {
                "path": audit_decision_relative_path(path, output_dir),
                "present": path_present,
                "sha256": hash_binary_file(path) if path_present else "",
                "bytes": path.stat().st_size if path_present else 0,
            }
        )
    return entries


def audit_decision_red_team_summary(
    path: Path,
    *,
    pass_key: str,
) -> dict[str, object]:
    try:
        payload = load_json(path) if path.exists() else {}
    except (json.JSONDecodeError, OSError):
        payload = {}
    cases = dict(payload.get("cases", {})) if isinstance(payload, dict) else {}
    return {
        "path": path.name,
        "present": path.exists(),
        "sha256": hash_binary_file(path) if path.exists() else "",
        "pass": bool(payload.get(pass_key)) if isinstance(payload, dict) else False,
        "case_count": int(payload.get("case_count", 0))
        if isinstance(payload, dict)
        else 0,
        "rejected_cases": sorted(
            name for name, case in cases.items() if bool(case.get("rejected"))
        ),
        "failed_cases": sorted(
            name for name, case in cases.items() if not bool(case.get("rejected"))
        ),
    }


def audit_challenge_transcript_hash_body(
    transcript: dict[str, object],
) -> dict[str, object]:
    return {
        key: value
        for key, value in transcript.items()
        if key not in {
            "audit_challenge_transcript_sha256",
            "result_path",
            "markdown_path",
        }
    }


def audit_challenge_transcript_family(
    output_dir: Path,
    family: str,
    result_name: str,
    *,
    pass_key: str,
    verifier_key: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    path = output_dir / result_name
    try:
        payload = load_json(path) if path.exists() else {}
    except (json.JSONDecodeError, OSError):
        payload = {}
    payload = payload if isinstance(payload, dict) else {}
    cases = dict(payload.get("cases", {}))
    rows: list[dict[str, object]] = []
    for name in sorted(cases):
        case = cases.get(name, {})
        case = case if isinstance(case, dict) else {}
        expected_failed = sorted(str(item) for item in case.get("expected_failed_checks", []))
        actual_failed = sorted(str(item) for item in case.get("actual_failed_checks", []))
        missing_expected = sorted(
            str(item) for item in case.get("missing_expected_failures", [])
        )
        rows.append(
            {
                "family": family,
                "case": name,
                "rejected": bool(case.get("rejected")),
                "verifier_key": verifier_key,
                "verifier_accepted": bool(case.get(verifier_key)),
                "expected_failed_checks": expected_failed,
                "actual_failed_checks": actual_failed,
                "missing_expected_failures": missing_expected,
            }
        )
    failed_cases = [row["case"] for row in rows if not bool(row["rejected"])]
    summary = {
        "family": family,
        "result_path": result_name,
        "result_present": path.exists(),
        "result_sha256": hash_binary_file(path) if path.exists() else "",
        "result_pass": bool(payload.get(pass_key)),
        "declared_case_count": int(payload.get("case_count", 0)),
        "case_count": len(rows),
        "rejected_count": sum(1 for row in rows if bool(row["rejected"])),
        "failed_cases": failed_cases,
    }
    return summary, rows


def audit_challenge_transcript_markdown(transcript: dict[str, object]) -> str:
    lines = [
        "# PeTTaChainer Audit Challenge Transcript",
        "",
        f"- Verdict: `{transcript.get('verdict', '')}`",
        f"- Transcript SHA-256: `{transcript.get('audit_challenge_transcript_sha256', '')}`",
        f"- Required cases: `{transcript.get('required_case_count', 0)}`",
        f"- Observed cases: `{transcript.get('observed_case_count', 0)}`",
        f"- Rejected cases: `{transcript.get('rejected_case_count', 0)}`",
        f"- Gauntlet SHA-256: `{transcript.get('audit_gauntlet_sha256', '')}`",
        "",
        "## Family Summary",
        "",
        "| Family | Result | Cases | Rejected | Source hash |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for family in list(transcript.get("families", [])):
        if not isinstance(family, dict):
            continue
        lines.append(
            "| "
            f"{markdown_cell(family.get('family', ''))} | "
            f"{'PASS' if family.get('result_pass') else 'FAIL'} | "
            f"{int(family.get('case_count', 0))} | "
            f"{int(family.get('rejected_count', 0))} | "
            f"{markdown_cell(family.get('result_sha256', ''))} |"
        )
    lines.extend(
        [
            "",
            "## Challenge Cases",
            "",
            "| Family | Case | Rejected | Expected failed checks | Actual failed checks |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for case in list(transcript.get("cases", [])):
        if not isinstance(case, dict):
            continue
        lines.append(
            "| "
            f"{markdown_cell(case.get('family', ''))} | "
            f"{markdown_cell(case.get('case', ''))} | "
            f"{'PASS' if case.get('rejected') else 'FAIL'} | "
            f"{markdown_cell(', '.join(str(item) for item in case.get('expected_failed_checks', [])))} | "
            f"{markdown_cell(', '.join(str(item) for item in case.get('actual_failed_checks', [])))} |"
        )
    lines.append("")
    return "\n".join(lines)


def build_audit_challenge_transcript(output_dir: str | Path) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    family_specs = [
        (
            "audit_capsule",
            "showcase-audit-capsule-red-team-result.json",
            "audit_capsule_red_team_pass",
            "audit_capsule_verified",
        ),
        (
            "audit_capsule_archive",
            "showcase-audit-capsule-archive-red-team-result.json",
            "audit_capsule_archive_red_team_pass",
            "audit_capsule_archive_verified",
        ),
    ]
    families: list[dict[str, object]] = []
    cases: list[dict[str, object]] = []
    for family, result_name, pass_key, verifier_key in family_specs:
        summary, rows = audit_challenge_transcript_family(
            output_dir,
            family,
            result_name,
            pass_key=pass_key,
            verifier_key=verifier_key,
        )
        families.append(summary)
        cases.extend(rows)
    required_cases = audit_policy_required_red_team_cases()
    required_case_ids = sorted(
        f"{family}:{name}"
        for family, names in required_cases.items()
        for name in names
    )
    observed_case_ids = sorted(
        f"{case.get('family')}:{case.get('case')}" for case in cases
    )
    all_required_observed = set(required_case_ids).issubset(set(observed_case_ids))
    all_observed_rejected = bool(cases) and all(
        bool(case.get("rejected")) for case in cases
    )
    no_missing_expected_failures = all(
        not list(case.get("missing_expected_failures", [])) for case in cases
    )
    family_results_pass = bool(families) and all(
        bool(family.get("result_pass")) for family in families
    )
    gauntlet_path = output_dir / AUDIT_DECISION_GAUNTLET
    decision_verifier_path = output_dir / AUDIT_DECISION_STANDALONE_VERIFIER
    body = {
        "artifact_kind": "pettachainer_showcase_audit_challenge_transcript",
        "transcript_version": 1,
        "subject_base": "external-red-team-results",
        "verdict": "PASS"
        if (
            family_results_pass
            and all_required_observed
            and all_observed_rejected
            and no_missing_expected_failures
        )
        else "FAIL",
        "families": families,
        "cases": cases,
        "required_red_team_cases": required_cases,
        "required_case_count": len(required_case_ids),
        "observed_case_count": len(observed_case_ids),
        "rejected_case_count": sum(1 for case in cases if bool(case.get("rejected"))),
        "coverage": {
            "all_required_cases_observed": all_required_observed,
            "all_observed_cases_rejected": all_observed_rejected,
            "no_missing_expected_failures": no_missing_expected_failures,
            "family_results_pass": family_results_pass,
        },
        "standalone_decision_verifier_path": AUDIT_DECISION_STANDALONE_VERIFIER,
        "standalone_decision_verifier_sha256": hash_binary_file(decision_verifier_path)
        if decision_verifier_path.exists()
        else "",
        "audit_gauntlet_path": AUDIT_DECISION_GAUNTLET,
        "audit_gauntlet_sha256": hash_binary_file(gauntlet_path)
        if gauntlet_path.exists()
        else "",
        "verification_commands": [
            f"python {AUDIT_DECISION_GAUNTLET} .",
            f"python -m pettachainer.benchmarks.verify_showcase . --verify-audit-challenge-transcript {AUDIT_CHALLENGE_TRANSCRIPT_JSON} --strict",
        ],
    }
    return {**body, "audit_challenge_transcript_sha256": canonical_object_sha256(body)}


def write_audit_challenge_transcript(
    output_dir: str | Path,
    result_path: str | Path | None = None,
    *,
    markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    result_path = (
        Path(result_path).resolve()
        if result_path is not None
        else output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON
    )
    markdown_path = (
        Path(markdown_path).resolve()
        if markdown_path is not None
        else output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN
    )
    transcript = build_audit_challenge_transcript(output_dir)
    write_json(result_path, transcript)
    markdown_path.write_text(
        audit_challenge_transcript_markdown(transcript),
        encoding="utf-8",
    )
    return {
        **transcript,
        "result_path": str(result_path),
        "markdown_path": str(markdown_path),
    }


def verify_audit_challenge_transcript(
    output_dir: str | Path,
    transcript_path: str | Path | None = None,
    *,
    markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    transcript_path = (
        Path(transcript_path).resolve()
        if transcript_path is not None
        else output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON
    )
    markdown_path = (
        Path(markdown_path).resolve()
        if markdown_path is not None
        else output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN
    )
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if transcript_path.exists():
            loaded = load_json(transcript_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    expected = build_audit_challenge_transcript(output_dir)
    actual_body = audit_challenge_transcript_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    expected_markdown = audit_challenge_transcript_markdown(expected)
    actual_markdown = (
        markdown_path.read_text(encoding="utf-8") if markdown_path.exists() else ""
    )
    checks = {
        "audit_challenge_transcript_present": transcript_path.exists(),
        "audit_challenge_transcript_json_valid": json_valid,
        "audit_challenge_transcript_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_challenge_transcript",
        "audit_challenge_transcript_hash_matches": actual.get(
            "audit_challenge_transcript_sha256"
        )
        == actual_hash,
        "audit_challenge_transcript_matches_current_artifacts": bool(actual)
        and actual == expected,
        "audit_challenge_transcript_verdict_pass": actual.get("verdict") == "PASS",
        "audit_challenge_transcript_markdown_present": markdown_path.exists(),
        "audit_challenge_transcript_markdown_matches": actual_markdown
        == expected_markdown,
    }
    checks["audit_challenge_transcript_verified"] = all(checks.values())
    return {
        "audit_challenge_transcript_path": str(transcript_path),
        "audit_challenge_transcript_markdown_path": str(markdown_path),
        "audit_challenge_transcript_file_sha256": hash_binary_file(transcript_path)
        if transcript_path.exists()
        else "",
        "audit_challenge_transcript_sha256": actual.get(
            "audit_challenge_transcript_sha256",
            "",
        ),
        "expected_audit_challenge_transcript_sha256": expected.get(
            "audit_challenge_transcript_sha256",
            "",
        ),
        "verdict": actual.get("verdict", ""),
        "checks": checks,
    }


def safe_audit_decision_verifier(
    verified_key: str,
    verifier: object,
    *args: object,
    **kwargs: object,
) -> dict[str, object]:
    try:
        result = verifier(*args, **kwargs)  # type: ignore[operator]
        return result if isinstance(result, dict) else {"checks": {verified_key: False}}
    except (
        json.JSONDecodeError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        return {
            "checks": {verified_key: False},
            "error": f"{type(exc).__name__}: {exc}",
        }


def build_audit_decision_certificate(
    output_dir: str | Path,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    *,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    capsule_path = (
        Path(capsule_path).resolve()
        if capsule_path is not None
        else output_dir / "showcase-audit-capsule.json"
    )
    archive_path = (
        Path(archive_path).resolve()
        if archive_path is not None
        else output_dir / "showcase-audit-capsule.zip"
    )
    capsule_markdown_path = (
        Path(capsule_markdown_path).resolve()
        if capsule_markdown_path is not None
        else capsule_path.with_suffix(".md")
    )
    try:
        capsule = load_json(capsule_path)
    except (json.JSONDecodeError, OSError):
        capsule = {}
    roles = dict(capsule.get("artifact_roles", {})) if isinstance(capsule, dict) else {}
    decision_verifier_path = output_dir / AUDIT_DECISION_STANDALONE_VERIFIER
    expected_decision_verifier_text = audit_decision_standalone_verifier_text()
    gauntlet_path = output_dir / AUDIT_DECISION_GAUNTLET
    expected_gauntlet_text = audit_decision_gauntlet_text()
    challenge_transcript_path = output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON
    challenge_transcript_markdown_path = output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN
    packet_path = output_dir / str(roles.get("forensic_packet", ""))
    try:
        packet = load_json(packet_path) if packet_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        packet = {}
    policy_path = output_dir / str(roles.get("audit_policy", AUDIT_CAPSULE_AUDIT_POLICY))
    runtime_path = output_dir / str(
        roles.get("runtime_manifest", AUDIT_CAPSULE_RUNTIME_MANIFEST)
    )
    receipt_path = output_dir / str(
        roles.get("audit_receipt", AUDIT_CAPSULE_AUDIT_RECEIPT)
    )
    provenance_path = output_dir / str(
        roles.get("provenance_attestation", AUDIT_CAPSULE_PROVENANCE_ATTESTATION)
    )
    capsule_details = safe_audit_decision_verifier(
        "audit_capsule_verified",
        verify_audit_capsule,
        output_dir,
        capsule_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    archive_details = safe_audit_decision_verifier(
        "audit_capsule_archive_verified",
        verify_audit_capsule_archive,
        output_dir,
        archive_path,
        capsule_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    policy_details = safe_audit_decision_verifier(
        "audit_policy_verified",
        verify_audit_policy,
        output_dir,
        policy_path,
        capsule=capsule if isinstance(capsule, dict) else None,
    )
    runtime_details = safe_audit_decision_verifier(
        "runtime_manifest_verified",
        verify_runtime_manifest,
        output_dir,
        runtime_path,
    )
    receipt_details = safe_audit_decision_verifier(
        "audit_receipt_verified",
        verify_audit_receipt,
        output_dir,
        receipt_path,
    )
    provenance_details = safe_audit_decision_verifier(
        "provenance_attestation_verified",
        verify_audit_provenance_attestation,
        output_dir,
        provenance_path,
    )
    challenge_transcript_details = safe_audit_decision_verifier(
        "audit_challenge_transcript_verified",
        verify_audit_challenge_transcript,
        output_dir,
        challenge_transcript_path,
        markdown_path=challenge_transcript_markdown_path,
    )
    try:
        policy_payload = load_json(policy_path) if policy_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        policy_payload = {}
    expected_red_team_cases = audit_policy_required_red_team_cases()
    policy_red_team_cases = (
        dict(policy_payload.get("required_red_team_cases", {}))
        if isinstance(policy_payload, dict)
        else {}
    )
    capsule_red_team = audit_decision_red_team_summary(
        output_dir / "showcase-audit-capsule-red-team-result.json",
        pass_key="audit_capsule_red_team_pass",
    )
    archive_red_team = audit_decision_red_team_summary(
        output_dir / "showcase-audit-capsule-archive-red-team-result.json",
        pass_key="audit_capsule_archive_red_team_pass",
    )
    subjects = audit_decision_subject_entries(
        output_dir,
        capsule_path,
        archive_path,
        capsule_markdown_path,
    )
    checks = {
        "audit_capsule_verified": bool(
            dict(capsule_details.get("checks", {})).get("audit_capsule_verified")
        ),
        "audit_capsule_archive_verified": bool(
            dict(archive_details.get("checks", {})).get(
                "audit_capsule_archive_verified"
            )
        ),
        "audit_policy_verified": bool(
            dict(policy_details.get("checks", {})).get("audit_policy_verified")
        ),
        "runtime_manifest_verified": bool(
            dict(runtime_details.get("checks", {})).get("runtime_manifest_verified")
        ),
        "audit_receipt_verified": bool(
            dict(receipt_details.get("checks", {})).get("audit_receipt_verified")
        ),
        "provenance_attestation_verified": bool(
            dict(provenance_details.get("checks", {})).get(
                "provenance_attestation_verified"
            )
        ),
        "policy_declares_required_red_team_cases": (
            policy_red_team_cases == expected_red_team_cases
        ),
        "audit_capsule_red_team_pass": bool(capsule_red_team["pass"]),
        "audit_capsule_archive_red_team_pass": bool(archive_red_team["pass"]),
        "audit_capsule_red_team_covers_required_cases": set(
            expected_red_team_cases["audit_capsule"]
        ).issubset(set(capsule_red_team["rejected_cases"])),
        "audit_capsule_archive_red_team_covers_required_cases": set(
            expected_red_team_cases["audit_capsule_archive"]
        ).issubset(set(archive_red_team["rejected_cases"])),
        "all_subjects_present": bool(subjects)
        and all(bool(subject["present"]) for subject in subjects),
        "standalone_decision_verifier_present": decision_verifier_path.exists()
        and decision_verifier_path.is_file(),
        "standalone_decision_verifier_matches_expected": (
            decision_verifier_path.exists()
            and decision_verifier_path.read_text(encoding="utf-8")
            == expected_decision_verifier_text
        ),
        "audit_gauntlet_present": gauntlet_path.exists()
        and gauntlet_path.is_file(),
        "audit_gauntlet_matches_expected": (
            gauntlet_path.exists()
            and gauntlet_path.read_text(encoding="utf-8") == expected_gauntlet_text
        ),
        "audit_challenge_transcript_verified": bool(
            dict(challenge_transcript_details.get("checks", {})).get(
                "audit_challenge_transcript_verified"
            )
        ),
    }
    verdict = "PASS" if all(checks.values()) else "FAIL"
    body = {
        "artifact_kind": "pettachainer_showcase_audit_decision",
        "decision_version": 1,
        "subject_base": "external-over-sealed-capsule",
        "verdict": verdict,
        "checks": checks,
        "audit_capsule_path": audit_decision_relative_path(capsule_path, output_dir),
        "audit_capsule_markdown_path": audit_decision_relative_path(
            capsule_markdown_path,
            output_dir,
        ),
        "audit_capsule_archive_path": audit_decision_relative_path(
            archive_path,
            output_dir,
        ),
        "audit_capsule_sha256": capsule.get("audit_capsule_sha256", "")
        if isinstance(capsule, dict)
        else "",
        "audit_capsule_archive_sha256": archive_details.get("archive_sha256", ""),
        "audit_policy_sha256": policy_details.get("audit_policy_sha256", ""),
        "runtime_manifest_sha256": runtime_details.get("runtime_manifest_sha256", ""),
        "audit_receipt_sha256": receipt_details.get("audit_receipt_sha256", ""),
        "audit_receipt_subject_merkle_root_sha256": receipt_details.get(
            "subject_merkle_root_sha256",
            "",
        ),
        "provenance_sha256": provenance_details.get("provenance_sha256", ""),
        "packet_root_sha256": packet.get("packet_root_sha256", "")
        if isinstance(packet, dict)
        else "",
        "file_manifest_root_sha256": capsule.get("file_manifest_root_sha256", "")
        if isinstance(capsule, dict)
        else "",
        "transparency_log_root_sha256": capsule.get(
            "transparency_log_root_sha256",
            "",
        )
        if isinstance(capsule, dict)
        else "",
        "file_count": int(capsule.get("file_count", 0))
        if isinstance(capsule, dict)
        else 0,
        "archive_entry_count": int(archive_details.get("archive_entry_count", 0)),
        "subject_count": len(subjects),
        "subject_manifest_sha256": canonical_object_sha256(subjects),
        "standalone_decision_verifier_path": AUDIT_DECISION_STANDALONE_VERIFIER,
        "standalone_decision_verifier_sha256": hash_binary_file(
            decision_verifier_path
        )
        if decision_verifier_path.exists()
        else "",
        "audit_gauntlet_path": AUDIT_DECISION_GAUNTLET,
        "audit_gauntlet_sha256": hash_binary_file(gauntlet_path)
        if gauntlet_path.exists()
        else "",
        "audit_challenge_transcript_path": AUDIT_CHALLENGE_TRANSCRIPT_JSON,
        "audit_challenge_transcript_markdown_path": (
            AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN
        ),
        "audit_challenge_transcript_sha256": challenge_transcript_details.get(
            "audit_challenge_transcript_sha256",
            "",
        ),
        "audit_challenge_transcript_file_sha256": (
            challenge_transcript_details.get(
                "audit_challenge_transcript_file_sha256",
                "",
            )
        ),
        "audit_challenge_transcript_rejected_cases": int(
            build_audit_challenge_transcript(output_dir).get(
                "rejected_case_count",
                0,
            )
        ),
        "subjects": subjects,
        "red_team_summary": {
            "audit_capsule": capsule_red_team,
            "audit_capsule_archive": archive_red_team,
        },
        "verification_commands": [
            f"python {AUDIT_CAPSULE_STANDALONE_VERIFIER} .",
            f"python {AUDIT_CAPSULE_STANDALONE_ARCHIVE_VERIFIER} {audit_decision_relative_path(archive_path, output_dir)}",
            f"python {AUDIT_DECISION_STANDALONE_VERIFIER} .",
            f"python {AUDIT_DECISION_GAUNTLET} .",
            f"python -m pettachainer.benchmarks.verify_showcase . --verify-audit-challenge-transcript {AUDIT_CHALLENGE_TRANSCRIPT_JSON} --strict",
            f"python -m pettachainer.benchmarks.verify_showcase . --verify-audit-decision {AUDIT_DECISION_CERTIFICATE} --strict",
        ],
    }
    return {**body, "audit_decision_sha256": canonical_object_sha256(body)}


def write_audit_decision_certificate(
    output_dir: str | Path,
    result_path: str | Path | None = None,
    *,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    result_path = (
        Path(result_path).resolve()
        if result_path is not None
        else output_dir / AUDIT_DECISION_CERTIFICATE
    )
    write_audit_decision_standalone_verifier(output_dir)
    write_audit_decision_gauntlet(output_dir)
    write_audit_challenge_transcript(output_dir)
    certificate = build_audit_decision_certificate(
        output_dir,
        capsule_path,
        archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    write_json(result_path, certificate)
    return {**certificate, "result_path": str(result_path)}


def verify_audit_decision_certificate(
    output_dir: str | Path,
    certificate_path: str | Path | None = None,
    *,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    certificate_path = (
        Path(certificate_path).resolve()
        if certificate_path is not None
        else output_dir / AUDIT_DECISION_CERTIFICATE
    )
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if certificate_path.exists():
            loaded = load_json(certificate_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    expected = build_audit_decision_certificate(
        output_dir,
        capsule_path,
        archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    actual_body = audit_decision_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    checks = {
        "audit_decision_present": certificate_path.exists(),
        "audit_decision_json_valid": json_valid,
        "audit_decision_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_decision",
        "audit_decision_hash_matches": actual.get("audit_decision_sha256")
        == actual_hash,
        "audit_decision_matches_current_artifacts": bool(actual)
        and actual == expected,
        "audit_decision_verdict_pass": actual.get("verdict") == "PASS",
        "audit_decision_subject_manifest_matches": actual.get(
            "subject_manifest_sha256"
        )
        == expected.get("subject_manifest_sha256"),
    }
    checks["audit_decision_verified"] = all(checks.values())
    return {
        "audit_decision_path": str(certificate_path),
        "audit_decision_file_sha256": hash_binary_file(certificate_path)
        if certificate_path.exists()
        else "",
        "audit_decision_sha256": actual.get("audit_decision_sha256", ""),
        "expected_audit_decision_sha256": expected.get(
            "audit_decision_sha256",
            "",
        ),
        "verdict": actual.get("verdict", ""),
        "checks": checks,
    }


def audit_board_hash_body(board: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in board.items()
        if key not in {"audit_board_sha256", "result_path", "markdown_path"}
    }


def audit_board_markdown(board: dict[str, object]) -> str:
    lines = [
        "# PeTTaChainer Showcase Audit Board",
        "",
        f"- Verdict: `{board.get('verdict', '')}`",
        f"- Audit board SHA-256: `{board.get('audit_board_sha256', '')}`",
        f"- Audit decision SHA-256: `{board.get('audit_decision_sha256', '')}`",
        f"- Challenge transcript SHA-256: `{board.get('audit_challenge_transcript_sha256', '')}`",
        f"- Packet root: `{board.get('packet_root_sha256', '')}`",
        f"- Capsule SHA-256: `{board.get('audit_capsule_sha256', '')}`",
        f"- Archive SHA-256: `{board.get('audit_capsule_archive_sha256', '')}`",
        f"- Decision subjects: `{board.get('subject_count', 0)}`",
        f"- Red-team rejected cases: `{board.get('red_team_rejected_cases', 0)}`",
        "",
        "## Control Matrix",
        "",
        "| Control | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for control in list(board.get("controls", [])):
        if not isinstance(control, dict):
            continue
        lines.append(
            "| "
            f"{markdown_cell(control.get('name', ''))} | "
            f"{'PASS' if control.get('pass') else 'FAIL'} | "
            f"{markdown_cell(control.get('evidence', ''))} |"
        )
    lines.extend(
        [
            "",
            "## Portable Commands",
            "",
        ]
    )
    for command in list(board.get("verification_commands", [])):
        lines.append(f"- `{markdown_cell(command)}`")
    lines.append("")
    return "\n".join(lines)


def audit_board_control(
    name: str,
    passed: bool,
    evidence: str,
) -> dict[str, object]:
    return {"name": name, "pass": bool(passed), "evidence": evidence}


def build_audit_board(
    output_dir: str | Path,
    decision_path: str | Path | None = None,
    *,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    decision_path = (
        Path(decision_path).resolve()
        if decision_path is not None
        else output_dir / AUDIT_DECISION_CERTIFICATE
    )
    decision: dict[str, object] = {}
    try:
        if decision_path.exists():
            loaded = load_json(decision_path)
            if isinstance(loaded, dict):
                decision = loaded
    except (json.JSONDecodeError, OSError):
        decision = {}
    capsule_path = (
        Path(capsule_path).resolve()
        if capsule_path is not None
        else output_dir / str(decision.get("audit_capsule_path", "showcase-audit-capsule.json"))
    )
    archive_path = (
        Path(archive_path).resolve()
        if archive_path is not None
        else output_dir / str(decision.get("audit_capsule_archive_path", "showcase-audit-capsule.zip"))
    )
    capsule_markdown_path = (
        Path(capsule_markdown_path).resolve()
        if capsule_markdown_path is not None
        else output_dir / str(decision.get("audit_capsule_markdown_path", "showcase-audit-capsule.md"))
    )
    try:
        capsule = load_json(capsule_path) if capsule_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        capsule = {}
    decision_verification = verify_audit_decision_certificate(
        output_dir,
        decision_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    decision_checks = dict(decision.get("checks", {}))
    decision_verification_checks = dict(decision_verification.get("checks", {}))
    red_team_summary = dict(decision.get("red_team_summary", {}))
    capsule_red_team = dict(red_team_summary.get("audit_capsule", {}))
    archive_red_team = dict(red_team_summary.get("audit_capsule_archive", {}))
    red_team_rejected_cases = len(
        list(capsule_red_team.get("rejected_cases", []))
    ) + len(list(archive_red_team.get("rejected_cases", [])))
    verification_commands = list(
        dict.fromkeys(str(command) for command in list(decision.get("verification_commands", [])))
    )
    board_command = f"python -m pettachainer.benchmarks.verify_showcase . --verify-audit-board {AUDIT_BOARD_JSON} --strict"
    if board_command not in verification_commands:
        verification_commands.append(board_command)
    controls = [
        audit_board_control(
            "decision certificate recomputes",
            bool(decision_verification_checks.get("audit_decision_verified")),
            str(decision_verification.get("audit_decision_sha256", "")),
        ),
        audit_board_control(
            "sealed capsule verifies",
            bool(decision_checks.get("audit_capsule_verified")),
            str(decision.get("audit_capsule_sha256", "")),
        ),
        audit_board_control(
            "deterministic archive verifies",
            bool(decision_checks.get("audit_capsule_archive_verified")),
            str(decision.get("audit_capsule_archive_sha256", "")),
        ),
        audit_board_control(
            "runtime manifest verifies",
            bool(decision_checks.get("runtime_manifest_verified")),
            str(decision.get("runtime_manifest_sha256", "")),
        ),
        audit_board_control(
            "provenance and receipt verify",
            bool(decision_checks.get("provenance_attestation_verified"))
            and bool(decision_checks.get("audit_receipt_verified")),
            str(decision.get("audit_receipt_subject_merkle_root_sha256", "")),
        ),
        audit_board_control(
            "portable decision verifier attested",
            bool(decision_checks.get("standalone_decision_verifier_matches_expected")),
            str(decision.get("standalone_decision_verifier_sha256", "")),
        ),
        audit_board_control(
            "portable tamper gauntlet attested",
            bool(decision_checks.get("audit_gauntlet_matches_expected")),
            str(decision.get("audit_gauntlet_sha256", "")),
        ),
        audit_board_control(
            "challenge transcript verifies",
            bool(decision_checks.get("audit_challenge_transcript_verified"))
            and int(decision.get("audit_challenge_transcript_rejected_cases", 0))
            >= red_team_rejected_cases,
            str(decision.get("audit_challenge_transcript_sha256", "")),
        ),
        audit_board_control(
            "red-team policy coverage",
            bool(decision_checks.get("audit_capsule_red_team_covers_required_cases"))
            and bool(
                decision_checks.get(
                    "audit_capsule_archive_red_team_covers_required_cases"
                )
            )
            and red_team_rejected_cases >= 19,
            f"{red_team_rejected_cases} rejected forged cases",
        ),
        audit_board_control(
            "external subjects present",
            bool(decision_checks.get("all_subjects_present"))
            and int(decision.get("subject_count", 0)) >= 11,
            str(decision.get("subject_manifest_sha256", "")),
        ),
        audit_board_control(
            "transparency log anchored",
            bool(decision.get("transparency_log_root_sha256"))
            and int(capsule.get("transparency_log_entry_count", 0)) > 0
            if isinstance(capsule, dict)
            else False,
            str(decision.get("transparency_log_root_sha256", "")),
        ),
    ]
    verdict = "PASS" if controls and all(bool(control["pass"]) for control in controls) else "FAIL"
    body = {
        "artifact_kind": "pettachainer_showcase_audit_board",
        "board_version": 1,
        "verdict": verdict,
        "decision_path": audit_decision_relative_path(decision_path, output_dir),
        "audit_decision_sha256": decision.get("audit_decision_sha256", ""),
        "audit_capsule_sha256": decision.get("audit_capsule_sha256", ""),
        "audit_capsule_archive_sha256": decision.get(
            "audit_capsule_archive_sha256",
            "",
        ),
        "packet_root_sha256": decision.get("packet_root_sha256", ""),
        "file_manifest_root_sha256": decision.get("file_manifest_root_sha256", ""),
        "transparency_log_root_sha256": decision.get(
            "transparency_log_root_sha256",
            "",
        ),
        "runtime_manifest_sha256": decision.get("runtime_manifest_sha256", ""),
        "audit_receipt_sha256": decision.get("audit_receipt_sha256", ""),
        "provenance_sha256": decision.get("provenance_sha256", ""),
        "standalone_decision_verifier_sha256": decision.get(
            "standalone_decision_verifier_sha256",
            "",
        ),
        "audit_gauntlet_sha256": decision.get("audit_gauntlet_sha256", ""),
        "audit_challenge_transcript_sha256": decision.get(
            "audit_challenge_transcript_sha256",
            "",
        ),
        "audit_challenge_transcript_rejected_cases": int(
            decision.get("audit_challenge_transcript_rejected_cases", 0)
        ),
        "subject_count": int(decision.get("subject_count", 0)),
        "capsule_file_count": int(decision.get("file_count", 0)),
        "archive_entry_count": int(decision.get("archive_entry_count", 0)),
        "transparency_log_entry_count": int(
            capsule.get("transparency_log_entry_count", 0)
        )
        if isinstance(capsule, dict)
        else 0,
        "red_team_rejected_cases": red_team_rejected_cases,
        "controls": controls,
        "verification_commands": verification_commands,
    }
    return {**body, "audit_board_sha256": canonical_object_sha256(body)}


def write_audit_board(
    output_dir: str | Path,
    result_path: str | Path | None = None,
    *,
    markdown_path: str | Path | None = None,
    decision_path: str | Path | None = None,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    result_path = (
        Path(result_path).resolve()
        if result_path is not None
        else output_dir / AUDIT_BOARD_JSON
    )
    markdown_path = (
        Path(markdown_path).resolve()
        if markdown_path is not None
        else output_dir / AUDIT_BOARD_MARKDOWN
    )
    board = build_audit_board(
        output_dir,
        decision_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    write_json(result_path, board)
    markdown_path.write_text(audit_board_markdown(board), encoding="utf-8")
    return {**board, "result_path": str(result_path), "markdown_path": str(markdown_path)}


def verify_audit_board(
    output_dir: str | Path,
    board_path: str | Path | None = None,
    *,
    markdown_path: str | Path | None = None,
    decision_path: str | Path | None = None,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    board_path = (
        Path(board_path).resolve()
        if board_path is not None
        else output_dir / AUDIT_BOARD_JSON
    )
    markdown_path = (
        Path(markdown_path).resolve()
        if markdown_path is not None
        else output_dir / AUDIT_BOARD_MARKDOWN
    )
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if board_path.exists():
            loaded = load_json(board_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    expected = build_audit_board(
        output_dir,
        decision_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    actual_body = audit_board_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    expected_markdown = audit_board_markdown(expected)
    actual_markdown = (
        markdown_path.read_text(encoding="utf-8") if markdown_path.exists() else ""
    )
    checks = {
        "audit_board_present": board_path.exists(),
        "audit_board_json_valid": json_valid,
        "audit_board_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_board",
        "audit_board_hash_matches": actual.get("audit_board_sha256")
        == actual_hash,
        "audit_board_matches_current_artifacts": bool(actual)
        and actual == expected,
        "audit_board_verdict_pass": actual.get("verdict") == "PASS",
        "audit_board_markdown_present": markdown_path.exists(),
        "audit_board_markdown_matches": actual_markdown == expected_markdown,
    }
    checks["audit_board_verified"] = all(checks.values())
    return {
        "audit_board_path": str(board_path),
        "audit_board_markdown_path": str(markdown_path),
        "audit_board_file_sha256": hash_binary_file(board_path)
        if board_path.exists()
        else "",
        "audit_board_sha256": actual.get("audit_board_sha256", ""),
        "expected_audit_board_sha256": expected.get("audit_board_sha256", ""),
        "verdict": actual.get("verdict", ""),
        "checks": checks,
    }


def audit_facts_hash_body(facts: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in facts.items()
        if key not in {"audit_facts_sha256", "result_path", "metta_file_path"}
    }


def metta_string(value: object) -> str:
    return json.dumps(str(value))


def audit_facts_metta_text(facts: dict[str, object]) -> str:
    status = "PASS" if facts.get("verdict") == "PASS" else "FAIL"
    lines = [
        "(= (audit-facts-artifact-kind) pettachainer-showcase-audit-facts)",
        f"(= (audit-facts-verdict) {status})",
        f"(= (audit-facts-board-sha256) {metta_string(facts.get('audit_board_sha256', ''))})",
        f"(= (audit-facts-decision-sha256) {metta_string(facts.get('audit_decision_sha256', ''))})",
        f"(= (audit-facts-challenge-transcript-sha256) {metta_string(facts.get('audit_challenge_transcript_sha256', ''))})",
        f"(= (audit-facts-packet-root-sha256) {metta_string(facts.get('packet_root_sha256', ''))})",
        f"(= (audit-facts-red-team-rejected-cases) {int(facts.get('red_team_rejected_cases', 0))})",
        f"(= (audit-facts-challenge-rejected-cases) {int(facts.get('audit_challenge_transcript_rejected_cases', 0))})",
        f"(= (audit-facts-control-count) {int(facts.get('control_count', 0))})",
        f"(= (audit-facts-subject-count) {int(facts.get('subject_count', 0))})",
        f"(= (audit-facts-archive-entry-count) {int(facts.get('archive_entry_count', 0))})",
        f"(= (audit-facts-transparency-entry-count) {int(facts.get('transparency_log_entry_count', 0))})",
    ]
    for control in list(facts.get("controls", [])):
        if not isinstance(control, dict):
            continue
        name = metta_string(control.get("name", ""))
        control_status = "PASS" if control.get("pass") else "FAIL"
        lines.append(f"(= (audit-control-status {name}) {control_status})")
        lines.append(
            f"(= (audit-control-evidence {name}) {metta_string(control.get('evidence', ''))})"
        )
    lines.extend(
        [
            f"!(test (audit-facts-verdict) {status})",
            f"!(test (audit-facts-board-sha256) {metta_string(facts.get('audit_board_sha256', ''))})",
            f"!(test (audit-facts-red-team-rejected-cases) {int(facts.get('red_team_rejected_cases', 0))})",
            f"!(test (audit-facts-challenge-rejected-cases) {int(facts.get('audit_challenge_transcript_rejected_cases', 0))})",
            f"!(test (audit-facts-control-count) {int(facts.get('control_count', 0))})",
            '!(test (audit-control-status "decision certificate recomputes") PASS)',
            '!(test (audit-control-status "challenge transcript verifies") PASS)',
            '!(test (audit-control-status "red-team policy coverage") PASS)',
            "",
        ]
    )
    return "\n".join(lines)


def build_audit_facts(
    output_dir: str | Path,
    board_path: str | Path | None = None,
    *,
    decision_path: str | Path | None = None,
    transcript_path: str | Path | None = None,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    board_path = (
        Path(board_path).resolve()
        if board_path is not None
        else output_dir / AUDIT_BOARD_JSON
    )
    board: dict[str, object] = {}
    try:
        if board_path.exists():
            loaded = load_json(board_path)
            if isinstance(loaded, dict):
                board = loaded
    except (json.JSONDecodeError, OSError):
        board = {}
    decision_path = (
        Path(decision_path).resolve()
        if decision_path is not None
        else output_dir / str(board.get("decision_path", AUDIT_DECISION_CERTIFICATE))
    )
    decision: dict[str, object] = {}
    try:
        if decision_path.exists():
            loaded = load_json(decision_path)
            if isinstance(loaded, dict):
                decision = loaded
    except (json.JSONDecodeError, OSError):
        decision = {}
    transcript_path = (
        Path(transcript_path).resolve()
        if transcript_path is not None
        else output_dir
        / str(decision.get("audit_challenge_transcript_path", AUDIT_CHALLENGE_TRANSCRIPT_JSON))
    )
    board_details = verify_audit_board(
        output_dir,
        board_path,
        decision_path=decision_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    transcript_details = verify_audit_challenge_transcript(
        output_dir,
        transcript_path,
    )
    board_checks = dict(board_details.get("checks", {}))
    transcript_checks = dict(transcript_details.get("checks", {}))
    controls = [
        {
            "name": str(control.get("name", "")),
            "pass": bool(control.get("pass")),
            "evidence": str(control.get("evidence", "")),
        }
        for control in list(board.get("controls", []))
        if isinstance(control, dict)
    ]
    controls_pass = bool(controls) and all(bool(control["pass"]) for control in controls)
    body = {
        "artifact_kind": "pettachainer_showcase_audit_facts",
        "facts_version": 1,
        "subject_base": "audit-board-to-petta",
        "verdict": "PASS"
        if (
            board.get("verdict") == "PASS"
            and board_checks.get("audit_board_verified")
            and transcript_checks.get("audit_challenge_transcript_verified")
            and controls_pass
        )
        else "FAIL",
        "board_path": audit_decision_relative_path(board_path, output_dir),
        "decision_path": audit_decision_relative_path(decision_path, output_dir),
        "challenge_transcript_path": audit_decision_relative_path(
            transcript_path,
            output_dir,
        ),
        "metta_path": AUDIT_FACTS_METTA,
        "audit_board_sha256": board.get("audit_board_sha256", ""),
        "audit_decision_sha256": board.get("audit_decision_sha256", ""),
        "audit_challenge_transcript_sha256": board.get(
            "audit_challenge_transcript_sha256",
            "",
        ),
        "packet_root_sha256": board.get("packet_root_sha256", ""),
        "red_team_rejected_cases": int(board.get("red_team_rejected_cases", 0)),
        "audit_challenge_transcript_rejected_cases": int(
            board.get("audit_challenge_transcript_rejected_cases", 0)
        ),
        "control_count": len(controls),
        "subject_count": int(board.get("subject_count", 0)),
        "archive_entry_count": int(board.get("archive_entry_count", 0)),
        "transparency_log_entry_count": int(
            board.get("transparency_log_entry_count", 0)
        ),
        "controls": controls,
        "checks": {
            "audit_board_verified": bool(board_checks.get("audit_board_verified")),
            "audit_challenge_transcript_verified": bool(
                transcript_checks.get("audit_challenge_transcript_verified")
            ),
            "all_controls_pass": controls_pass,
            "board_verdict_pass": board.get("verdict") == "PASS",
        },
        "verification_commands": [
            f"python -m pettachainer.benchmarks.verify_showcase . --verify-audit-facts {AUDIT_FACTS_JSON} --strict",
            f"../PeTTa/run.sh {AUDIT_FACTS_METTA}",
        ],
    }
    metta_text = audit_facts_metta_text(body)
    body["metta_source_sha256"] = hashlib.sha256(metta_text.encode("utf-8")).hexdigest()
    return {**body, "audit_facts_sha256": canonical_object_sha256(body)}


def write_audit_facts(
    output_dir: str | Path,
    result_path: str | Path | None = None,
    *,
    metta_path: str | Path | None = None,
    board_path: str | Path | None = None,
    decision_path: str | Path | None = None,
    transcript_path: str | Path | None = None,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    result_path = (
        Path(result_path).resolve()
        if result_path is not None
        else output_dir / AUDIT_FACTS_JSON
    )
    metta_path = (
        Path(metta_path).resolve()
        if metta_path is not None
        else output_dir / AUDIT_FACTS_METTA
    )
    facts = build_audit_facts(
        output_dir,
        board_path,
        decision_path=decision_path,
        transcript_path=transcript_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    metta_path.write_text(audit_facts_metta_text(facts), encoding="utf-8")
    write_json(result_path, facts)
    return {**facts, "result_path": str(result_path), "metta_file_path": str(metta_path)}


def verify_audit_facts(
    output_dir: str | Path,
    facts_path: str | Path | None = None,
    *,
    metta_path: str | Path | None = None,
    board_path: str | Path | None = None,
    decision_path: str | Path | None = None,
    transcript_path: str | Path | None = None,
    capsule_path: str | Path | None = None,
    archive_path: str | Path | None = None,
    capsule_markdown_path: str | Path | None = None,
) -> dict[str, object]:
    output_dir = Path(output_dir).resolve()
    facts_path = (
        Path(facts_path).resolve()
        if facts_path is not None
        else output_dir / AUDIT_FACTS_JSON
    )
    metta_path = (
        Path(metta_path).resolve()
        if metta_path is not None
        else output_dir / AUDIT_FACTS_METTA
    )
    actual: dict[str, object] = {}
    json_valid = False
    try:
        if facts_path.exists():
            loaded = load_json(facts_path)
            json_valid = isinstance(loaded, dict)
            if isinstance(loaded, dict):
                actual = loaded
    except (json.JSONDecodeError, OSError):
        json_valid = False
    expected = build_audit_facts(
        output_dir,
        board_path,
        decision_path=decision_path,
        transcript_path=transcript_path,
        capsule_path=capsule_path,
        archive_path=archive_path,
        capsule_markdown_path=capsule_markdown_path,
    )
    actual_body = audit_facts_hash_body(actual)
    actual_hash = canonical_object_sha256(actual_body) if actual else ""
    expected_metta = audit_facts_metta_text(expected)
    actual_metta = metta_path.read_text(encoding="utf-8") if metta_path.exists() else ""
    checks = {
        "audit_facts_present": facts_path.exists(),
        "audit_facts_json_valid": json_valid,
        "audit_facts_kind_matches": actual.get("artifact_kind")
        == "pettachainer_showcase_audit_facts",
        "audit_facts_hash_matches": actual.get("audit_facts_sha256") == actual_hash,
        "audit_facts_match_current_board": bool(actual) and actual == expected,
        "audit_facts_verdict_pass": actual.get("verdict") == "PASS",
        "audit_facts_metta_present": metta_path.exists(),
        "audit_facts_metta_matches": actual_metta == expected_metta,
        "audit_facts_metta_hash_matches": hashlib.sha256(
            actual_metta.encode("utf-8")
        ).hexdigest()
        == actual.get("metta_source_sha256", ""),
    }
    checks["audit_facts_verified"] = all(checks.values())
    return {
        "audit_facts_path": str(facts_path),
        "audit_facts_metta_path": str(metta_path),
        "audit_facts_file_sha256": hash_binary_file(facts_path)
        if facts_path.exists()
        else "",
        "audit_facts_metta_file_sha256": hash_binary_file(metta_path)
        if metta_path.exists()
        else "",
        "audit_facts_sha256": actual.get("audit_facts_sha256", ""),
        "expected_audit_facts_sha256": expected.get("audit_facts_sha256", ""),
        "verdict": actual.get("verdict", ""),
        "checks": checks,
    }


def verify_claim_evidence(
    packet_path: Path,
    claim_id: str,
    *,
    artifact_dir: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {"packet_present": packet_path.exists()}
    if not checks["packet_present"]:
        checks["claim_verified"] = False
        return {"packet_path": str(packet_path), "claim_id": claim_id, "checks": checks}

    packet = load_json(packet_path)
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else Path(str(packet.get("output_dir", packet_path.parent))).resolve()
    )
    packet_details = verify_forensic_packet_details(packet_path, artifact_dir=output_dir)
    packet_checks = dict(packet_details["checks"])
    claims = dict(packet.get("claim_ledger", {}))
    evidence_index_path = output_dir / "showcase-evidence-index.json"
    evidence_index = load_json(evidence_index_path) if evidence_index_path.exists() else {}
    indexed_claims = dict(evidence_index.get("claims", {}))
    claim = dict(claims.get(claim_id, {}))
    indexed_claim = dict(indexed_claims.get(claim_id, {}))
    expected_indexed_claim = {
        "description": claim.get("description", ""),
        "covered": bool(claim.get("covered")),
        "evidence_complete": bool(claim.get("evidence_complete")),
        "enforced_by": claim.get("enforced_by", []),
        "evidence": claim.get("evidence", []),
    }
    evidence = list(claim.get("evidence", []))
    link_results: list[dict[str, object]] = []
    for link in evidence:
        artifact_name = str(link.get("artifact", ""))
        json_path = str(link.get("json_path", ""))
        source_path = output_dir / artifact_name
        source_present = source_path.exists()
        resolved_value: object | None = None
        resolution_error = ""
        if source_present:
            try:
                resolved_value = resolve_json_pointer(load_json(source_path), json_path)
            except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
                resolution_error = type(exc).__name__
        source_binding = evidence_source_binding(
            packet_path,
            packet,
            output_dir,
            artifact_name,
        )
        link_results.append(
            {
                "check": str(link.get("check", "")),
                "artifact": artifact_name,
                "json_path": json_path,
                "source_present": source_present,
                "resolved_value": resolved_value,
                "expected_passed": bool(link.get("passed")),
                "resolved_matches_expected": source_present
                and not resolution_error
                and bool(resolved_value) == bool(link.get("passed")),
                "resolution_error": resolution_error,
                **source_binding,
            }
        )

    checks.update(
        {
            "packet_verified": bool(packet_checks.get("packet_verified")),
            "claim_present": bool(claim),
            "claim_covered": bool(claim.get("covered")),
            "claim_evidence_complete": bool(claim.get("evidence_complete"))
            and bool(evidence),
            "claim_matches_evidence_index": bool(claim)
            and indexed_claim == expected_indexed_claim,
            "claim_root_matches_packet": packet.get("roots", {}).get(
                "claim_ledger_root_sha256"
            )
            == canonical_object_sha256(claims),
            "evidence_links_resolve": bool(link_results)
            and all(bool(item["resolved_matches_expected"]) for item in link_results),
            "evidence_sources_sealed": bool(link_results)
            and all(bool(item["source_sealed"]) for item in link_results),
        }
    )
    checks["claim_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "claim_id": claim_id,
        "description": claim.get("description", ""),
        "enforced_by": claim.get("enforced_by", []),
        "evidence_link_count": len(evidence),
        "evidence": link_results,
        "checks": checks,
    }


def verify_all_claims(
    packet_path: Path,
    *,
    artifact_dir: Path | None = None,
    result_path: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {"packet_present": packet_path.exists()}
    if not checks["packet_present"]:
        checks["claim_sweep_verified"] = False
        result: dict[str, object] = {
            "packet_path": str(packet_path),
            "artifact_dir": str(artifact_dir) if artifact_dir is not None else "",
            "claim_count": 0,
            "verified_claim_count": 0,
            "evidence_link_count": 0,
            "sealed_source_count": 0,
            "source_anchor_counts": {},
            "failed_claims": [],
            "claims": [],
            "checks": checks,
        }
        if result_path is not None:
            result["result_path"] = str(result_path)
            certificate_json_path = result_path.with_name("showcase-claim-certificate.json")
            certificate_markdown_path = result_path.with_name("showcase-claim-certificate.md")
            certificate = write_claim_certificate(
                result,
                certificate_json_path,
                certificate_markdown_path,
            )
            result["claim_certificate_path"] = str(certificate_json_path)
            result["claim_certificate_markdown_path"] = str(certificate_markdown_path)
            result["claim_certificate_sha256"] = certificate["certificate_sha256"]
            write_json(result_path, result)
        return result

    packet = load_json(packet_path)
    roots = dict(packet.get("roots", {}))
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else Path(str(packet.get("output_dir", packet_path.parent))).resolve()
    )
    claims = dict(packet.get("claim_ledger", {}))
    claim_results = [
        verify_claim_evidence(packet_path, claim_id, artifact_dir=output_dir)
        for claim_id in sorted(claims)
    ]
    failed_claims = [
        str(claim["claim_id"])
        for claim in claim_results
        if not bool(dict(claim["checks"]).get("claim_verified"))
    ]
    evidence_link_count = sum(
        int(claim.get("evidence_link_count", 0)) for claim in claim_results
    )
    evidence_links = [
        link
        for claim in claim_results
        for link in list(claim.get("evidence", []))
    ]
    sealed_source_count = sum(1 for link in evidence_links if link.get("source_sealed"))
    source_anchor_counts: dict[str, int] = {}
    for link in evidence_links:
        anchor = str(link.get("source_hash_anchor", "unbound"))
        source_anchor_counts[anchor] = source_anchor_counts.get(anchor, 0) + 1
    checks.update(
        {
            "claims_present": bool(claims),
            "claim_root_matches_packet": packet.get("roots", {}).get(
                "claim_ledger_root_sha256"
            )
            == canonical_object_sha256(claims),
            "all_claims_verified": bool(claim_results) and not failed_claims,
        }
    )
    checks["claim_sweep_verified"] = all(checks.values())
    result = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "packet_root_sha256": packet.get("packet_root_sha256", ""),
        "claim_ledger_root_sha256": roots.get("claim_ledger_root_sha256", ""),
        "claim_count": len(claim_results),
        "verified_claim_count": len(claim_results) - len(failed_claims),
        "evidence_link_count": evidence_link_count,
        "sealed_source_count": sealed_source_count,
        "source_anchor_counts": source_anchor_counts,
        "failed_claims": failed_claims,
        "claims": claim_results,
        "checks": checks,
    }
    if result_path is not None:
        result["result_path"] = str(result_path)
        certificate_json_path = result_path.with_name("showcase-claim-certificate.json")
        certificate_markdown_path = result_path.with_name("showcase-claim-certificate.md")
        certificate = write_claim_certificate(
            result,
            certificate_json_path,
            certificate_markdown_path,
        )
        result["claim_certificate_path"] = str(certificate_json_path)
        result["claim_certificate_markdown_path"] = str(certificate_markdown_path)
        result["claim_certificate_sha256"] = certificate["certificate_sha256"]
        write_json(result_path, result)
    return result


def compact_noise_cases(result: dict[str, Any]) -> list[dict[str, object]]:
    return [
        {
            "extra_edges": int(case["extra_edges"]),
            "proof_sha256": case["proof_sha256"],
            "proof_hash_matches_incident": bool(case["proof_hash_matches_incident"]),
            "built_in_noise_tokens": int(case["built_in_noise_tokens"]),
            "injected_noise_tokens": int(case["injected_noise_tokens"]),
            "stable": bool(case["stable"]),
        }
        for case in result.get("noise_stability", [])
    ]


def compact_context_noise_cases(result: dict[str, Any]) -> list[dict[str, object]]:
    return [
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
        for case in result.get("context_noise_stability", [])
    ]


def compact_context_counterfactual_cases(result: dict[str, Any]) -> list[dict[str, object]]:
    return [
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
        for case in result.get("context_counterfactuals", [])
    ]


def compact_tamper_cases(result: dict[str, Any]) -> dict[str, dict[str, object]]:
    return {
        name: {
            "hash_verification_passed": bool(case["hash_verification_passed"]),
            "replay_rejected": bool(case["replay_rejected"]),
            "semantic_mismatch_detected": bool(case["semantic_mismatch_detected"]),
            "replay_failures": list(case["replay_failures"]),
        }
        for name, case in sorted(result.get("tamper_drill", {}).items())
    }


def compact_context_evidence(result: dict[str, Any]) -> dict[str, object]:
    context = result.get("context", {})
    return {
        "checks": context.get("checks", {}),
        "demos": {
            demo.get("name"): {
                "metta_file": demo.get("metta_file"),
                "summary_lines": demo.get("summary_lines", []),
                "summary_sha256": demo.get("summary_sha256"),
                "checks": {
                    check.get("name"): {
                        "passed": bool(check.get("passed", False)),
                        "expected": check.get("expected"),
                        "matched_line": check.get("matched_line"),
                    }
                    for check in demo.get("checks", [])
                },
            }
            for demo in context.get("demos", [])
        },
        "noise_stability": compact_context_noise_cases(result),
        "counterfactuals": compact_context_counterfactual_cases(result),
    }


def compact_complementary_evidence(result: dict[str, Any]) -> dict[str, object]:
    complementary = result.get("complementary", {})
    return {
        "checks": complementary.get("checks", {}),
        "metta_file": complementary.get("metta_file", ""),
        "summary_lines": complementary.get("summary_lines", []),
        "summary_sha256": complementary.get("summary_sha256", ""),
    }


def verify_witness_certificate(
    output_dir: Path,
    result: dict[str, Any],
    contract: dict[str, Any],
) -> tuple[bool, dict[str, object]]:
    artifacts = contract.get("artifacts", {})
    witness_name = str(artifacts.get("witness_certificate", "showcase-witness.json"))
    witness_path = output_dir / witness_name
    details: dict[str, object] = {
        "path": str(witness_path),
        "present": witness_path.exists(),
    }
    if not witness_path.exists():
        return False, details

    witness = load_json(witness_path)
    body = dict(witness)
    root = str(body.pop("witness_root_sha256", ""))
    artifact_hashes = witness.get("artifact_hashes", {})
    expected_artifact_paths = {
        str(artifacts.get("result_json", "showcase-result.json")),
        str(artifacts.get("report_markdown", "showcase-report.md")),
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
    }
    artifact_hash_checks = {
        filename: (
            (output_dir / filename).exists()
            and hash_file(output_dir / filename) == expected_hash
        )
        for filename, expected_hash in artifact_hashes.items()
    }
    timings = {item["name"]: item for item in result["dispatch"]["timings"]}
    dispatch_evidence = witness.get("dispatch_evidence", {})
    proof_evidence = witness.get("proof_evidence", {})
    causal_evidence = witness.get("causal_evidence", {})
    context_evidence = witness.get("context_evidence", {})
    complementary_evidence = witness.get("complementary_evidence", {})
    noise_evidence = witness.get("noise_evidence", {})
    tamper_evidence = witness.get("tamper_evidence", {})
    incident = result.get("incident", {})
    expected_claim_ids = [str(claim["id"]) for claim in contract.get("claims", [])]
    expected_noise_cases = compact_noise_cases(result)
    expected_context_noise_cases = compact_context_noise_cases(result)
    expected_context_counterfactuals = compact_context_counterfactual_cases(result)
    primary_ablation_count = sum(
        case.get("mode") == "primary_path_minimality"
        for case in incident.get("causal_ablation", [])
    )
    distractor_ablation_count = sum(
        case.get("mode") == "distractor_invariance"
        for case in incident.get("causal_ablation", [])
    )
    expected_max_noise_edges = max(
        (int(case["extra_edges"]) for case in result.get("noise_stability", [])),
        default=0,
    )
    bool_checks = {
        "kind_matches": (
            witness.get("artifact_kind")
            == "pettachainer_showcase_witness_certificate"
        ),
        "version_matches": witness.get("witness_version") == 1,
        "root_hash_matches": root == canonical_json_sha256(body),
        "expected_artifacts_listed": expected_artifact_paths.issubset(
            set(artifact_hashes)
        ),
        "artifact_hashes_match": bool(artifact_hash_checks)
        and all(artifact_hash_checks.values()),
        "objective_matches_contract": witness.get("objective")
        == contract.get("objective", ""),
        "claim_ids_match_contract": witness.get("contract_claim_ids")
        == expected_claim_ids,
        "showcase_checks_match_result": witness.get("showcase_checks")
        == result.get("checks", {}),
        "proof_hash_matches_result": proof_evidence.get("isolate_proof_sha256")
        == incident.get("proof_sha256"),
        "scenario_hash_matches_result": proof_evidence.get("scenario_sha256")
        == incident.get("scenario_sha256"),
        "query_counts_match_result": proof_evidence.get("query_counts")
        == incident.get("query_counts"),
        "proof_tokens_match_result": proof_evidence.get("isolate_proof_tokens")
        == incident.get("isolate_proof_tokens"),
        "proof_ladder_match_result": proof_evidence.get("proof_ladder")
        == incident.get("proof_ladder"),
        "proof_structure_match_result": proof_evidence.get("proof_structure")
        == incident.get("proof_structure"),
        "causal_counts_match_result": (
            int(causal_evidence.get("primary_ablation_count", -1))
            == primary_ablation_count
            and int(causal_evidence.get("distractor_ablation_count", -1))
            == distractor_ablation_count
        ),
        "causal_checks_match_result": causal_evidence.get("causal_checks")
        == incident.get("causal_checks"),
        "context_evidence_match_result": context_evidence
        == compact_context_evidence(result),
        "context_noise_cases_match_result": context_evidence.get("noise_stability")
        == expected_context_noise_cases,
        "context_counterfactuals_match_result": context_evidence.get("counterfactuals")
        == expected_context_counterfactuals,
        "complementary_evidence_match_result": complementary_evidence
        == compact_complementary_evidence(result),
        "noise_cases_match_result": noise_evidence.get("cases")
        == expected_noise_cases,
        "noise_max_edges_match_result": int(noise_evidence.get("max_extra_edges", -1))
        == expected_max_noise_edges,
        "dispatch_evidence_match_result": all(
            name in dispatch_evidence
            and float(dispatch_evidence[name]["ratio_to_smart"])
            == float(timings[name]["ratio_to_smart"])
            and dispatch_evidence[name]["codegen_marker"] == timings[name]["codegen_marker"]
            for name in ("smart", "call", "reduce", "eval")
        ),
        "tamper_evidence_match_result": tamper_evidence
        == compact_tamper_cases(result),
    }
    details.update(bool_checks)
    details["artifact_hashes"] = artifact_hash_checks
    details["witness_root_sha256"] = root
    return all(bool_checks.values()), details


def verify_acceptance_contract(
    contract: dict[str, Any],
    result: dict[str, Any],
    report: str,
    checks: dict[str, bool],
) -> bool:
    timings = {item["name"]: item for item in result["dispatch"]["timings"]}
    thresholds = contract.get("thresholds", {})
    required_showcase_checks = set(contract.get("required_showcase_checks", []))
    required_verifier_checks = {
        name
        for name in contract.get("required_verifier_checks", [])
        if name not in {"contract_enforced", "verifier_completed"}
    }
    required_tamper_cases = set(contract.get("required_tamper_cases", []))
    max_noise_edges = max(
        (int(case["extra_edges"]) for case in result.get("noise_stability", [])),
        default=0,
    )
    max_context_noise_packets = max(
        (
            int(case["extra_packets"])
            for case in result.get("context_noise_stability", [])
        ),
        default=0,
    )
    return (
        contract.get("contract_version") == 1
        and contract.get("artifact_kind") == "pettachainer_showcase_acceptance_contract"
        and bool(contract.get("claims"))
        and required_showcase_checks.issubset(result.get("checks", {}))
        and all(result["checks"][name] for name in required_showcase_checks)
        and required_verifier_checks.issubset(checks)
        and all(checks[name] for name in required_verifier_checks)
        and all(section in report for section in contract.get("required_report_sections", []))
        and set(result.get("tamper_drill", {})) == required_tamper_cases
        and float(timings["reduce"]["ratio_to_smart"])
        > float(thresholds.get("dispatch_reduce_ratio_gt", 1.0))
        and (
            not thresholds.get("dispatch_eval_ratio_gt_reduce", True)
            or float(timings["eval"]["ratio_to_smart"])
            > float(timings["reduce"]["ratio_to_smart"])
        )
        and max_noise_edges >= int(thresholds.get("minimum_noise_extra_edges", 0))
        and max_context_noise_packets
        >= int(thresholds.get("minimum_context_noise_packets", 0))
        and all(
            int(case["proofs"]) == int(thresholds.get("noise_proofs", 1))
            and int(case["built_in_noise_tokens"]) == int(thresholds.get("noise_tokens", 0))
            and int(case["injected_noise_tokens"]) == int(thresholds.get("noise_tokens", 0))
            for case in result.get("noise_stability", [])
        )
        and verify_recorded_context_noise(result)
        and verify_recorded_context_counterfactuals(result)
    )


def build_claim_coverage(
    contract: dict[str, Any],
    result: dict[str, Any],
    checks: dict[str, bool],
) -> dict[str, dict[str, object]]:
    result_checks = dict(result.get("checks", {}))
    verifier_checks = dict(checks)
    available_checks = {**result_checks, **verifier_checks}
    coverage: dict[str, dict[str, object]] = {}
    for claim in contract.get("claims", []):
        claim_id = str(claim.get("id", "unnamed_claim"))
        enforced_by = [str(name) for name in claim.get("enforced_by", [])]
        status_by_check = {
            name: bool(available_checks.get(name, False)) for name in enforced_by
        }
        missing_checks = [name for name in enforced_by if name not in available_checks]
        evidence: list[dict[str, object]] = []
        for name in enforced_by:
            if name in result_checks:
                evidence.append(
                    {
                        "check": name,
                        "artifact": "showcase-result.json",
                        "json_path": f"/checks/{name}",
                        "passed": bool(result_checks[name]),
                    }
                )
            if name in verifier_checks:
                evidence.append(
                    {
                        "check": name,
                        "artifact": "showcase-verifier-result.json",
                        "json_path": f"/checks/{name}",
                        "passed": bool(verifier_checks[name]),
                    }
                )
        evidence_by_check = {
            str(item["check"]) for item in evidence if bool(item.get("passed"))
        }
        evidence_complete = (
            bool(enforced_by)
            and not missing_checks
            and set(enforced_by).issubset(evidence_by_check)
        )
        coverage[claim_id] = {
            "description": claim.get("description", ""),
            "enforced_by": enforced_by,
            "check_status": status_by_check,
            "missing_checks": missing_checks,
            "evidence": evidence,
            "evidence_complete": evidence_complete,
            "covered": bool(enforced_by)
            and not missing_checks
            and evidence_complete
            and all(status_by_check.values()),
        }
    return coverage


def verify_replayed_noise(
    result: dict[str, Any],
    *,
    output_dir: Path,
    replay_noise: bool,
) -> tuple[bool, list[dict[str, object]]]:
    if not replay_noise:
        return True, []
    levels = tuple(int(case["extra_edges"]) for case in result.get("noise_stability", []))
    expected_sha = str(result.get("incident", {}).get("proof_sha256", ""))
    incident = result.get("incident", {})
    with redirect_process_output(output_dir / "showcase-verifier-noise-replay.log"):
        replay = noise_stability_sweep(
            expected_proof_sha256=expected_sha,
            forward_steps=int(incident.get("forward_steps", 0)),
            query_steps=int(incident.get("query_steps", 0)),
            levels=levels,
        )
    replay_path = output_dir / "showcase-verifier-noise-replay.json"
    replay_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return all(bool(case["stable"]) for case in replay), replay


def verify_replayed_context_noise(
    result: dict[str, Any],
    *,
    output_dir: Path,
    replay_context_noise: bool,
) -> tuple[bool, list[dict[str, object]]]:
    if not replay_context_noise:
        return True, []
    levels = tuple(
        int(case["extra_packets"])
        for case in result.get("context_noise_stability", [])
    )
    replay = context_noise_stability_sweep(levels=levels)
    replay_path = output_dir / "showcase-verifier-context-noise-replay.json"
    replay_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    replay_result = {"context_noise_stability": replay}
    return (
        verify_recorded_context_noise(replay_result)
        and compact_context_noise_cases(replay_result)
        == compact_context_noise_cases(result),
        replay,
    )


def verify_replayed_context_counterfactuals(
    result: dict[str, Any],
    *,
    output_dir: Path,
    replay_context_counterfactuals: bool,
) -> tuple[bool, list[dict[str, object]]]:
    if not replay_context_counterfactuals:
        return True, []
    replay = context_counterfactual_sensitivity_cases()
    replay_path = output_dir / "showcase-verifier-context-counterfactual-replay.json"
    replay_path.write_text(json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    replay_result = {"context_counterfactuals": replay}
    return (
        verify_recorded_context_counterfactuals(replay_result)
        and compact_context_counterfactual_cases(replay_result)
        == compact_context_counterfactual_cases(result),
        replay,
    )


def verify_tamper_cases(
    output_dir: Path,
    result: dict[str, Any],
) -> tuple[bool, dict[str, dict[str, object]]]:
    tamper_result: dict[str, dict[str, object]] = {}
    expected_names = set(result.get("tamper_drill", {}))
    for case_name in sorted(expected_names):
        case_dir = tamper_case_path(output_dir, case_name)
        hash_checks = verify_audit_bundle(case_dir)
        replay_checks = replay_audit_bundle(
            case_dir,
            output_dir / f"showcase-verifier-{case_name}-replay.log",
        )
        failures = [name for name, passed in replay_checks.items() if not passed]
        tamper_result[case_name] = {
            "path": str(case_dir),
            "hash_verification": hash_checks,
            "replay_verification": replay_checks,
            "hash_verification_passed": all(hash_checks.values()),
            "replay_rejected": not all(replay_checks.values()),
            "replay_failures": failures,
        }
    return (
        expected_names
        == {
            "hash_consistent_scenario_forgery",
            "metadata_consistent_semantic_forgery",
        }
        and all(
            bool(case["hash_verification_passed"]) and bool(case["replay_rejected"])
            for case in tamper_result.values()
        ),
        tamper_result,
    )


def verify_showcase_artifacts(
    output_dir: Path,
    *,
    replay_noise: bool = True,
    replay_context: bool = True,
    replay_complementary: bool = True,
    replay_context_noise: bool = True,
    replay_context_counterfactuals: bool = True,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    result_path = output_dir / "showcase-result.json"
    report_path = output_dir / "showcase-report.md"
    contract_path = output_dir / "showcase-contract.json"
    bundle_dir = output_dir / "incident-bundle"

    checks: dict[str, bool] = {
        "artifact_files_present": (
            result_path.exists()
            and report_path.exists()
            and contract_path.exists()
            and (bundle_dir / "MANIFEST.json").exists()
        )
    }
    if not checks["artifact_files_present"]:
        checks["verifier_completed"] = False
        return {
            "output_dir": str(output_dir),
            "replay_noise": replay_noise,
            "replay_context": replay_context,
            "replay_complementary": replay_complementary,
            "replay_context_noise": replay_context_noise,
            "replay_context_counterfactuals": replay_context_counterfactuals,
            "checks": checks,
        }

    result = load_json(result_path)
    report = report_path.read_text(encoding="utf-8")
    contract = load_json(contract_path)

    timings = {item["name"]: item for item in result["dispatch"]["timings"]}
    checks.update(
        {
            "result_checks_claim_pass": all(result.get("checks", {}).values()),
            "dispatch_artifact_claims_pass": (
                all(result["dispatch"]["checks"].values())
                and float(timings["reduce"]["ratio_to_smart"]) > 1.0
                and float(timings["eval"]["ratio_to_smart"])
                > float(timings["reduce"]["ratio_to_smart"])
            ),
            "report_mentions_audit_sections": all(
                section in report
                for section in (
                    "PeTTaChainer Full Showcase",
                    "Generated Context Control",
                    "Complementary Evidence Merge",
                    "Needle-in-Haystack Noise Sweep",
                    "Adversarial Tamper Drill",
                    "Causal Minimality Certificate",
                )
            ),
        }
    )

    bundle_checks = verify_audit_bundle(bundle_dir)
    replay_checks = replay_audit_bundle(
        bundle_dir,
        output_dir / "showcase-verifier-incident-replay.log",
    )
    tamper_passed, tamper_checks = verify_tamper_cases(output_dir, result)
    noise_replay_passed, noise_replay = verify_replayed_noise(
        result,
        output_dir=output_dir,
        replay_noise=replay_noise,
    )
    context_verification = verify_context_showcase_artifacts(
        output_dir / "context-showcase",
        replay=replay_context,
    )
    complementary_verification = verify_complementary_evidence_artifacts(
        output_dir / "complementary-evidence",
        replay=replay_complementary,
    )
    context_noise_replay_passed, context_noise_replay = verify_replayed_context_noise(
        result,
        output_dir=output_dir,
        replay_context_noise=replay_context_noise,
    )
    context_counterfactual_replay_passed, context_counterfactual_replay = (
        verify_replayed_context_counterfactuals(
            result,
            output_dir=output_dir,
            replay_context_counterfactuals=replay_context_counterfactuals,
        )
    )
    witness_passed, witness_checks = verify_witness_certificate(
        output_dir,
        result,
        contract,
    )

    checks.update(
        {
            "bundle_hash_verification_passes": all(bundle_checks.values()),
            "bundle_replay_verification_passes": all(replay_checks.values()),
            "tamper_artifacts_reject_on_replay": tamper_passed,
            "recorded_noise_stability_passes": verify_recorded_noise(result),
            "noise_replay_passes": noise_replay_passed,
            "recorded_context_noise_stability_passes": verify_recorded_context_noise(
                result
            ),
            "context_noise_replay_passes": context_noise_replay_passed,
            "recorded_context_counterfactual_sensitivity_passes": verify_recorded_context_counterfactuals(
                result
            ),
            "context_counterfactual_replay_passes": context_counterfactual_replay_passed,
            "context_showcase_artifacts_verify": bool(context_verification["passed"]),
            "complementary_evidence_artifacts_verify": bool(
                complementary_verification["passed"]
            ),
            "witness_certificate_verified": witness_passed,
        }
    )
    claim_coverage = build_claim_coverage(contract, result, checks)
    checks["contract_claims_covered"] = (
        bool(claim_coverage)
        and all(bool(claim["covered"]) for claim in claim_coverage.values())
    )
    checks["contract_enforced"] = verify_acceptance_contract(
        contract,
        result,
        report,
        checks,
    )
    checks["verifier_completed"] = all(checks.values())

    verification = {
        "output_dir": str(output_dir),
        "replay_noise": replay_noise,
        "replay_context": replay_context,
        "replay_complementary": replay_complementary,
        "replay_context_noise": replay_context_noise,
        "replay_context_counterfactuals": replay_context_counterfactuals,
        "contract": contract,
        "checks": checks,
        "claim_coverage": claim_coverage,
        "bundle_verification": bundle_checks,
        "bundle_replay": replay_checks,
        "tamper_replay": tamper_checks,
        "noise_replay": noise_replay,
        "context_noise_replay": context_noise_replay,
        "context_counterfactual_replay": context_counterfactual_replay,
        "context_showcase_verification": context_verification,
        "complementary_evidence_verification": complementary_verification,
        "witness_verification": witness_checks,
        "result_path": str(output_dir / "showcase-verifier-result.json"),
    }
    Path(verification["result_path"]).write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return verification


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def copy_artifact_for_red_team(source_dir: Path, red_team_dir: Path, case_name: str) -> Path:
    case_dir = red_team_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    shutil.copytree(source_dir, case_dir)
    return case_dir


def mutate_noise_metadata(case_dir: Path) -> None:
    result_path = case_dir / "showcase-result.json"
    result = load_json(result_path)
    result["noise_stability"][0]["injected_noise_tokens"] = 1
    write_json(result_path, result)


def mutate_context_noise_metadata(case_dir: Path) -> None:
    result_path = case_dir / "showcase-result.json"
    result = load_json(result_path)
    result["context_noise_stability"][0]["noise_route_hits"] = 1
    result["context_noise_stability"][0]["stable"] = False
    write_json(result_path, result)


def mutate_context_ranking_metadata(case_dir: Path) -> None:
    result_path = case_dir / "showcase-result.json"
    result = load_json(result_path)
    result["context_noise_stability"][0]["ranking_margin"] = 0.0
    result["context_noise_stability"][0]["runner_up_guard"] = ["type:Penguin"]
    result["context_noise_stability"][0]["stable"] = False
    write_json(result_path, result)


def mutate_context_counterfactual_metadata(case_dir: Path) -> None:
    result_path = case_dir / "showcase-result.json"
    result = load_json(result_path)
    result["context_counterfactuals"][0]["passed"] = False
    result["context_counterfactuals"][0]["best_guard"] = ["type:Penguin"]
    write_json(result_path, result)


def mutate_tamper_metadata(case_dir: Path) -> None:
    result_path = case_dir / "showcase-result.json"
    result = load_json(result_path)
    result["tamper_drill"] = {}
    write_json(result_path, result)


def mutate_contract_threshold(case_dir: Path) -> None:
    contract_path = case_dir / "showcase-contract.json"
    contract = load_json(contract_path)
    contract["thresholds"]["minimum_noise_extra_edges"] = 999_999
    write_json(contract_path, contract)


def mutate_contract_claim(case_dir: Path) -> None:
    contract_path = case_dir / "showcase-contract.json"
    contract = load_json(contract_path)
    contract["claims"].append(
        {
            "id": "unsupported_impressive_claim",
            "description": "A forged claim that no verifier check enforces.",
            "enforced_by": ["nonexistent_verifier_check"],
        }
    )
    write_json(contract_path, contract)


def rewrite_witness_certificate(case_dir: Path, mutate) -> None:
    witness_path = case_dir / "showcase-witness.json"
    witness = load_json(witness_path)
    body = {key: value for key, value in witness.items() if key != "witness_root_sha256"}
    mutate(body)
    body["witness_root_sha256"] = canonical_json_sha256(body)
    write_json(witness_path, body)


def mutate_witness_certificate(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["proof_evidence"]["isolate_proof_sha256"] = "0" * 64

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_artifact_hash(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["artifact_hashes"]["showcase-result.json"] = "0" * 64

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_claim_ids(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["contract_claim_ids"].append("phantom_unenforced_claim")

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_dispatch_evidence(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["dispatch_evidence"]["reduce"]["codegen_marker"] = "direct_predicate_call"

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_noise_evidence(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["noise_evidence"]["cases"][0]["injected_noise_tokens"] = 1

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_context_noise(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["context_evidence"]["noise_stability"][0]["stable"] = False

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_context_ranking(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["context_evidence"]["noise_stability"][0]["ranking_margin"] = 0.0

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_context_counterfactual(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["context_evidence"]["counterfactuals"][0]["passed"] = False

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_complementary_evidence(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        complementary = body.setdefault("complementary_evidence", {})
        summary_lines = complementary.setdefault(
            "summary_lines",
            ["merge/additive-complement"],
        )
        if not summary_lines:
            summary_lines.append("merge/additive-complement")
        summary_lines[0] = str(summary_lines[0]).replace(
            "merge/additive-complement",
            "merge/highest-confidence",
        )

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_tamper_evidence(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["tamper_evidence"]["metadata_consistent_semantic_forgery"][
            "replay_rejected"
        ] = False

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_proof_structure(case_dir: Path) -> None:
    def mutate(body: dict[str, Any]) -> None:
        body["proof_evidence"]["proof_structure"]["checks"][
            "primary_chain_found"
        ] = False

    rewrite_witness_certificate(case_dir, mutate)


def mutate_witness_uncanonical_root(case_dir: Path) -> None:
    witness_path = case_dir / "showcase-witness.json"
    witness = load_json(witness_path)
    witness["proof_evidence"]["isolate_proof_sha256"] = "0" * 64
    write_json(witness_path, witness)


def mutate_report_section(case_dir: Path) -> None:
    report_path = case_dir / "showcase-report.md"
    report = report_path.read_text(encoding="utf-8")
    report = report.replace("## Adversarial Tamper Drill", "## Redacted Tamper Drill")
    report_path.write_text(report, encoding="utf-8")


def mutate_bundle_payload(case_dir: Path) -> None:
    scenario_path = case_dir / "incident-bundle" / "scenario.metta"
    scenario = scenario_path.read_text(encoding="utf-8")
    scenario_path.write_text(scenario + "; verifier red-team payload mutation\n", encoding="utf-8")


def refresh_bundle_manifest_hashes(case_dir: Path, filenames: list[str]) -> None:
    bundle_dir = case_dir / "incident-bundle"
    manifest_path = bundle_dir / "MANIFEST.json"
    manifest = load_json(manifest_path)
    files = dict(manifest.get("files", {}))
    for filename in filenames:
        files[filename] = hash_file(bundle_dir / filename)
    manifest["files"] = files
    write_json(manifest_path, manifest)


def mutate_bundle_proof_structure(case_dir: Path) -> None:
    cert_rel = "incident-bundle/proof-structure.json"
    manifest_rel = "incident-bundle/MANIFEST.json"
    cert_path = case_dir / cert_rel
    cert = load_json(cert_path)
    cert["checks"]["primary_chain_found"] = False
    cert["certificate_passes"] = False
    write_json(cert_path, cert)
    refresh_bundle_manifest_hashes(case_dir, ["proof-structure.json"])
    refresh_witness_artifact_hashes(case_dir, [cert_rel, manifest_rel])


def refresh_witness_artifact_hashes(case_dir: Path, filenames: list[str]) -> None:
    witness_path = case_dir / "showcase-witness.json"
    witness = load_json(witness_path)
    artifact_hashes = dict(witness.get("artifact_hashes", {}))
    for filename in filenames:
        artifact_hashes[filename] = hash_file(case_dir / filename)
    witness["artifact_hashes"] = artifact_hashes
    body = {key: value for key, value in witness.items() if key != "witness_root_sha256"}
    body["witness_root_sha256"] = canonical_json_sha256(body)
    write_json(witness_path, body)


def mutate_context_log_semantic_forgery(case_dir: Path) -> None:
    log_rel = "context-showcase/beam-needle-control.log"
    manifest_rel = "context-showcase/context-showcase-manifest.json"
    log_path = case_dir / log_rel
    log_path.write_text(
        log_path.read_text(encoding="utf-8").replace(
            "beam-needle-grounding",
            "beam-needle-forged-grounding",
        ),
        encoding="utf-8",
    )
    manifest_path = case_dir / manifest_rel
    manifest = load_json(manifest_path)
    manifest["files"]["beam-needle-control.log"] = hash_file(log_path)
    write_json(manifest_path, manifest)
    refresh_witness_artifact_hashes(case_dir, [log_rel, manifest_rel])


def mutate_complementary_log_semantic_forgery(case_dir: Path) -> None:
    log_rel = "complementary-evidence/additive-complement-merge.log"
    manifest_rel = "complementary-evidence/complementary-evidence-manifest.json"
    log_path = case_dir / log_rel
    log_path.write_text(
        log_path.read_text(encoding="utf-8").replace(
            "merge/additive-complement",
            "merge/highest-confidence",
        ),
        encoding="utf-8",
    )
    manifest_path = case_dir / manifest_rel
    manifest = load_json(manifest_path)
    manifest["files"]["additive-complement-merge.log"] = hash_file(log_path)
    write_json(manifest_path, manifest)
    refresh_witness_artifact_hashes(case_dir, [log_rel, manifest_rel])


def run_red_team_verifier(
    output_dir: Path,
    *,
    replay_noise: bool = False,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir.parent / f"{output_dir.name}-verifier-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)
    witness_failure_checks = [
        "witness_certificate_verified",
        "contract_claims_covered",
        "contract_enforced",
    ]

    cases = {
        "noise_metadata_forgery": {
            "mutate": mutate_noise_metadata,
            "mutation_family": "result_metadata",
            "expected_failed_checks": ["recorded_noise_stability_passes"],
        },
        "context_noise_metadata_forgery": {
            "mutate": mutate_context_noise_metadata,
            "mutation_family": "result_metadata",
            "expected_failed_checks": [
                "recorded_context_noise_stability_passes",
                "contract_enforced",
            ],
        },
        "context_ranking_metadata_forgery": {
            "mutate": mutate_context_ranking_metadata,
            "mutation_family": "result_metadata",
            "expected_failed_checks": [
                "recorded_context_noise_stability_passes",
                "contract_enforced",
            ],
        },
        "context_counterfactual_metadata_forgery": {
            "mutate": mutate_context_counterfactual_metadata,
            "mutation_family": "result_metadata",
            "expected_failed_checks": [
                "recorded_context_counterfactual_sensitivity_passes",
                "contract_enforced",
            ],
        },
        "tamper_metadata_forgery": {
            "mutate": mutate_tamper_metadata,
            "mutation_family": "result_metadata",
            "expected_failed_checks": ["tamper_artifacts_reject_on_replay"],
        },
        "contract_threshold_forgery": {
            "mutate": mutate_contract_threshold,
            "mutation_family": "contract",
            "expected_failed_checks": ["contract_enforced"],
        },
        "contract_claim_forgery": {
            "mutate": mutate_contract_claim,
            "mutation_family": "contract",
            "expected_failed_checks": [
                "contract_claims_covered",
                "contract_enforced",
            ],
        },
        "witness_certificate_forgery": {
            "mutate": mutate_witness_certificate,
            "mutation_family": "witness_proof",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_uncanonical_root_forgery": {
            "mutate": mutate_witness_uncanonical_root,
            "mutation_family": "witness_root",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_artifact_hash_forgery": {
            "mutate": mutate_witness_artifact_hash,
            "mutation_family": "witness_artifacts",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_claim_ids_forgery": {
            "mutate": mutate_witness_claim_ids,
            "mutation_family": "witness_contract",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_dispatch_evidence_forgery": {
            "mutate": mutate_witness_dispatch_evidence,
            "mutation_family": "witness_dispatch",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_noise_evidence_forgery": {
            "mutate": mutate_witness_noise_evidence,
            "mutation_family": "witness_noise",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_context_noise_evidence_forgery": {
            "mutate": mutate_witness_context_noise,
            "mutation_family": "witness_context_noise",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_context_ranking_evidence_forgery": {
            "mutate": mutate_witness_context_ranking,
            "mutation_family": "witness_context_ranking",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_context_counterfactual_evidence_forgery": {
            "mutate": mutate_witness_context_counterfactual,
            "mutation_family": "witness_context_counterfactual",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_complementary_evidence_forgery": {
            "mutate": mutate_witness_complementary_evidence,
            "mutation_family": "witness_complementary",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_tamper_evidence_forgery": {
            "mutate": mutate_witness_tamper_evidence,
            "mutation_family": "witness_tamper",
            "expected_failed_checks": witness_failure_checks,
        },
        "witness_proof_structure_forgery": {
            "mutate": mutate_witness_proof_structure,
            "mutation_family": "witness_proof_structure",
            "expected_failed_checks": witness_failure_checks,
        },
        "report_section_forgery": {
            "mutate": mutate_report_section,
            "mutation_family": "report",
            "expected_failed_checks": [
                "report_mentions_audit_sections",
                "contract_enforced",
            ],
        },
        "bundle_payload_forgery": {
            "mutate": mutate_bundle_payload,
            "mutation_family": "bundle",
            "expected_failed_checks": [
                "bundle_hash_verification_passes",
                "bundle_replay_verification_passes",
            ],
        },
        "bundle_proof_structure_forgery": {
            "mutate": mutate_bundle_proof_structure,
            "mutation_family": "bundle_proof_structure",
            "expected_failed_checks": [
                "bundle_hash_verification_passes",
                "contract_enforced",
            ],
        },
        "context_log_semantic_forgery": {
            "mutate": mutate_context_log_semantic_forgery,
            "mutation_family": "context_showcase",
            "expected_failed_checks": [
                "context_showcase_artifacts_verify",
                "contract_claims_covered",
                "contract_enforced",
            ],
        },
        "complementary_log_semantic_forgery": {
            "mutate": mutate_complementary_log_semantic_forgery,
            "mutation_family": "complementary_evidence",
            "expected_failed_checks": [
                "complementary_evidence_artifacts_verify",
                "contract_claims_covered",
                "contract_enforced",
            ],
        },
    }

    results: dict[str, dict[str, object]] = {}
    for case_name, spec in cases.items():
        case_dir = copy_artifact_for_red_team(output_dir, red_team_dir, case_name)
        spec["mutate"](case_dir)
        verification = verify_showcase_artifacts(
            case_dir,
            replay_noise=replay_noise,
            replay_context=False,
            replay_complementary=False,
            replay_context_counterfactuals=False,
            replay_context_noise=False,
        )
        checks = verification["checks"]
        expected_failed = list(spec["expected_failed_checks"])
        actual_failed = [name for name, passed in checks.items() if not passed]
        rejected = (
            not all(checks.values())
            and not bool(checks.get("verifier_completed"))
            and all(not bool(checks.get(name)) for name in expected_failed)
        )
        results[case_name] = {
            "path": str(case_dir),
            "mutation_family": str(spec["mutation_family"]),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": actual_failed,
            "rejected": rejected,
            "checks": checks,
        }

    summary = {
        "red_team_dir": str(red_team_dir),
        "replay_noise": replay_noise,
        "cases": results,
        "mutation_families": sorted(
            {str(result["mutation_family"]) for result in results.values()}
        ),
        "red_team_rejections_pass": all(
            bool(result["rejected"]) for result in results.values()
        ),
        "result_path": str(output_dir / "showcase-verifier-red-team-result.json"),
    }
    Path(summary["result_path"]).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def build_forensic_packet(
    verification: dict[str, object],
    red_team: dict[str, object] | None = None,
) -> dict[str, object]:
    output_dir = Path(str(verification["output_dir"]))
    witness_path = output_dir / "showcase-witness.json"
    result_path = output_dir / "showcase-result.json"
    proof_structure_path = output_dir / "incident-bundle" / "proof-structure.json"
    witness = load_json(witness_path) if witness_path.exists() else {}
    result = load_json(result_path) if result_path.exists() else {}
    proof_structure = (
        load_json(proof_structure_path) if proof_structure_path.exists() else {}
    )
    red_team_cases = red_team.get("cases", {}) if red_team is not None else {}
    artifact_hashes = witness.get("artifact_hashes", {})
    artifact_merkle_tree = build_artifact_merkle_tree(dict(artifact_hashes))
    claim_ledger = verification.get("claim_coverage", {})
    proof_structure_summary = {
        "certificate_passes": bool(proof_structure.get("certificate_passes")),
        "checks": proof_structure.get("checks", {}),
        "operator_counts": proof_structure.get("operator_counts", {}),
        "forbidden_label_counts": proof_structure.get("forbidden_label_counts", {}),
        "proof_sha256": proof_structure.get("proof_sha256", ""),
    }
    context_evidence = {
        "checks": witness.get("context_evidence", {}).get("checks", {}),
        "noise_stability": witness.get("context_evidence", {}).get(
            "noise_stability", []
        ),
        "counterfactuals": witness.get("context_evidence", {}).get(
            "counterfactuals", []
        ),
    }
    complementary_evidence = witness.get("complementary_evidence", {})
    red_team_summary = {
        "case_count": len(red_team_cases),
        "mutation_families": (
            red_team.get("mutation_families", []) if red_team is not None else []
        ),
        "cases": {
            name: {
                "mutation_family": case.get("mutation_family"),
                "expected_failed_checks": case.get("expected_failed_checks", []),
                "actual_failed_checks": case.get("actual_failed_checks", []),
                "rejected": bool(case.get("rejected")),
            }
            for name, case in sorted(red_team_cases.items())
        },
    }
    incident_summary = {
        "query_counts": result.get("incident", {}).get("query_counts", {}),
        "proof_sha256": result.get("incident", {}).get("proof_sha256", ""),
        "structural_certificate_passes": bool(
            result.get("incident", {})
            .get("proof_structure", {})
            .get("certificate_passes")
        ),
    }
    body: dict[str, object] = {
        "packet_version": 1,
        "artifact_kind": "pettachainer_showcase_forensic_packet",
        "output_dir": str(output_dir),
        "verdict": {
            "verifier_checks_pass": all(
                bool(value)
                for value in dict(verification.get("checks", {})).values()
            ),
            "red_team_rejections_pass": (
                red_team is None or bool(red_team.get("red_team_rejections_pass"))
            ),
        },
        "roots": {
            "witness_root_sha256": witness.get("witness_root_sha256", ""),
            "forensic_source_verifier_sha256": hash_file(
                output_dir / "showcase-verifier-result.json"
            )
            if (output_dir / "showcase-verifier-result.json").exists()
            else "",
            "forensic_source_red_team_sha256": hash_file(
                output_dir / "showcase-verifier-red-team-result.json"
            )
            if (output_dir / "showcase-verifier-red-team-result.json").exists()
            else "",
            "artifact_merkle_root_sha256": artifact_merkle_tree["root_sha256"],
            "artifact_hashes_root_sha256": canonical_object_sha256(artifact_hashes),
            "claim_ledger_root_sha256": canonical_object_sha256(claim_ledger),
            "context_evidence_root_sha256": canonical_object_sha256(context_evidence),
            "complementary_evidence_root_sha256": canonical_object_sha256(
                complementary_evidence
            ),
            "incident_summary_root_sha256": canonical_object_sha256(incident_summary),
            "proof_structure_root_sha256": canonical_object_sha256(
                proof_structure_summary
            ),
            "red_team_root_sha256": canonical_object_sha256(red_team_summary),
        },
        "artifact_hashes": artifact_hashes,
        "artifact_merkle_tree": artifact_merkle_tree,
        "claim_ledger": claim_ledger,
        "verifier_checks": verification.get("checks", {}),
        "proof_structure": proof_structure_summary,
        "dispatch_evidence": witness.get("dispatch_evidence", {}),
        "context_evidence": context_evidence,
        "complementary_evidence": complementary_evidence,
        "noise_evidence": witness.get("noise_evidence", {}),
        "incident_summary": incident_summary,
        "red_team": red_team_summary,
    }
    return {**body, "packet_root_sha256": canonical_json_sha256(body)}


def build_evidence_index(packet: dict[str, object]) -> dict[str, object]:
    claims = dict(packet.get("claim_ledger", {}))
    red_team = dict(packet.get("red_team", {}))
    context = dict(packet.get("context_evidence", {}))
    complementary = dict(packet.get("complementary_evidence", {}))
    noise = dict(packet.get("noise_evidence", {}))
    artifact_merkle_tree = dict(packet.get("artifact_merkle_tree", {}))
    evidence_links = [
        {
            "claim": claim_name,
            "check": str(link.get("check", "")),
            "artifact": str(link.get("artifact", "")),
            "json_path": str(link.get("json_path", "")),
            "passed": bool(link.get("passed")),
        }
        for claim_name, claim in sorted(claims.items())
        for link in list(claim.get("evidence", []))
    ]
    return {
        "index_version": 1,
        "artifact_kind": "pettachainer_showcase_evidence_index",
        "packet_root_sha256": packet.get("packet_root_sha256", ""),
        "verdict": packet.get("verdict", {}),
        "roots": packet.get("roots", {}),
        "claims": {
            name: {
                "description": claim.get("description", ""),
                "covered": bool(claim.get("covered")),
                "evidence_complete": bool(claim.get("evidence_complete")),
                "enforced_by": claim.get("enforced_by", []),
                "evidence": claim.get("evidence", []),
            }
            for name, claim in sorted(claims.items())
        },
        "evidence_summary": {
            "claim_count": len(claims),
            "evidence_link_count": len(evidence_links),
            "all_claims_covered": bool(claims)
            and all(bool(claim.get("covered")) for claim in claims.values()),
            "all_claims_have_evidence": bool(claims)
            and all(
                bool(claim.get("evidence_complete")) and bool(claim.get("evidence"))
                for claim in claims.values()
            ),
            "context_noise_levels": [
                int(case.get("extra_packets", 0))
                for case in context.get("noise_stability", [])
            ],
            "context_counterfactual_cases": [
                str(case.get("name", ""))
                for case in context.get("counterfactuals", [])
            ],
            "complementary_summary_sha256": complementary.get("summary_sha256", ""),
            "noise_max_extra_edges": int(noise.get("max_extra_edges", 0)),
            "red_team_case_count": int(red_team.get("case_count", 0)),
            "artifact_merkle_leaf_count": int(
                artifact_merkle_tree.get("leaf_count", 0)
            ),
            "artifact_merkle_root_sha256": artifact_merkle_tree.get(
                "root_sha256", ""
            ),
        },
        "aggregate_roots": {
            name: value
            for name, value in dict(packet.get("roots", {})).items()
            if name.endswith("_root_sha256")
        },
        "evidence_links": evidence_links,
        "artifact_hash_count": len(dict(packet.get("artifact_hashes", {}))),
        "proof_sha256": dict(packet.get("proof_structure", {})).get(
            "proof_sha256", ""
        ),
        "red_team": {
            "case_count": int(red_team.get("case_count", 0)),
            "mutation_families": red_team.get("mutation_families", []),
            "cases": red_team.get("cases", {}),
        },
    }


def evidence_index_markdown(index: dict[str, object]) -> str:
    summary = dict(index.get("evidence_summary", {}))
    lines = [
        "# PeTTaChainer Evidence Index",
        "",
        f"Packet root: `{index.get('packet_root_sha256', '')}`",
        f"Claims: {summary.get('claim_count', 0)}",
        f"Evidence links: {summary.get('evidence_link_count', 0)}",
        f"Red-team cases: {summary.get('red_team_case_count', 0)}",
        "",
        "## Aggregate Roots",
        "",
    ]
    for name, value in sorted(dict(index.get("aggregate_roots", {})).items()):
        lines.append(f"- `{name}`: `{value}`")
    lines.extend(
        [
        "",
        "## Claims",
        "",
        ]
    )
    for name, claim in sorted(dict(index.get("claims", {})).items()):
        evidence = list(claim.get("evidence", []))
        lines.append(
            f"- {'PASS' if claim.get('covered') else 'FAIL'} `{name}` "
            f"({len(evidence)} evidence link(s))"
        )
        for link in evidence:
            lines.append(
                f"  - `{link.get('artifact', '')}{link.get('json_path', '')}` "
                f"-> `{link.get('check', '')}`"
            )
    lines.extend(
        [
            "",
            "## Red Team",
            "",
        ]
    )
    for name, case in sorted(dict(index.get("red_team", {}).get("cases", {})).items()):
        failed = ", ".join(case.get("actual_failed_checks", []))
        lines.append(
            f"- {'PASS' if case.get('rejected') else 'FAIL'} `{name}` -> {failed}"
        )
    return "\n".join(lines) + "\n"


def forensic_packet_markdown(packet: dict[str, object]) -> str:
    verdict = packet.get("verdict", {})
    roots = packet.get("roots", {})
    claims = dict(packet.get("claim_ledger", {}))
    red_team = dict(packet.get("red_team", {}))
    proof = dict(packet.get("proof_structure", {}))
    lines = [
        "# PeTTaChainer Forensic Packet",
        "",
        f"Packet root: `{packet['packet_root_sha256']}`",
        f"Witness root: `{roots.get('witness_root_sha256', '')}`",
        "",
        "## Verdict",
        "",
        f"- Verifier checks: {'PASS' if verdict.get('verifier_checks_pass') else 'FAIL'}",
        f"- Red-team rejections: {'PASS' if verdict.get('red_team_rejections_pass') else 'FAIL'}",
        f"- Artifact hashes bound: {len(dict(packet.get('artifact_hashes', {})))}",
        "",
        "## Contract Claims",
        "",
    ]
    for name, claim in claims.items():
        evidence = list(claim.get("evidence", []))
        lines.append(
            f"- {'PASS' if claim.get('covered') else 'FAIL'} `{name}` "
            f"({len(evidence)} evidence link(s))"
        )
    lines.extend(
        [
            "",
            "## Structural Proof Audit",
            "",
            f"- Certificate: {'PASS' if proof.get('certificate_passes') else 'FAIL'}",
            f"- Proof SHA-256: `{proof.get('proof_sha256', '')}`",
            f"- Operator counts: `{json.dumps(proof.get('operator_counts', {}), sort_keys=True)}`",
            "",
            "## Red Team",
            "",
            f"- Cases: {red_team.get('case_count', 0)}",
            f"- Mutation families: `{', '.join(red_team.get('mutation_families', []))}`",
        ]
    )
    for name, case in dict(red_team.get("cases", {})).items():
        failed = ", ".join(case.get("actual_failed_checks", []))
        lines.append(
            f"- {'PASS' if case.get('rejected') else 'FAIL'} `{name}` -> {failed}"
        )
    return "\n".join(lines) + "\n"


def write_forensic_packet(
    verification: dict[str, object],
    red_team: dict[str, object] | None = None,
) -> dict[str, object]:
    output_dir = Path(str(verification["output_dir"]))
    packet = build_forensic_packet(verification, red_team)
    evidence_index = build_evidence_index(packet)
    json_path = output_dir / "showcase-forensic-packet.json"
    markdown_path = output_dir / "showcase-forensic-packet.md"
    evidence_index_path = output_dir / "showcase-evidence-index.json"
    evidence_index_markdown_path = output_dir / "showcase-evidence-index.md"
    json_path.write_text(
        json.dumps(packet, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(forensic_packet_markdown(packet), encoding="utf-8")
    evidence_index_path.write_text(
        json.dumps(evidence_index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence_index_markdown_path.write_text(
        evidence_index_markdown(evidence_index),
        encoding="utf-8",
    )
    return {
        "json_path": str(json_path),
        "markdown_path": str(markdown_path),
        "evidence_index_path": str(evidence_index_path),
        "evidence_index_markdown_path": str(evidence_index_markdown_path),
        "evidence_index_sha256": hash_file(evidence_index_path),
        "packet_root_sha256": packet["packet_root_sha256"],
        "packet_verified": verify_forensic_packet(json_path),
    }


def verify_forensic_packet_details(
    packet_path: Path,
    *,
    artifact_dir: Path | None = None,
) -> dict[str, object]:
    checks: dict[str, bool] = {"packet_present": packet_path.exists()}
    if not checks["packet_present"]:
        checks["packet_verified"] = False
        return {"packet_path": str(packet_path), "checks": checks}

    packet = load_json(packet_path)
    body = dict(packet)
    root = str(body.pop("packet_root_sha256", ""))
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else Path(str(packet.get("output_dir", packet_path.parent))).resolve()
    )
    roots = dict(packet.get("roots", {}))
    artifact_hashes = dict(packet.get("artifact_hashes", {}))
    artifact_merkle_tree = dict(packet.get("artifact_merkle_tree", {}))
    claims = dict(packet.get("claim_ledger", {}))
    red_team = dict(packet.get("red_team", {}))
    red_team_cases = dict(red_team.get("cases", {}))
    proof = dict(packet.get("proof_structure", {}))
    result_path = output_dir / "showcase-result.json"
    verifier_path = output_dir / "showcase-verifier-result.json"
    red_team_path = output_dir / "showcase-verifier-red-team-result.json"
    witness_path = output_dir / "showcase-witness.json"
    proof_structure_path = output_dir / "incident-bundle" / "proof-structure.json"
    evidence_index_path = output_dir / "showcase-evidence-index.json"
    evidence_index_markdown_path = output_dir / "showcase-evidence-index.md"
    result_source = load_json(result_path) if result_path.exists() else {}
    verifier_source = load_json(verifier_path) if verifier_path.exists() else {}
    red_team_source = load_json(red_team_path) if red_team_path.exists() else {}
    witness = load_json(witness_path) if witness_path.exists() else {}
    proof_source = load_json(proof_structure_path) if proof_structure_path.exists() else {}
    evidence_index = load_json(evidence_index_path) if evidence_index_path.exists() else {}
    expected_evidence_index = build_evidence_index(packet)
    expected_evidence_index_markdown = evidence_index_markdown(expected_evidence_index)
    expected_artifact_merkle_tree = build_artifact_merkle_tree(artifact_hashes)
    expected_aggregate_roots = {
        "artifact_merkle_root_sha256": expected_artifact_merkle_tree["root_sha256"],
        "artifact_hashes_root_sha256": canonical_object_sha256(artifact_hashes),
        "claim_ledger_root_sha256": canonical_object_sha256(claims),
        "context_evidence_root_sha256": canonical_object_sha256(
            packet.get("context_evidence", {})
        ),
        "complementary_evidence_root_sha256": canonical_object_sha256(
            packet.get("complementary_evidence", {})
        ),
        "incident_summary_root_sha256": canonical_object_sha256(
            packet.get("incident_summary", {})
        ),
        "proof_structure_root_sha256": canonical_object_sha256(proof),
        "red_team_root_sha256": canonical_object_sha256(red_team),
    }
    artifact_hash_checks = {
        filename: (
            (output_dir / filename).exists()
            and hash_file(output_dir / filename) == expected_hash
        )
        for filename, expected_hash in artifact_hashes.items()
    }
    verifier_source_hash = str(roots.get("forensic_source_verifier_sha256", ""))
    red_team_source_hash = str(roots.get("forensic_source_red_team_sha256", ""))
    expected_context_evidence = {
        "checks": witness.get("context_evidence", {}).get("checks", {}),
        "noise_stability": witness.get("context_evidence", {}).get(
            "noise_stability", []
        ),
        "counterfactuals": witness.get("context_evidence", {}).get(
            "counterfactuals", []
        ),
    }
    expected_complementary_evidence = witness.get("complementary_evidence", {})
    expected_proof_structure = {
        "certificate_passes": bool(proof_source.get("certificate_passes")),
        "checks": proof_source.get("checks", {}),
        "operator_counts": proof_source.get("operator_counts", {}),
        "forbidden_label_counts": proof_source.get("forbidden_label_counts", {}),
        "proof_sha256": proof_source.get("proof_sha256", ""),
    }
    expected_incident_summary = {
        "query_counts": result_source.get("incident", {}).get("query_counts", {}),
        "proof_sha256": result_source.get("incident", {}).get("proof_sha256", ""),
        "structural_certificate_passes": bool(
            result_source.get("incident", {})
            .get("proof_structure", {})
            .get("certificate_passes")
        ),
    }
    expected_red_team_cases = {
        name: {
            "mutation_family": case.get("mutation_family"),
            "expected_failed_checks": case.get("expected_failed_checks", []),
            "actual_failed_checks": case.get("actual_failed_checks", []),
            "rejected": bool(case.get("rejected")),
        }
        for name, case in sorted(dict(red_team_source.get("cases", {})).items())
    }
    checks.update(
        {
            "kind_matches": (
                packet.get("artifact_kind")
                == "pettachainer_showcase_forensic_packet"
            ),
            "version_matches": packet.get("packet_version") == 1,
            "root_hash_matches": root == canonical_json_sha256(body),
            "verifier_verdict_pass": bool(
                packet.get("verdict", {}).get("verifier_checks_pass")
            ),
            "red_team_verdict_pass": bool(
                packet.get("verdict", {}).get("red_team_rejections_pass")
            ),
            "source_verifier_hash_matches": (
                bool(verifier_source_hash)
                and verifier_path.exists()
                and hash_file(verifier_path) == verifier_source_hash
            ),
            "source_red_team_hash_matches": (
                not red_team_source_hash
                or (
                    red_team_path.exists()
                    and hash_file(red_team_path) == red_team_source_hash
                )
            ),
            "aggregate_roots_match_packet": all(
                roots.get(name) == expected_hash
                for name, expected_hash in expected_aggregate_roots.items()
            ),
            "witness_root_matches": (
                witness_path.exists()
                and witness.get("witness_root_sha256")
                == roots.get("witness_root_sha256")
            ),
            "artifact_hashes_match_witness": artifact_hashes
            == witness.get("artifact_hashes", {}),
            "artifact_hashes_match": bool(artifact_hash_checks)
            and all(artifact_hash_checks.values()),
            "artifact_merkle_tree_matches_hashes": artifact_merkle_tree
            == expected_artifact_merkle_tree,
            "artifact_merkle_root_matches_packet": roots.get(
                "artifact_merkle_root_sha256"
            )
            == artifact_merkle_tree.get("root_sha256"),
            "artifact_merkle_proofs_verify": verify_artifact_merkle_proofs(
                artifact_merkle_tree
            ),
            "claim_ledger_matches_source": claims
            == verifier_source.get("claim_coverage", {}),
            "claim_ledger_passes": bool(claims)
            and all(bool(claim.get("covered")) for claim in claims.values()),
            "claim_ledger_evidence_complete": bool(claims)
            and all(
                bool(claim.get("evidence_complete"))
                and bool(claim.get("evidence"))
                for claim in claims.values()
            ),
            "evidence_index_present": evidence_index_path.exists(),
            "evidence_index_matches_packet": evidence_index == expected_evidence_index,
            "evidence_index_markdown_present": evidence_index_markdown_path.exists(),
            "evidence_index_markdown_matches_packet": (
                evidence_index_markdown_path.exists()
                and evidence_index_markdown_path.read_text(encoding="utf-8")
                == expected_evidence_index_markdown
            ),
            "verifier_checks_match_source": packet.get("verifier_checks", {})
            == verifier_source.get("checks", {}),
            "dispatch_evidence_matches_witness": packet.get("dispatch_evidence", {})
            == witness.get("dispatch_evidence", {}),
            "context_evidence_matches_witness": packet.get("context_evidence", {})
            == expected_context_evidence,
            "complementary_evidence_matches_witness": packet.get(
                "complementary_evidence", {}
            )
            == expected_complementary_evidence,
            "noise_evidence_matches_witness": packet.get("noise_evidence", {})
            == witness.get("noise_evidence", {}),
            "incident_summary_matches_source": packet.get("incident_summary", {})
            == expected_incident_summary,
            "red_team_cases_match_count": int(red_team.get("case_count", -1))
            == len(red_team_cases),
            "red_team_cases_rejected": bool(red_team_cases)
            and all(bool(case.get("rejected")) for case in red_team_cases.values()),
            "red_team_cases_match_source": (
                not red_team_source_hash or red_team_cases == expected_red_team_cases
            ),
            "red_team_mutation_families_match_source": (
                not red_team_source_hash
                or red_team.get("mutation_families", [])
                == red_team_source.get("mutation_families", [])
            ),
            "proof_structure_matches_source": proof == expected_proof_structure,
            "proof_structure_passes": bool(proof.get("certificate_passes"))
            and all(bool(value) for value in dict(proof.get("checks", {})).values()),
        }
    )
    checks["packet_verified"] = all(checks.values())
    return {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "packet_root_sha256": root,
        "checks": checks,
        "artifact_hash_checks": artifact_hash_checks,
        "evidence_index_path": str(evidence_index_path),
        "evidence_index_sha256": hash_file(evidence_index_path)
        if evidence_index_path.exists()
        else "",
        "evidence_index_markdown_path": str(evidence_index_markdown_path),
        "evidence_index_markdown_sha256": hash_file(evidence_index_markdown_path)
        if evidence_index_markdown_path.exists()
        else "",
        "aggregate_root_checks": {
            name: roots.get(name) == expected_hash
            for name, expected_hash in expected_aggregate_roots.items()
        },
    }


def verify_forensic_packet(packet_path: Path, *, artifact_dir: Path | None = None) -> bool:
    return bool(
        verify_forensic_packet_details(packet_path, artifact_dir=artifact_dir)["checks"][
            "packet_verified"
        ]
    )


def seal_sweep_case_name(filename: str) -> str:
    return (
        filename.replace("/", "__")
        .replace("\\", "__")
        .replace(".", "_")
        .replace("-", "_")
    )


def tamper_bound_artifact(path: Path) -> None:
    if path.suffix == ".json":
        payload = load_json(path)
        if isinstance(payload, dict):
            payload["_forensic_seal_sweep_tamper"] = True
        else:
            payload = {
                "_forensic_seal_sweep_tamper": True,
                "payload": payload,
            }
        write_json(path, payload)
        return
    path.write_text(
        path.read_text(encoding="utf-8") + "\nforensic-seal-sweep-tamper\n",
        encoding="utf-8",
    )


def verify_artifact_hash_seal(
    packet: dict[str, Any],
    artifact_dir: Path,
) -> dict[str, object]:
    artifact_hashes = dict(packet.get("artifact_hashes", {}))
    artifact_hash_checks = {
        filename: (
            (artifact_dir / filename).exists()
            and hash_file(artifact_dir / filename) == expected_hash
        )
        for filename, expected_hash in artifact_hashes.items()
    }
    return {
        "artifact_hash_checks": artifact_hash_checks,
        "artifact_hashes_match": bool(artifact_hash_checks)
        and all(artifact_hash_checks.values()),
    }


def run_forensic_seal_sweep(
    output_dir: Path,
    *,
    packet_path: Path | None = None,
    sweep_dir: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    packet_path = (packet_path or output_dir / "showcase-forensic-packet.json").resolve()
    packet = load_json(packet_path)
    artifacts = sorted(dict(packet.get("artifact_hashes", {})))
    baseline = verify_forensic_packet_details(packet_path, artifact_dir=output_dir)
    baseline_verified = bool(baseline["checks"].get("packet_verified"))
    sweep_dir = (
        sweep_dir.resolve()
        if sweep_dir is not None
        else output_dir.parent / f"{output_dir.name}-forensic-seal-sweep"
    )
    if sweep_dir.exists():
        shutil.rmtree(sweep_dir)
    sweep_dir.mkdir(parents=True)

    cases: dict[str, dict[str, object]] = {}
    for filename in artifacts:
        case_dir = sweep_dir / seal_sweep_case_name(filename)
        shutil.copytree(output_dir, case_dir)
        target = case_dir / filename
        tamper_bound_artifact(target)
        seal = verify_artifact_hash_seal(packet, case_dir)
        artifact_hash_checks = dict(seal["artifact_hash_checks"])
        artifact_hashes_match = bool(seal["artifact_hashes_match"])
        rejected = (
            baseline_verified
            and not artifact_hashes_match
            and not bool(artifact_hash_checks.get(filename, True))
        )
        cases[filename] = {
            "case_dir": str(case_dir),
            "rejected": rejected,
            "failed_artifact_hash": not bool(artifact_hash_checks.get(filename, True)),
            "packet_verified": False if rejected else baseline_verified,
            "artifact_hashes_match": artifact_hashes_match,
        }

    summary = {
        "packet_path": str(packet_path),
        "sweep_dir": str(sweep_dir),
        "baseline_packet_verified": baseline_verified,
        "artifact_count": len(artifacts),
        "cases": cases,
        "seal_sweep_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-forensic-seal-sweep-result.json"),
    }
    Path(summary["result_path"]).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def recompute_packet_root(packet: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in packet.items() if key != "packet_root_sha256"}
    return {**body, "packet_root_sha256": canonical_json_sha256(body)}


def run_forensic_packet_red_team(
    packet_path: Path,
    *,
    artifact_dir: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    packet_path = packet_path.resolve()
    packet = load_json(packet_path)
    output_dir = (
        artifact_dir.resolve()
        if artifact_dir is not None
        else Path(str(packet.get("output_dir", packet_path.parent))).resolve()
    )
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir.parent / f"{output_dir.name}-forensic-packet-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    baseline = verify_forensic_packet_details(packet_path, artifact_dir=output_dir)
    baseline_verified = bool(baseline["checks"].get("packet_verified"))

    def first_key(mapping: dict[str, object]) -> str:
        return next(iter(sorted(mapping)))

    def mutate_verdict(forged: dict[str, Any]) -> None:
        forged["verdict"]["verifier_checks_pass"] = False

    def mutate_source_verifier_hash(forged: dict[str, Any]) -> None:
        forged["roots"]["forensic_source_verifier_sha256"] = "0" * 64

    def mutate_source_red_team_hash(forged: dict[str, Any]) -> None:
        forged["roots"]["forensic_source_red_team_sha256"] = "0" * 64

    def mutate_aggregate_root(forged: dict[str, Any]) -> None:
        forged["roots"]["claim_ledger_root_sha256"] = "0" * 64

    def mutate_witness_root(forged: dict[str, Any]) -> None:
        forged["roots"]["witness_root_sha256"] = "0" * 64

    def mutate_artifact_hash(forged: dict[str, Any]) -> None:
        artifact_hashes = dict(forged["artifact_hashes"])
        artifact_hashes[first_key(artifact_hashes)] = "0" * 64
        forged["artifact_hashes"] = artifact_hashes

    def mutate_artifact_merkle_root(forged: dict[str, Any]) -> None:
        forged["artifact_merkle_tree"]["root_sha256"] = "0" * 64

    def mutate_artifact_merkle_proof(forged: dict[str, Any]) -> None:
        proofs = forged["artifact_merkle_tree"]["proofs"]
        first_path = first_key(proofs)
        proofs[first_path][0]["sha256"] = "0" * 64

    def mutate_claim_ledger(forged: dict[str, Any]) -> None:
        claims = forged["claim_ledger"]
        claim = claims[first_key(claims)]
        evidence = list(claim.get("evidence", []))
        if evidence:
            evidence[0]["artifact"] = "forged-verifier-result.json"
            claim["evidence"] = evidence
        else:
            claim["description"] = "forged claim description"

    def mutate_verifier_checks(forged: dict[str, Any]) -> None:
        checks = dict(forged["verifier_checks"])
        name = next(key for key in sorted(checks) if bool(checks[key]))
        checks[name] = False
        forged["verifier_checks"] = checks

    def mutate_dispatch_evidence(forged: dict[str, Any]) -> None:
        dispatch = forged["dispatch_evidence"]
        if "smart" in dispatch and isinstance(dispatch["smart"], dict):
            dispatch["smart"]["codegen_marker"] = "dynamic_reduce"
            return
        dispatch[first_key(dispatch)] = {"codegen_marker": "forged"}

    def mutate_context_evidence(forged: dict[str, Any]) -> None:
        forged["context_evidence"]["counterfactuals"][0]["passed"] = False

    def mutate_complementary_evidence(forged: dict[str, Any]) -> None:
        forged["complementary_evidence"]["summary_lines"][0] = (
            forged["complementary_evidence"]["summary_lines"][0].replace(
                "merge/additive-complement",
                "merge/highest-confidence",
            )
        )

    def mutate_noise_evidence(forged: dict[str, Any]) -> None:
        forged["noise_evidence"]["cases"][0]["stable"] = False

    def mutate_incident_summary(forged: dict[str, Any]) -> None:
        forged["incident_summary"]["proof_sha256"] = "0" * 64

    def mutate_proof_structure(forged: dict[str, Any]) -> None:
        forged["proof_structure"]["certificate_passes"] = False

    def mutate_red_team_case(forged: dict[str, Any]) -> None:
        cases = forged["red_team"]["cases"]
        cases[first_key(cases)]["rejected"] = False

    def mutate_red_team_count(forged: dict[str, Any]) -> None:
        forged["red_team"]["case_count"] = int(forged["red_team"]["case_count"]) + 1

    mutation_specs = {
        "verdict_forgery": {
            "mutate": mutate_verdict,
            "expected_failed_checks": ["verifier_verdict_pass"],
        },
        "source_verifier_hash_forgery": {
            "mutate": mutate_source_verifier_hash,
            "expected_failed_checks": ["source_verifier_hash_matches"],
        },
        "source_red_team_hash_forgery": {
            "mutate": mutate_source_red_team_hash,
            "expected_failed_checks": ["source_red_team_hash_matches"],
        },
        "aggregate_root_forgery": {
            "mutate": mutate_aggregate_root,
            "expected_failed_checks": [
                "aggregate_roots_match_packet",
                "evidence_index_matches_packet",
                "evidence_index_markdown_matches_packet",
            ],
        },
        "witness_root_forgery": {
            "mutate": mutate_witness_root,
            "expected_failed_checks": ["witness_root_matches"],
        },
        "artifact_hash_forgery": {
            "mutate": mutate_artifact_hash,
            "expected_failed_checks": [
                "artifact_hashes_match_witness",
                "artifact_hashes_match",
                "artifact_merkle_tree_matches_hashes",
            ],
        },
        "artifact_merkle_root_forgery": {
            "mutate": mutate_artifact_merkle_root,
            "expected_failed_checks": [
                "artifact_merkle_tree_matches_hashes",
                "artifact_merkle_root_matches_packet",
                "artifact_merkle_proofs_verify",
            ],
        },
        "artifact_merkle_proof_forgery": {
            "mutate": mutate_artifact_merkle_proof,
            "expected_failed_checks": [
                "artifact_merkle_tree_matches_hashes",
                "artifact_merkle_proofs_verify",
            ],
        },
        "claim_ledger_forgery": {
            "mutate": mutate_claim_ledger,
            "expected_failed_checks": ["claim_ledger_matches_source"],
        },
        "verifier_checks_forgery": {
            "mutate": mutate_verifier_checks,
            "expected_failed_checks": ["verifier_checks_match_source"],
        },
        "dispatch_evidence_forgery": {
            "mutate": mutate_dispatch_evidence,
            "expected_failed_checks": ["dispatch_evidence_matches_witness"],
        },
        "context_evidence_forgery": {
            "mutate": mutate_context_evidence,
            "expected_failed_checks": ["context_evidence_matches_witness"],
        },
        "complementary_evidence_forgery": {
            "mutate": mutate_complementary_evidence,
            "expected_failed_checks": ["complementary_evidence_matches_witness"],
        },
        "noise_evidence_forgery": {
            "mutate": mutate_noise_evidence,
            "expected_failed_checks": ["noise_evidence_matches_witness"],
        },
        "incident_summary_forgery": {
            "mutate": mutate_incident_summary,
            "expected_failed_checks": ["incident_summary_matches_source"],
        },
        "proof_structure_forgery": {
            "mutate": mutate_proof_structure,
            "expected_failed_checks": [
                "proof_structure_matches_source",
                "proof_structure_passes",
            ],
        },
        "red_team_case_forgery": {
            "mutate": mutate_red_team_case,
            "expected_failed_checks": [
                "red_team_cases_rejected",
                "red_team_cases_match_source",
            ],
        },
        "red_team_count_forgery": {
            "mutate": mutate_red_team_count,
            "expected_failed_checks": ["red_team_cases_match_count"],
        },
    }

    cases: dict[str, dict[str, object]] = {}
    for name, spec in mutation_specs.items():
        forged = json.loads(json.dumps(packet))
        expected_failed = list(spec["expected_failed_checks"])
        forged_path = red_team_dir / f"{name}.json"
        try:
            spec["mutate"](forged)
        except (KeyError, IndexError, StopIteration, TypeError, ValueError) as exc:
            cases[name] = {
                "path": str(forged_path),
                "skipped": True,
                "skip_reason": type(exc).__name__,
                "expected_failed_checks": expected_failed,
                "rejected": False,
            }
            continue
        forged = recompute_packet_root(forged)
        write_json(forged_path, forged)
        details = verify_forensic_packet_details(forged_path, artifact_dir=output_dir)
        checks = dict(details["checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and bool(checks.get("root_hash_matches"))
            and not bool(checks.get("packet_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "path": str(forged_path),
            "skipped": False,
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "root_hash_matches": bool(checks.get("root_hash_matches")),
            "packet_verified": bool(checks.get("packet_verified")),
            "rejected": rejected,
        }

    applied_cases = {
        name: case for name, case in cases.items() if not bool(case.get("skipped"))
    }
    summary = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "red_team_dir": str(red_team_dir),
        "baseline_packet_verified": baseline_verified,
        "case_count": len(applied_cases),
        "skipped_case_count": len(cases) - len(applied_cases),
        "cases": cases,
        "packet_red_team_pass": baseline_verified
        and bool(applied_cases)
        and all(bool(case["rejected"]) for case in applied_cases.values()),
        "result_path": str(output_dir / "showcase-forensic-packet-red-team-result.json"),
    }
    Path(summary["result_path"]).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def run_evidence_index_red_team(
    output_dir: Path,
    *,
    packet_path: Path | None = None,
    red_team_dir: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.resolve()
    packet_path = (packet_path or output_dir / "showcase-forensic-packet.json").resolve()
    red_team_dir = (
        red_team_dir.resolve()
        if red_team_dir is not None
        else output_dir.parent / f"{output_dir.name}-evidence-index-red-team"
    )
    if red_team_dir.exists():
        shutil.rmtree(red_team_dir)
    red_team_dir.mkdir(parents=True)

    try:
        packet_relative_path = packet_path.relative_to(output_dir)
    except ValueError:
        packet_relative_path = Path(packet_path.name)

    baseline = verify_forensic_packet_details(packet_path, artifact_dir=output_dir)
    baseline_verified = bool(baseline["checks"].get("packet_verified"))

    def mutate_index_json(case_dir: Path) -> None:
        index_path = case_dir / "showcase-evidence-index.json"
        index = load_json(index_path)
        index["evidence_summary"]["claim_count"] = 0
        write_json(index_path, index)

    def mutate_index_markdown(case_dir: Path) -> None:
        markdown_path = case_dir / "showcase-evidence-index.md"
        markdown_path.write_text(
            markdown_path.read_text(encoding="utf-8")
            + "\nforged-evidence-index-line\n",
            encoding="utf-8",
        )

    specs = {
        "evidence_index_json_forgery": {
            "mutate": mutate_index_json,
            "expected_failed_checks": [
                "evidence_index_matches_packet",
                "packet_verified",
            ],
        },
        "evidence_index_markdown_forgery": {
            "mutate": mutate_index_markdown,
            "expected_failed_checks": [
                "evidence_index_markdown_matches_packet",
                "packet_verified",
            ],
        },
    }

    cases: dict[str, dict[str, object]] = {}
    for name, spec in specs.items():
        case_dir = red_team_dir / name
        shutil.copytree(output_dir, case_dir)
        expected_failed = list(spec["expected_failed_checks"])
        spec["mutate"](case_dir)
        case_packet_path = case_dir / packet_relative_path
        details = verify_forensic_packet_details(case_packet_path, artifact_dir=case_dir)
        checks = dict(details["checks"])
        missing_expected_failures = [
            check for check in expected_failed if bool(checks.get(check))
        ]
        rejected = (
            baseline_verified
            and bool(checks.get("root_hash_matches"))
            and not bool(checks.get("packet_verified"))
            and not missing_expected_failures
        )
        cases[name] = {
            "path": str(case_dir),
            "expected_failed_checks": expected_failed,
            "actual_failed_checks": [
                check for check, passed in checks.items() if not bool(passed)
            ],
            "missing_expected_failures": missing_expected_failures,
            "root_hash_matches": bool(checks.get("root_hash_matches")),
            "packet_verified": bool(checks.get("packet_verified")),
            "rejected": rejected,
        }

    summary = {
        "packet_path": str(packet_path),
        "artifact_dir": str(output_dir),
        "red_team_dir": str(red_team_dir),
        "baseline_packet_verified": baseline_verified,
        "case_count": len(cases),
        "cases": cases,
        "evidence_index_red_team_pass": baseline_verified
        and bool(cases)
        and all(bool(case["rejected"]) for case in cases.values()),
        "result_path": str(output_dir / "showcase-evidence-index-red-team-result.json"),
    }
    Path(summary["result_path"]).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def print_text(verification: dict[str, object]) -> None:
    checks = verification["checks"]
    print("PeTTaChainer showcase artifact verifier")
    print(f"Output: {verification['output_dir']}")
    print(f"Noise replay: {'enabled' if verification['replay_noise'] else 'skipped'}")
    print(f"Context replay: {'enabled' if verification['replay_context'] else 'skipped'}")
    print(
        "Complementary evidence replay: "
        f"{'enabled' if verification['replay_complementary'] else 'skipped'}"
    )
    print(
        "Context noise replay: "
        f"{'enabled' if verification['replay_context_noise'] else 'skipped'}"
    )
    print(
        "Context counterfactual replay: "
        f"{'enabled' if verification['replay_context_counterfactuals'] else 'skipped'}"
    )
    print()
    print("Verifier checks")
    for name, passed in checks.items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")
    if "claim_coverage" in verification:
        print()
        print("Contract claims")
        for name, claim in verification["claim_coverage"].items():
            print(f"- {'PASS' if claim['covered'] else 'FAIL'} {name}")
    if "result_path" in verification:
        print()
        print(f"JSON: {verification['result_path']}")
    if "forensic_packet" in verification:
        packet = verification["forensic_packet"]
        print(f"Forensic packet: {packet['json_path']}")
        print(f"Forensic packet root: {packet['packet_root_sha256']}")


def print_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Red-team checks")
    for name, result in red_team["cases"].items():
        print(f"- {'PASS' if result['rejected'] else 'FAIL'} {name}")
    print(f"Red-team JSON: {red_team['result_path']}")


def print_forensic_packet_details(details: dict[str, object]) -> None:
    print("PeTTaChainer forensic packet verifier")
    print(f"Packet: {details['packet_path']}")
    print(f"Artifact dir: {details.get('artifact_dir', '')}")
    print(f"Packet root: {details.get('packet_root_sha256', '')}")
    print()
    print("Packet checks")
    for name, passed in details["checks"].items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_forensic_seal_sweep(sweep: dict[str, object]) -> None:
    print()
    print("Forensic seal sweep")
    print(f"Artifacts: {sweep['artifact_count']}")
    print(f"Sweep: {'PASS' if sweep['seal_sweep_pass'] else 'FAIL'}")
    print(f"JSON: {sweep['result_path']}")


def print_forensic_packet_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Forensic packet red-team")
    print(f"Cases: {red_team['case_count']}")
    print(f"Skipped: {red_team['skipped_case_count']}")
    print(f"Packet red-team: {'PASS' if red_team['packet_red_team_pass'] else 'FAIL'}")
    print(f"JSON: {red_team['result_path']}")


def print_evidence_index_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Evidence index red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Evidence index red-team: "
        f"{'PASS' if red_team['evidence_index_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_artifact_inclusion(inclusion: dict[str, object]) -> None:
    print()
    print("Artifact inclusion proof")
    print(f"Artifact: {inclusion['artifact_key']}")
    print(f"Artifact SHA-256: {inclusion.get('artifact_sha256', '')}")
    print(f"Leaf SHA-256: {inclusion.get('leaf_sha256', '')}")
    print(f"Merkle root: {inclusion.get('computed_merkle_root_sha256', '')}")
    print(f"Proof length: {inclusion.get('proof_length', 0)}")
    print("Inclusion checks")
    for name, passed in dict(inclusion["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_claim_evidence(claim: dict[str, object]) -> None:
    print()
    print("Claim evidence proof")
    print(f"Claim: {claim['claim_id']}")
    print(f"Evidence links: {claim.get('evidence_link_count', 0)}")
    print("Evidence")
    for link in list(claim.get("evidence", [])):
        print(
            f"- {'PASS' if link.get('resolved_matches_expected') else 'FAIL'} "
            f"{link.get('artifact', '')}{link.get('json_path', '')} "
            f"-> {link.get('check', '')} "
            f"[{link.get('source_hash_anchor', 'unbound')}]"
        )
    print("Claim checks")
    for name, passed in dict(claim["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_claim_sweep(sweep: dict[str, object]) -> None:
    print()
    print("Claim evidence sweep")
    print(f"Claims: {sweep.get('claim_count', 0)}")
    print(f"Verified claims: {sweep.get('verified_claim_count', 0)}")
    print(f"Evidence links: {sweep.get('evidence_link_count', 0)}")
    print(
        "Sealed sources: "
        f"{sweep.get('sealed_source_count', 0)}/{sweep.get('evidence_link_count', 0)}"
    )
    print(
        "Source anchors: "
        f"{json.dumps(sweep.get('source_anchor_counts', {}), sort_keys=True)}"
    )
    failed = list(sweep.get("failed_claims", []))
    failed_text = ", ".join(str(item) for item in failed) if failed else "none"
    print(f"Failed claims: {failed_text}")
    if "result_path" in sweep:
        print(f"JSON: {sweep['result_path']}")
    if "claim_certificate_path" in sweep:
        print(f"Claim certificate JSON: {sweep['claim_certificate_path']}")
    if "claim_certificate_markdown_path" in sweep:
        print(f"Claim certificate Markdown: {sweep['claim_certificate_markdown_path']}")
    if "claim_certificate_sha256" in sweep:
        print(f"Claim certificate SHA-256: {sweep['claim_certificate_sha256']}")
    print("Claim sweep checks")
    for name, passed in dict(sweep["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_claim_certificate_verification(certificate: dict[str, object]) -> None:
    print()
    print("Claim certificate verification")
    print(f"Certificate: {certificate['certificate_path']}")
    print(f"Markdown: {certificate['certificate_markdown_path']}")
    print(f"Certificate SHA-256: {certificate.get('certificate_sha256', '')}")
    print(
        "Claims: "
        f"{certificate.get('verified_claim_count', 0)}/{certificate.get('claim_count', 0)}"
    )
    print(
        "Sealed sources: "
        f"{certificate.get('sealed_source_count', 0)}/"
        f"{certificate.get('evidence_link_count', 0)}"
    )
    print(
        "Source anchors: "
        f"{json.dumps(certificate.get('source_anchor_counts', {}), sort_keys=True)}"
    )
    print("Claim certificate checks")
    for name, passed in dict(certificate["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_claim_certificate_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Claim certificate red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Claim certificate red-team: "
        f"{'PASS' if red_team['claim_certificate_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_audit_verdict(verdict: dict[str, object]) -> None:
    print()
    print("Audit verdict")
    print(f"Verdict: {verdict.get('verdict', 'FAIL')}")
    print(f"Audit verdict SHA-256: {verdict.get('audit_verdict_sha256', '')}")
    print(f"Claims: {verdict.get('verified_claim_count', 0)}/{verdict.get('claim_count', 0)}")
    print(
        "Sealed sources: "
        f"{verdict.get('sealed_source_count', 0)}/{verdict.get('evidence_link_count', 0)}"
    )
    print(f"Red-team cases: {verdict.get('red_team_case_count_total', 0)}")
    print(f"JSON: {verdict.get('result_path', '')}")
    print(f"Markdown: {verdict.get('markdown_path', '')}")
    print("Audit checks")
    for name, passed in dict(verdict.get("component_checks", {})).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_verdict_verification(verdict: dict[str, object]) -> None:
    print()
    print("Audit verdict verification")
    print(f"Audit verdict: {verdict['audit_verdict_path']}")
    print(f"Markdown: {verdict['audit_verdict_markdown_path']}")
    print(f"Verdict: {verdict.get('verdict', 'FAIL')}")
    print(f"Audit verdict SHA-256: {verdict.get('audit_verdict_sha256', '')}")
    print(
        "Claims: "
        f"{verdict.get('verified_claim_count', 0)}/{verdict.get('claim_count', 0)}"
    )
    print(
        "Sealed sources: "
        f"{verdict.get('sealed_source_count', 0)}/"
        f"{verdict.get('evidence_link_count', 0)}"
    )
    print(f"Red-team cases: {verdict.get('red_team_case_count_total', 0)}")
    print("Audit verdict checks")
    for name, passed in dict(verdict["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_verdict_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Audit verdict red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Audit verdict red-team: "
        f"{'PASS' if red_team['audit_verdict_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_audit_proof_graph(graph: dict[str, object]) -> None:
    print()
    print("Audit proof graph")
    print(f"Verdict: {graph.get('verdict', 'FAIL')}")
    print(f"Proof graph SHA-256: {graph.get('proof_graph_sha256', '')}")
    print(f"Nodes: {graph.get('node_count', 0)}")
    print(f"Edges: {graph.get('edge_count', 0)}")
    print(
        "Claims: "
        f"{graph.get('verified_claim_count', 0)}/{graph.get('claim_count', 0)}"
    )
    print(
        "Sealed sources: "
        f"{graph.get('sealed_source_count', 0)}/{graph.get('evidence_link_count', 0)}"
    )
    print(f"JSON: {graph.get('result_path', '')}")
    print(f"Markdown: {graph.get('markdown_path', '')}")
    print(f"DOT: {graph.get('dot_path', '')}")


def print_audit_proof_graph_verification(graph: dict[str, object]) -> None:
    print()
    print("Audit proof graph verification")
    print(f"Proof graph: {graph['audit_proof_graph_path']}")
    print(f"Markdown: {graph['audit_proof_graph_markdown_path']}")
    print(f"DOT: {graph['audit_proof_graph_dot_path']}")
    print(f"Proof graph SHA-256: {graph.get('proof_graph_sha256', '')}")
    print(f"Nodes: {graph.get('node_count', 0)}")
    print(f"Edges: {graph.get('edge_count', 0)}")
    print(
        "Claims: "
        f"{graph.get('verified_claim_count', 0)}/{graph.get('claim_count', 0)}"
    )
    print(
        "Sealed sources: "
        f"{graph.get('sealed_source_count', 0)}/{graph.get('evidence_link_count', 0)}"
    )
    print("Audit proof graph checks")
    for name, passed in dict(graph["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_proof_graph_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Audit proof graph red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Audit proof graph red-team: "
        f"{'PASS' if red_team['audit_proof_graph_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_audit_capsule(capsule: dict[str, object]) -> None:
    print()
    print("Audit capsule")
    print(f"Audit capsule SHA-256: {capsule.get('audit_capsule_sha256', '')}")
    print(f"File manifest root: {capsule.get('file_manifest_root_sha256', '')}")
    print(f"Files: {capsule.get('file_count', 0)}")
    print(
        "Required roles: "
        f"{json.dumps(capsule.get('artifact_roles', {}), sort_keys=True)}"
    )
    print(f"JSON: {capsule.get('result_path', '')}")
    print(f"Markdown: {capsule.get('markdown_path', '')}")


def print_audit_capsule_verification(capsule: dict[str, object]) -> None:
    print()
    print("Audit capsule verification")
    print(f"Audit capsule: {capsule['audit_capsule_path']}")
    print(f"Markdown: {capsule['audit_capsule_markdown_path']}")
    print(f"Audit capsule SHA-256: {capsule.get('audit_capsule_sha256', '')}")
    print(f"File manifest root: {capsule.get('file_manifest_root_sha256', '')}")
    print(f"Files: {capsule.get('file_count', 0)}")
    print("Audit capsule checks")
    for name, passed in dict(capsule["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_capsule_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Audit capsule red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Audit capsule red-team: "
        f"{'PASS' if red_team['audit_capsule_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_audit_capsule_archive(archive: dict[str, object]) -> None:
    print()
    print("Audit capsule archive")
    print(f"Archive: {archive['archive_path']}")
    print(f"Archive SHA-256: {archive.get('archive_sha256', '')}")
    print(f"Archive manifest SHA-256: {archive.get('archive_manifest_sha256', '')}")
    print(f"Entries: {archive.get('entry_count', 0)}")


def print_audit_capsule_archive_verification(archive: dict[str, object]) -> None:
    print()
    print("Audit capsule archive verification")
    print(f"Archive: {archive['archive_path']}")
    print(f"Archive SHA-256: {archive.get('archive_sha256', '')}")
    print(f"Archive manifest SHA-256: {archive.get('archive_manifest_sha256', '')}")
    print(
        "Entries: "
        f"{archive.get('archive_entry_count', 0)}/"
        f"{archive.get('expected_entry_count', 0)}"
    )
    print("Audit capsule archive checks")
    for name, passed in dict(archive["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_capsule_archive_red_team(red_team: dict[str, object]) -> None:
    print()
    print("Audit capsule archive red-team")
    print(f"Cases: {red_team['case_count']}")
    print(
        "Audit capsule archive red-team: "
        f"{'PASS' if red_team['audit_capsule_archive_red_team_pass'] else 'FAIL'}"
    )
    print(f"JSON: {red_team['result_path']}")


def print_audit_challenge_transcript(transcript: dict[str, object]) -> None:
    print()
    print("Audit challenge transcript")
    print(f"Verdict: {transcript.get('verdict', '')}")
    print(
        "Audit challenge transcript SHA-256: "
        f"{transcript.get('audit_challenge_transcript_sha256', '')}"
    )
    print(f"Observed cases: {transcript.get('observed_case_count', 0)}")
    print(f"Rejected cases: {transcript.get('rejected_case_count', 0)}")
    print(f"JSON: {transcript.get('result_path', '')}")
    print(f"Markdown: {transcript.get('markdown_path', '')}")


def print_audit_challenge_transcript_verification(
    transcript: dict[str, object],
) -> None:
    print()
    print("Audit challenge transcript verification")
    print(f"Transcript: {transcript['audit_challenge_transcript_path']}")
    print(f"Markdown: {transcript['audit_challenge_transcript_markdown_path']}")
    print(f"Verdict: {transcript.get('verdict', '')}")
    print(
        "Audit challenge transcript SHA-256: "
        f"{transcript.get('audit_challenge_transcript_sha256', '')}"
    )
    print("Audit challenge transcript checks")
    for name, passed in dict(transcript["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_decision_certificate(decision: dict[str, object]) -> None:
    print()
    print("Audit decision certificate")
    print(f"Verdict: {decision.get('verdict', '')}")
    print(f"Audit decision SHA-256: {decision.get('audit_decision_sha256', '')}")
    print(f"Subjects: {decision.get('subject_count', 0)}")
    print(f"Subject manifest SHA-256: {decision.get('subject_manifest_sha256', '')}")
    print(f"JSON: {decision.get('result_path', '')}")


def print_audit_decision_verification(decision: dict[str, object]) -> None:
    print()
    print("Audit decision verification")
    print(f"Audit decision: {decision['audit_decision_path']}")
    print(f"Verdict: {decision.get('verdict', '')}")
    print(f"Audit decision SHA-256: {decision.get('audit_decision_sha256', '')}")
    print("Audit decision checks")
    for name, passed in dict(decision["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_board(board: dict[str, object]) -> None:
    print()
    print("Audit board")
    print(f"Verdict: {board.get('verdict', '')}")
    print(f"Audit board SHA-256: {board.get('audit_board_sha256', '')}")
    print(f"Controls: {len(list(board.get('controls', [])))}")
    print(f"Rejected forged cases: {board.get('red_team_rejected_cases', 0)}")
    print(f"JSON: {board.get('result_path', '')}")
    print(f"Markdown: {board.get('markdown_path', '')}")


def print_audit_board_verification(board: dict[str, object]) -> None:
    print()
    print("Audit board verification")
    print(f"Audit board: {board['audit_board_path']}")
    print(f"Markdown: {board['audit_board_markdown_path']}")
    print(f"Verdict: {board.get('verdict', '')}")
    print(f"Audit board SHA-256: {board.get('audit_board_sha256', '')}")
    print("Audit board checks")
    for name, passed in dict(board["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def print_audit_facts(facts: dict[str, object]) -> None:
    print()
    print("PeTTa audit facts")
    print(f"Verdict: {facts.get('verdict', '')}")
    print(f"Audit facts SHA-256: {facts.get('audit_facts_sha256', '')}")
    print(f"PeTTa source SHA-256: {facts.get('metta_source_sha256', '')}")
    print(f"Controls: {facts.get('control_count', 0)}")
    print(f"Rejected cases: {facts.get('red_team_rejected_cases', 0)}")
    print(f"JSON: {facts.get('result_path', '')}")
    print(f"PeTTa: {facts.get('metta_file_path', facts.get('metta_path', ''))}")


def print_audit_facts_verification(facts: dict[str, object]) -> None:
    print()
    print("PeTTa audit facts verification")
    print(f"Facts: {facts['audit_facts_path']}")
    print(f"PeTTa: {facts['audit_facts_metta_path']}")
    print(f"Verdict: {facts.get('verdict', '')}")
    print(f"Audit facts SHA-256: {facts.get('audit_facts_sha256', '')}")
    print("PeTTa audit facts checks")
    for name, passed in dict(facts["checks"]).items():
        print(f"- {'PASS' if passed else 'FAIL'} {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_dir",
        nargs="?",
        type=Path,
        default=Path("/tmp/pettachainer-showcase"),
    )
    parser.add_argument("--no-noise-replay", action="store_true")
    parser.add_argument("--no-context-replay", action="store_true")
    parser.add_argument("--no-complementary-replay", action="store_true")
    parser.add_argument("--no-context-noise-replay", action="store_true")
    parser.add_argument("--no-context-counterfactual-replay", action="store_true")
    parser.add_argument(
        "--red-team",
        action="store_true",
        help="Copy the artifact directory, corrupt it in known ways, and require rejection",
    )
    parser.add_argument(
        "--red-team-dir",
        type=Path,
        default=None,
        help="Directory for forged artifact copies; defaults beside output_dir",
    )
    parser.add_argument(
        "--verify-forensic-packet",
        type=Path,
        default=None,
        help="Verify an existing showcase-forensic-packet.json without rerunning replay",
    )
    parser.add_argument(
        "--forensic-seal-sweep",
        action="store_true",
        help="Mutate each packet-bound artifact in copied directories and require rejection",
    )
    parser.add_argument(
        "--forensic-packet-red-team",
        action="store_true",
        help="Forge packet fields, recompute packet roots, and require semantic rejection",
    )
    parser.add_argument(
        "--evidence-index-red-team",
        action="store_true",
        help="Forge the derived evidence-index files and require packet verification rejection",
    )
    parser.add_argument(
        "--verify-artifact-inclusion",
        type=Path,
        default=None,
        help="Verify one artifact path against the packet's Merkle inclusion proof",
    )
    parser.add_argument(
        "--verify-claim",
        type=str,
        default=None,
        help="Verify one acceptance claim against packet evidence links",
    )
    parser.add_argument(
        "--verify-all-claims",
        action="store_true",
        help="Verify every packet claim against its linked source evidence",
    )
    parser.add_argument(
        "--verify-claim-certificate",
        type=Path,
        default=None,
        help="Verify a showcase-claim-certificate.json against the packet and source evidence",
    )
    parser.add_argument(
        "--claim-certificate-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-claim-certificate; defaults beside JSON",
    )
    parser.add_argument(
        "--claim-certificate-red-team",
        action="store_true",
        help="Forge claim certificate JSON/Markdown fields and require rejection",
    )
    parser.add_argument(
        "--audit-verdict",
        action="store_true",
        help="Run the full audit stack and write showcase-audit-verdict.json/.md",
    )
    parser.add_argument(
        "--verify-audit-verdict",
        type=Path,
        default=None,
        help="Verify a showcase-audit-verdict.json against all supporting artifacts",
    )
    parser.add_argument(
        "--audit-verdict-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-audit-verdict; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-verdict-red-team",
        action="store_true",
        help="Forge audit verdict JSON/Markdown fields and require rejection",
    )
    parser.add_argument(
        "--audit-proof-graph",
        action="store_true",
        help="Write showcase-audit-proof-graph.json/.md/.dot linking verdict, claims, evidence, and sealed sources",
    )
    parser.add_argument(
        "--verify-audit-proof-graph",
        type=Path,
        default=None,
        help="Verify a showcase-audit-proof-graph.json against the packet, verdict, and claim certificate",
    )
    parser.add_argument(
        "--audit-proof-graph-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-audit-proof-graph; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-proof-graph-dot",
        type=Path,
        default=None,
        help="Graphviz DOT companion for --verify-audit-proof-graph; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-proof-graph-red-team",
        action="store_true",
        help="Forge audit proof graph JSON/Markdown/DOT fields and require rejection",
    )
    parser.add_argument(
        "--audit-capsule",
        action="store_true",
        help="Write showcase-audit-capsule.json/.md as a handoff manifest over audit artifacts",
    )
    parser.add_argument(
        "--verify-audit-capsule",
        type=Path,
        default=None,
        help="Verify a showcase-audit-capsule.json manifest against declared artifact files",
    )
    parser.add_argument(
        "--audit-capsule-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-audit-capsule; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-capsule-red-team",
        action="store_true",
        help="Forge audit capsule JSON/Markdown/artifact fields and require rejection",
    )
    parser.add_argument(
        "--audit-capsule-archive",
        action="store_true",
        help="Write a deterministic showcase-audit-capsule.zip handoff archive",
    )
    parser.add_argument(
        "--verify-audit-capsule-archive",
        type=Path,
        default=None,
        help="Verify a deterministic audit capsule ZIP archive against the capsule manifest",
    )
    parser.add_argument(
        "--audit-capsule-archive-red-team",
        action="store_true",
        help="Forge audit capsule archive entries/metadata and require rejection",
    )
    parser.add_argument(
        "--audit-challenge-transcript",
        action="store_true",
        help="Write showcase-audit-challenge-transcript.json/.md from red-team rejection evidence",
    )
    parser.add_argument(
        "--verify-audit-challenge-transcript",
        type=Path,
        default=None,
        help="Verify a showcase-audit-challenge-transcript.json against current red-team results",
    )
    parser.add_argument(
        "--audit-challenge-transcript-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-audit-challenge-transcript; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-decision",
        action="store_true",
        help="Write showcase-audit-decision.json as an external verdict over the sealed capsule and archive",
    )
    parser.add_argument(
        "--verify-audit-decision",
        type=Path,
        default=None,
        help="Verify a showcase-audit-decision.json against the current sealed capsule and archive",
    )
    parser.add_argument(
        "--audit-board",
        action="store_true",
        help="Write showcase-audit-board.json/.md as a concise board-level audit handoff",
    )
    parser.add_argument(
        "--verify-audit-board",
        type=Path,
        default=None,
        help="Verify a showcase-audit-board.json against the current audit decision",
    )
    parser.add_argument(
        "--audit-board-markdown",
        type=Path,
        default=None,
        help="Markdown companion for --verify-audit-board; defaults beside JSON",
    )
    parser.add_argument(
        "--audit-facts",
        action="store_true",
        help="Write showcase-audit-facts.json and .metta as a PeTTa-queryable audit export",
    )
    parser.add_argument(
        "--verify-audit-facts",
        type=Path,
        default=None,
        help="Verify a showcase-audit-facts.json against the current audit board",
    )
    parser.add_argument(
        "--audit-facts-metta",
        type=Path,
        default=None,
        help="PeTTa companion for --verify-audit-facts; defaults beside JSON",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero if any check fails")
    args = parser.parse_args()
    if args.audit_facts:
        args.audit_board = True
    if args.audit_board:
        args.audit_decision = True
    if args.audit_decision:
        args.audit_challenge_transcript = True
    if args.audit_challenge_transcript:
        args.audit_capsule_archive_red_team = True

    if args.verify_forensic_packet is not None:
        details = verify_forensic_packet_details(
            args.verify_forensic_packet,
            artifact_dir=args.output_dir,
        )
        seal_sweep = (
            run_forensic_seal_sweep(
                args.output_dir,
                packet_path=args.verify_forensic_packet,
            )
            if args.forensic_seal_sweep
            else None
        )
        packet_red_team = (
            run_forensic_packet_red_team(
                args.verify_forensic_packet,
                artifact_dir=args.output_dir,
            )
            if args.forensic_packet_red_team
            or args.audit_verdict
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        evidence_index_red_team = (
            run_evidence_index_red_team(
                args.output_dir,
                packet_path=args.verify_forensic_packet,
            )
            if args.evidence_index_red_team
            or args.audit_verdict
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        artifact_inclusion = (
            verify_artifact_inclusion(
                args.verify_forensic_packet,
                args.verify_artifact_inclusion,
                artifact_dir=args.output_dir,
            )
            if args.verify_artifact_inclusion is not None
            else None
        )
        claim_evidence = (
            verify_claim_evidence(
                args.verify_forensic_packet,
                args.verify_claim,
                artifact_dir=args.output_dir,
            )
            if args.verify_claim is not None
            else None
        )
        claim_sweep = (
            verify_all_claims(
                args.verify_forensic_packet,
                artifact_dir=args.output_dir,
                result_path=args.output_dir / "showcase-claim-sweep-result.json",
            )
            if args.verify_all_claims
            or args.audit_verdict
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        claim_certificate = (
            verify_claim_certificate(
                args.verify_forensic_packet,
                claim_certificate_path,
                artifact_dir=args.output_dir,
                certificate_markdown_path=args.claim_certificate_markdown,
            )
            if args.verify_claim_certificate is not None
            or args.claim_certificate_red_team
            or args.audit_verdict
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        claim_certificate_red_team = (
            run_claim_certificate_red_team(
                args.verify_forensic_packet,
                claim_certificate_path,
                artifact_dir=args.output_dir,
                certificate_markdown_path=args.claim_certificate_markdown,
            )
            if args.claim_certificate_red_team
            or args.audit_verdict
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_verdict = (
            write_audit_verdict(
                details,
                packet_red_team=packet_red_team,
                evidence_index_red_team=evidence_index_red_team,
                claim_sweep=claim_sweep,
                claim_certificate=claim_certificate,
                claim_certificate_red_team=claim_certificate_red_team,
                result_path=args.output_dir / "showcase-audit-verdict.json",
                markdown_path=args.output_dir / "showcase-audit-verdict.md",
            )
            if args.audit_verdict
            or (
                (
                    args.audit_verdict_red_team
                    or args.audit_proof_graph
                    or args.audit_proof_graph_red_team
                    or args.audit_capsule
                    or args.audit_capsule_red_team
                    or args.audit_capsule_archive
                    or args.audit_capsule_archive_red_team
                )
                and args.verify_audit_verdict is None
            )
            else None
        )
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        audit_verdict_verification = (
            verify_audit_verdict(
                args.verify_forensic_packet,
                audit_verdict_path,
                artifact_dir=args.output_dir,
                markdown_path=args.audit_verdict_markdown,
            )
            if args.verify_audit_verdict is not None
            or args.audit_verdict_red_team
            or args.audit_proof_graph
            or args.verify_audit_proof_graph is not None
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.verify_audit_capsule is not None
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.verify_audit_capsule_archive is not None
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_verdict_red_team = (
            run_audit_verdict_red_team(
                args.verify_forensic_packet,
                audit_verdict_path,
                artifact_dir=args.output_dir,
                markdown_path=args.audit_verdict_markdown,
            )
            if args.audit_verdict_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_proof_graph_path = (
            args.verify_audit_proof_graph
            if args.verify_audit_proof_graph is not None
            else args.output_dir / "showcase-audit-proof-graph.json"
        )
        audit_proof_graph = (
            write_audit_proof_graph(
                args.verify_forensic_packet,
                audit_verdict_path,
                claim_certificate_path,
                artifact_dir=args.output_dir,
                result_path=args.output_dir / "showcase-audit-proof-graph.json",
                markdown_path=args.output_dir / "showcase-audit-proof-graph.md",
                dot_path=args.output_dir / "showcase-audit-proof-graph.dot",
            )
            if args.audit_proof_graph
            or (
                (
                    args.audit_proof_graph_red_team
                    or args.audit_capsule
                    or args.audit_capsule_red_team
                    or args.audit_capsule_archive
                    or args.audit_capsule_archive_red_team
                )
                and args.verify_audit_proof_graph is None
            )
            else None
        )
        audit_proof_graph_verification = (
            verify_audit_proof_graph(
                args.verify_forensic_packet,
                audit_proof_graph_path,
                artifact_dir=args.output_dir,
                audit_verdict_path=audit_verdict_path,
                audit_verdict_markdown_path=args.audit_verdict_markdown,
                claim_certificate_path=claim_certificate_path,
                claim_certificate_markdown_path=args.claim_certificate_markdown,
                graph_markdown_path=args.audit_proof_graph_markdown,
                graph_dot_path=args.audit_proof_graph_dot,
            )
            if args.verify_audit_proof_graph is not None
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.verify_audit_capsule is not None
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.verify_audit_capsule_archive is not None
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_proof_graph_red_team = (
            run_audit_proof_graph_red_team(
                args.verify_forensic_packet,
                audit_proof_graph_path,
                artifact_dir=args.output_dir,
                audit_verdict_path=audit_verdict_path,
                audit_verdict_markdown_path=args.audit_verdict_markdown,
                claim_certificate_path=claim_certificate_path,
                claim_certificate_markdown_path=args.claim_certificate_markdown,
                graph_markdown_path=args.audit_proof_graph_markdown,
                graph_dot_path=args.audit_proof_graph_dot,
            )
            if args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_capsule_path = (
            args.verify_audit_capsule
            if args.verify_audit_capsule is not None
            else args.output_dir / "showcase-audit-capsule.json"
        )
        audit_capsule = (
            write_audit_capsule(
                args.output_dir,
                result_path=args.output_dir / "showcase-audit-capsule.json",
                markdown_path=args.output_dir / "showcase-audit-capsule.md",
            )
            if args.audit_capsule
            or (
                (
                    args.audit_capsule_red_team
                    or args.audit_capsule_archive
                    or args.audit_capsule_archive_red_team
                )
                and args.verify_audit_capsule is None
            )
            else None
        )
        audit_capsule_verification = (
            verify_audit_capsule(
                args.output_dir,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.verify_audit_capsule is not None
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.verify_audit_capsule_archive is not None
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_capsule_red_team = (
            run_audit_capsule_red_team(
                args.output_dir,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_capsule_archive_path = (
            args.verify_audit_capsule_archive
            if args.verify_audit_capsule_archive is not None
            else args.output_dir / "showcase-audit-capsule.zip"
        )
        audit_capsule_archive = (
            write_audit_capsule_archive(
                args.output_dir,
                audit_capsule_path,
                audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_capsule_archive
            or (
                args.audit_capsule_archive_red_team
                and args.verify_audit_capsule_archive is None
            )
            else None
        )
        audit_capsule_archive_verification = (
            verify_audit_capsule_archive(
                args.output_dir,
                audit_capsule_archive_path,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.verify_audit_capsule_archive is not None
            or args.audit_capsule_archive_red_team
            else None
        )
        audit_capsule_archive_red_team = (
            run_audit_capsule_archive_red_team(
                args.output_dir,
                audit_capsule_archive_path,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_capsule_archive_red_team
            else None
        )
        audit_challenge_transcript_path = (
            args.verify_audit_challenge_transcript
            if args.verify_audit_challenge_transcript is not None
            else args.output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON
        )
        audit_challenge_transcript = (
            write_audit_challenge_transcript(
                args.output_dir,
                audit_challenge_transcript_path,
                markdown_path=args.output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN,
            )
            if args.audit_challenge_transcript
            else None
        )
        audit_challenge_transcript_verification = (
            verify_audit_challenge_transcript(
                args.output_dir,
                audit_challenge_transcript_path,
                markdown_path=args.audit_challenge_transcript_markdown,
            )
            if args.verify_audit_challenge_transcript is not None
            or args.audit_challenge_transcript
            else None
        )
        audit_decision_path = (
            args.verify_audit_decision
            if args.verify_audit_decision is not None
            else args.output_dir / AUDIT_DECISION_CERTIFICATE
        )
        audit_decision = (
            write_audit_decision_certificate(
                args.output_dir,
                audit_decision_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_decision
            else None
        )
        audit_decision_verification = (
            verify_audit_decision_certificate(
                args.output_dir,
                audit_decision_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.verify_audit_decision is not None or args.audit_decision
            else None
        )
        audit_board_path = (
            args.verify_audit_board
            if args.verify_audit_board is not None
            else args.output_dir / AUDIT_BOARD_JSON
        )
        audit_board = (
            write_audit_board(
                args.output_dir,
                audit_board_path,
                markdown_path=args.output_dir / AUDIT_BOARD_MARKDOWN,
                decision_path=audit_decision_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_board
            else None
        )
        audit_board_verification = (
            verify_audit_board(
                args.output_dir,
                audit_board_path,
                markdown_path=args.audit_board_markdown,
                decision_path=audit_decision_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.verify_audit_board is not None or args.audit_board
            else None
        )
        audit_facts_path = (
            args.verify_audit_facts
            if args.verify_audit_facts is not None
            else args.output_dir / AUDIT_FACTS_JSON
        )
        audit_facts = (
            write_audit_facts(
                args.output_dir,
                audit_facts_path,
                metta_path=args.output_dir / AUDIT_FACTS_METTA,
                board_path=audit_board_path,
                decision_path=audit_decision_path,
                transcript_path=audit_challenge_transcript_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.audit_facts
            else None
        )
        audit_facts_verification = (
            verify_audit_facts(
                args.output_dir,
                audit_facts_path,
                metta_path=args.audit_facts_metta,
                board_path=audit_board_path,
                decision_path=audit_decision_path,
                transcript_path=audit_challenge_transcript_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
            if args.verify_audit_facts is not None or args.audit_facts
            else None
        )
        if args.json:
            if seal_sweep is not None:
                details["forensic_seal_sweep"] = seal_sweep
            if packet_red_team is not None:
                details["forensic_packet_red_team"] = packet_red_team
            if evidence_index_red_team is not None:
                details["evidence_index_red_team"] = evidence_index_red_team
            if artifact_inclusion is not None:
                details["artifact_inclusion"] = artifact_inclusion
            if claim_evidence is not None:
                details["claim_evidence"] = claim_evidence
            if claim_sweep is not None:
                details["claim_sweep"] = claim_sweep
            if claim_certificate is not None:
                details["claim_certificate"] = claim_certificate
            if claim_certificate_red_team is not None:
                details["claim_certificate_red_team"] = claim_certificate_red_team
            if audit_verdict is not None:
                details["audit_verdict"] = audit_verdict
            if audit_verdict_verification is not None:
                details["audit_verdict_verification"] = audit_verdict_verification
            if audit_verdict_red_team is not None:
                details["audit_verdict_red_team"] = audit_verdict_red_team
            if audit_proof_graph is not None:
                details["audit_proof_graph"] = audit_proof_graph
            if audit_proof_graph_verification is not None:
                details["audit_proof_graph_verification"] = (
                    audit_proof_graph_verification
                )
            if audit_proof_graph_red_team is not None:
                details["audit_proof_graph_red_team"] = audit_proof_graph_red_team
            if audit_capsule is not None:
                details["audit_capsule"] = audit_capsule
            if audit_capsule_verification is not None:
                details["audit_capsule_verification"] = audit_capsule_verification
            if audit_capsule_red_team is not None:
                details["audit_capsule_red_team"] = audit_capsule_red_team
            if audit_capsule_archive is not None:
                details["audit_capsule_archive"] = audit_capsule_archive
            if audit_capsule_archive_verification is not None:
                details["audit_capsule_archive_verification"] = (
                    audit_capsule_archive_verification
                )
            if audit_capsule_archive_red_team is not None:
                details["audit_capsule_archive_red_team"] = (
                    audit_capsule_archive_red_team
                )
            if audit_challenge_transcript is not None:
                details["audit_challenge_transcript"] = audit_challenge_transcript
            if audit_challenge_transcript_verification is not None:
                details["audit_challenge_transcript_verification"] = (
                    audit_challenge_transcript_verification
                )
            if audit_decision is not None:
                details["audit_decision"] = audit_decision
            if audit_decision_verification is not None:
                details["audit_decision_verification"] = audit_decision_verification
            if audit_board is not None:
                details["audit_board"] = audit_board
            if audit_board_verification is not None:
                details["audit_board_verification"] = audit_board_verification
            if audit_facts is not None:
                details["audit_facts"] = audit_facts
            if audit_facts_verification is not None:
                details["audit_facts_verification"] = audit_facts_verification
            print(json.dumps(details, indent=2, sort_keys=True))
        else:
            print_forensic_packet_details(details)
            if seal_sweep is not None:
                print_forensic_seal_sweep(seal_sweep)
            if packet_red_team is not None:
                print_forensic_packet_red_team(packet_red_team)
            if evidence_index_red_team is not None:
                print_evidence_index_red_team(evidence_index_red_team)
            if artifact_inclusion is not None:
                print_artifact_inclusion(artifact_inclusion)
            if claim_evidence is not None:
                print_claim_evidence(claim_evidence)
            if claim_sweep is not None:
                print_claim_sweep(claim_sweep)
            if claim_certificate is not None:
                print_claim_certificate_verification(claim_certificate)
            if claim_certificate_red_team is not None:
                print_claim_certificate_red_team(claim_certificate_red_team)
            if audit_verdict is not None:
                print_audit_verdict(audit_verdict)
            if audit_verdict_verification is not None:
                print_audit_verdict_verification(audit_verdict_verification)
            if audit_verdict_red_team is not None:
                print_audit_verdict_red_team(audit_verdict_red_team)
            if audit_proof_graph is not None:
                print_audit_proof_graph(audit_proof_graph)
            if audit_proof_graph_verification is not None:
                print_audit_proof_graph_verification(audit_proof_graph_verification)
            if audit_proof_graph_red_team is not None:
                print_audit_proof_graph_red_team(audit_proof_graph_red_team)
            if audit_capsule is not None:
                print_audit_capsule(audit_capsule)
            if audit_capsule_verification is not None:
                print_audit_capsule_verification(audit_capsule_verification)
            if audit_capsule_red_team is not None:
                print_audit_capsule_red_team(audit_capsule_red_team)
            if audit_capsule_archive is not None:
                print_audit_capsule_archive(audit_capsule_archive)
            if audit_capsule_archive_verification is not None:
                print_audit_capsule_archive_verification(
                    audit_capsule_archive_verification
                )
            if audit_capsule_archive_red_team is not None:
                print_audit_capsule_archive_red_team(audit_capsule_archive_red_team)
            if audit_challenge_transcript is not None:
                print_audit_challenge_transcript(audit_challenge_transcript)
            if audit_challenge_transcript_verification is not None:
                print_audit_challenge_transcript_verification(
                    audit_challenge_transcript_verification
                )
            if audit_decision is not None:
                print_audit_decision_certificate(audit_decision)
            if audit_decision_verification is not None:
                print_audit_decision_verification(audit_decision_verification)
            if audit_board is not None:
                print_audit_board(audit_board)
            if audit_board_verification is not None:
                print_audit_board_verification(audit_board_verification)
            if audit_facts is not None:
                print_audit_facts(audit_facts)
            if audit_facts_verification is not None:
                print_audit_facts_verification(audit_facts_verification)
        passed = bool(details["checks"]["packet_verified"]) and (
            seal_sweep is None or bool(seal_sweep["seal_sweep_pass"])
        ) and (
            packet_red_team is None
            or bool(packet_red_team["packet_red_team_pass"])
        ) and (
            evidence_index_red_team is None
            or bool(evidence_index_red_team["evidence_index_red_team_pass"])
        ) and (
            artifact_inclusion is None
            or bool(artifact_inclusion["checks"]["inclusion_verified"])
        ) and (
            claim_evidence is None
            or bool(claim_evidence["checks"]["claim_verified"])
        ) and (
            claim_sweep is None
            or bool(claim_sweep["checks"]["claim_sweep_verified"])
        ) and (
            claim_certificate is None
            or bool(claim_certificate["checks"]["claim_certificate_verified"])
        ) and (
            claim_certificate_red_team is None
            or bool(
                claim_certificate_red_team["claim_certificate_red_team_pass"]
            )
        ) and (
            audit_verdict is None
            or bool(audit_verdict.get("verdict") == "PASS")
        ) and (
            audit_verdict_verification is None
            or bool(
                audit_verdict_verification["checks"]["audit_verdict_verified"]
            )
        ) and (
            audit_verdict_red_team is None
            or bool(audit_verdict_red_team["audit_verdict_red_team_pass"])
        ) and (
            audit_proof_graph is None
            or bool(audit_proof_graph.get("verdict") == "PASS")
        ) and (
            audit_proof_graph_verification is None
            or bool(
                audit_proof_graph_verification["checks"][
                    "audit_proof_graph_verified"
                ]
            )
        ) and (
            audit_proof_graph_red_team is None
            or bool(
                audit_proof_graph_red_team["audit_proof_graph_red_team_pass"]
            )
        ) and (
            audit_capsule is None
            or bool(audit_capsule.get("audit_capsule_sha256"))
        ) and (
            audit_capsule_verification is None
            or bool(
                audit_capsule_verification["checks"]["audit_capsule_verified"]
            )
        ) and (
            audit_capsule_red_team is None
            or bool(audit_capsule_red_team["audit_capsule_red_team_pass"])
        ) and (
            audit_capsule_archive is None
            or bool(audit_capsule_archive.get("archive_sha256"))
        ) and (
            audit_capsule_archive_verification is None
            or bool(
                audit_capsule_archive_verification["checks"][
                    "audit_capsule_archive_verified"
                ]
            )
        ) and (
            audit_capsule_archive_red_team is None
            or bool(
                audit_capsule_archive_red_team[
                    "audit_capsule_archive_red_team_pass"
                ]
            )
        ) and (
            audit_challenge_transcript is None
            or bool(audit_challenge_transcript.get("verdict") == "PASS")
        ) and (
            audit_challenge_transcript_verification is None
            or bool(
                audit_challenge_transcript_verification["checks"][
                    "audit_challenge_transcript_verified"
                ]
            )
        ) and (
            audit_decision is None
            or bool(audit_decision.get("verdict") == "PASS")
        ) and (
            audit_decision_verification is None
            or bool(
                audit_decision_verification["checks"]["audit_decision_verified"]
            )
        ) and (
            audit_board is None
            or bool(audit_board.get("verdict") == "PASS")
        ) and (
            audit_board_verification is None
            or bool(audit_board_verification["checks"]["audit_board_verified"])
        ) and (
            audit_facts is None
            or bool(audit_facts.get("verdict") == "PASS")
        ) and (
            audit_facts_verification is None
            or bool(audit_facts_verification["checks"]["audit_facts_verified"])
        )
        return 0 if not args.strict or passed else 1

    verification = verify_showcase_artifacts(
        args.output_dir,
        replay_noise=not args.no_noise_replay,
        replay_context=not args.no_context_replay,
        replay_complementary=not args.no_complementary_replay,
        replay_context_noise=not args.no_context_noise_replay,
        replay_context_counterfactuals=not args.no_context_counterfactual_replay,
    )
    red_team = None
    if args.red_team:
        red_team = run_red_team_verifier(
            args.output_dir,
            replay_noise=False,
            red_team_dir=args.red_team_dir,
        )
        verification["red_team"] = red_team
    verification["forensic_packet"] = write_forensic_packet(verification, red_team)
    if args.forensic_seal_sweep:
        verification["forensic_seal_sweep"] = run_forensic_seal_sweep(
            args.output_dir,
            packet_path=Path(str(verification["forensic_packet"]["json_path"])),
        )
    if (
        args.forensic_packet_red_team
        or args.audit_verdict
        or args.audit_proof_graph
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        verification["forensic_packet_red_team"] = run_forensic_packet_red_team(
            Path(str(verification["forensic_packet"]["json_path"])),
            artifact_dir=args.output_dir,
        )
    if (
        args.evidence_index_red_team
        or args.audit_verdict
        or args.audit_proof_graph
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        verification["evidence_index_red_team"] = run_evidence_index_red_team(
            args.output_dir,
            packet_path=Path(str(verification["forensic_packet"]["json_path"])),
        )
    if (
        args.verify_all_claims
        or args.audit_verdict
        or args.audit_proof_graph
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        verification["claim_sweep"] = verify_all_claims(
            Path(str(verification["forensic_packet"]["json_path"])),
            artifact_dir=args.output_dir,
            result_path=args.output_dir / "showcase-claim-sweep-result.json",
        )
    if (
        args.verify_claim_certificate is not None
        or args.claim_certificate_red_team
        or args.audit_verdict
        or args.audit_proof_graph
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        verification["claim_certificate"] = verify_claim_certificate(
            Path(str(verification["forensic_packet"]["json_path"])),
            claim_certificate_path,
            artifact_dir=args.output_dir,
            certificate_markdown_path=args.claim_certificate_markdown,
        )
    if (
        args.claim_certificate_red_team
        or args.audit_verdict
        or args.audit_proof_graph
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        verification["claim_certificate_red_team"] = run_claim_certificate_red_team(
            Path(str(verification["forensic_packet"]["json_path"])),
            claim_certificate_path,
            artifact_dir=args.output_dir,
            certificate_markdown_path=args.claim_certificate_markdown,
        )
    if args.audit_verdict or (
        (
            args.audit_verdict_red_team
            or args.audit_proof_graph
            or args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
        )
        and args.verify_audit_verdict is None
    ):
        verification["audit_verdict"] = write_audit_verdict(
            verify_forensic_packet_details(
                Path(str(verification["forensic_packet"]["json_path"])),
                artifact_dir=args.output_dir,
            ),
            packet_red_team=verification.get("forensic_packet_red_team"),
            evidence_index_red_team=verification.get("evidence_index_red_team"),
            claim_sweep=verification.get("claim_sweep"),
            claim_certificate=verification.get("claim_certificate"),
            claim_certificate_red_team=verification.get(
                "claim_certificate_red_team"
            ),
            result_path=args.output_dir / "showcase-audit-verdict.json",
            markdown_path=args.output_dir / "showcase-audit-verdict.md",
        )
    if (
        args.verify_audit_verdict is not None
        or args.audit_verdict_red_team
        or args.audit_proof_graph
        or args.verify_audit_proof_graph is not None
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.verify_audit_capsule is not None
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.verify_audit_capsule_archive is not None
        or args.audit_capsule_archive_red_team
    ):
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        verification["audit_verdict_verification"] = verify_audit_verdict(
            Path(str(verification["forensic_packet"]["json_path"])),
            audit_verdict_path,
            artifact_dir=args.output_dir,
            markdown_path=args.audit_verdict_markdown,
        )
    if (
        args.audit_verdict_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        verification["audit_verdict_red_team"] = run_audit_verdict_red_team(
            Path(str(verification["forensic_packet"]["json_path"])),
            audit_verdict_path,
            artifact_dir=args.output_dir,
            markdown_path=args.audit_verdict_markdown,
        )
    audit_proof_graph_path = (
        args.verify_audit_proof_graph
        if args.verify_audit_proof_graph is not None
        else args.output_dir / "showcase-audit-proof-graph.json"
    )
    if args.audit_proof_graph or (
        (
            args.audit_proof_graph_red_team
            or args.audit_capsule
            or args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
        )
        and args.verify_audit_proof_graph is None
    ):
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        verification["audit_proof_graph"] = write_audit_proof_graph(
            Path(str(verification["forensic_packet"]["json_path"])),
            audit_verdict_path,
            claim_certificate_path,
            artifact_dir=args.output_dir,
            result_path=args.output_dir / "showcase-audit-proof-graph.json",
            markdown_path=args.output_dir / "showcase-audit-proof-graph.md",
            dot_path=args.output_dir / "showcase-audit-proof-graph.dot",
        )
    if (
        args.verify_audit_proof_graph is not None
        or args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.verify_audit_capsule is not None
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.verify_audit_capsule_archive is not None
        or args.audit_capsule_archive_red_team
    ):
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        verification["audit_proof_graph_verification"] = verify_audit_proof_graph(
            Path(str(verification["forensic_packet"]["json_path"])),
            audit_proof_graph_path,
            artifact_dir=args.output_dir,
            audit_verdict_path=audit_verdict_path,
            audit_verdict_markdown_path=args.audit_verdict_markdown,
            claim_certificate_path=claim_certificate_path,
            claim_certificate_markdown_path=args.claim_certificate_markdown,
            graph_markdown_path=args.audit_proof_graph_markdown,
            graph_dot_path=args.audit_proof_graph_dot,
        )
    if (
        args.audit_proof_graph_red_team
        or args.audit_capsule
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        audit_verdict_path = (
            args.verify_audit_verdict
            if args.verify_audit_verdict is not None
            else args.output_dir / "showcase-audit-verdict.json"
        )
        claim_certificate_path = (
            args.verify_claim_certificate
            if args.verify_claim_certificate is not None
            else args.output_dir / "showcase-claim-certificate.json"
        )
        verification["audit_proof_graph_red_team"] = run_audit_proof_graph_red_team(
            Path(str(verification["forensic_packet"]["json_path"])),
            audit_proof_graph_path,
            artifact_dir=args.output_dir,
            audit_verdict_path=audit_verdict_path,
            audit_verdict_markdown_path=args.audit_verdict_markdown,
            claim_certificate_path=claim_certificate_path,
            claim_certificate_markdown_path=args.claim_certificate_markdown,
            graph_markdown_path=args.audit_proof_graph_markdown,
            graph_dot_path=args.audit_proof_graph_dot,
        )
    audit_capsule_path = (
        args.verify_audit_capsule
        if args.verify_audit_capsule is not None
        else args.output_dir / "showcase-audit-capsule.json"
    )
    if args.audit_capsule or (
        (
            args.audit_capsule_red_team
            or args.audit_capsule_archive
            or args.audit_capsule_archive_red_team
        )
        and args.verify_audit_capsule is None
    ):
        verification["audit_capsule"] = write_audit_capsule(
            args.output_dir,
            result_path=args.output_dir / "showcase-audit-capsule.json",
            markdown_path=args.output_dir / "showcase-audit-capsule.md",
        )
    if (
        args.verify_audit_capsule is not None
        or args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.verify_audit_capsule_archive is not None
        or args.audit_capsule_archive_red_team
    ):
        verification["audit_capsule_verification"] = verify_audit_capsule(
            args.output_dir,
            audit_capsule_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if (
        args.audit_capsule_red_team
        or args.audit_capsule_archive
        or args.audit_capsule_archive_red_team
    ):
        verification["audit_capsule_red_team"] = run_audit_capsule_red_team(
            args.output_dir,
            audit_capsule_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    audit_capsule_archive_path = (
        args.verify_audit_capsule_archive
        if args.verify_audit_capsule_archive is not None
        else args.output_dir / "showcase-audit-capsule.zip"
    )
    if args.audit_capsule_archive or (
        args.audit_capsule_archive_red_team
        and args.verify_audit_capsule_archive is None
    ):
        verification["audit_capsule_archive"] = write_audit_capsule_archive(
            args.output_dir,
            audit_capsule_path,
            audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if args.verify_audit_capsule_archive is not None or args.audit_capsule_archive_red_team:
        verification["audit_capsule_archive_verification"] = (
            verify_audit_capsule_archive(
                args.output_dir,
                audit_capsule_archive_path,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
        )
    if args.audit_capsule_archive_red_team:
        verification["audit_capsule_archive_red_team"] = (
            run_audit_capsule_archive_red_team(
                args.output_dir,
                audit_capsule_archive_path,
                audit_capsule_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
        )
    audit_challenge_transcript_path = (
        args.verify_audit_challenge_transcript
        if args.verify_audit_challenge_transcript is not None
        else args.output_dir / AUDIT_CHALLENGE_TRANSCRIPT_JSON
    )
    if args.audit_challenge_transcript:
        verification["audit_challenge_transcript"] = write_audit_challenge_transcript(
            args.output_dir,
            audit_challenge_transcript_path,
            markdown_path=args.output_dir / AUDIT_CHALLENGE_TRANSCRIPT_MARKDOWN,
        )
    if args.verify_audit_challenge_transcript is not None or args.audit_challenge_transcript:
        verification["audit_challenge_transcript_verification"] = (
            verify_audit_challenge_transcript(
                args.output_dir,
                audit_challenge_transcript_path,
                markdown_path=args.audit_challenge_transcript_markdown,
            )
        )
    audit_decision_path = (
        args.verify_audit_decision
        if args.verify_audit_decision is not None
        else args.output_dir / AUDIT_DECISION_CERTIFICATE
    )
    if args.audit_decision:
        verification["audit_decision"] = write_audit_decision_certificate(
            args.output_dir,
            audit_decision_path,
            capsule_path=audit_capsule_path,
            archive_path=audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if args.verify_audit_decision is not None or args.audit_decision:
        verification["audit_decision_verification"] = (
            verify_audit_decision_certificate(
                args.output_dir,
                audit_decision_path,
                capsule_path=audit_capsule_path,
                archive_path=audit_capsule_archive_path,
                capsule_markdown_path=args.audit_capsule_markdown,
            )
        )
    audit_board_path = (
        args.verify_audit_board
        if args.verify_audit_board is not None
        else args.output_dir / AUDIT_BOARD_JSON
    )
    if args.audit_board:
        verification["audit_board"] = write_audit_board(
            args.output_dir,
            audit_board_path,
            markdown_path=args.output_dir / AUDIT_BOARD_MARKDOWN,
            decision_path=audit_decision_path,
            capsule_path=audit_capsule_path,
            archive_path=audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if args.verify_audit_board is not None or args.audit_board:
        verification["audit_board_verification"] = verify_audit_board(
            args.output_dir,
            audit_board_path,
            markdown_path=args.audit_board_markdown,
            decision_path=audit_decision_path,
            capsule_path=audit_capsule_path,
            archive_path=audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    audit_facts_path = (
        args.verify_audit_facts
        if args.verify_audit_facts is not None
        else args.output_dir / AUDIT_FACTS_JSON
    )
    if args.audit_facts:
        verification["audit_facts"] = write_audit_facts(
            args.output_dir,
            audit_facts_path,
            metta_path=args.output_dir / AUDIT_FACTS_METTA,
            board_path=audit_board_path,
            decision_path=audit_decision_path,
            transcript_path=audit_challenge_transcript_path,
            capsule_path=audit_capsule_path,
            archive_path=audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if args.verify_audit_facts is not None or args.audit_facts:
        verification["audit_facts_verification"] = verify_audit_facts(
            args.output_dir,
            audit_facts_path,
            metta_path=args.audit_facts_metta,
            board_path=audit_board_path,
            decision_path=audit_decision_path,
            transcript_path=audit_challenge_transcript_path,
            capsule_path=audit_capsule_path,
            archive_path=audit_capsule_archive_path,
            capsule_markdown_path=args.audit_capsule_markdown,
        )
    if args.json:
        print(json.dumps(verification, indent=2, sort_keys=True))
    else:
        print_text(verification)
        if red_team is not None:
            print_red_team(red_team)
        if "forensic_seal_sweep" in verification:
            print_forensic_seal_sweep(verification["forensic_seal_sweep"])
        if "forensic_packet_red_team" in verification:
            print_forensic_packet_red_team(verification["forensic_packet_red_team"])
        if "evidence_index_red_team" in verification:
            print_evidence_index_red_team(verification["evidence_index_red_team"])
        if "claim_sweep" in verification:
            print_claim_sweep(verification["claim_sweep"])
        if "claim_certificate" in verification:
            print_claim_certificate_verification(verification["claim_certificate"])
        if "claim_certificate_red_team" in verification:
            print_claim_certificate_red_team(verification["claim_certificate_red_team"])
        if "audit_verdict" in verification:
            print_audit_verdict(verification["audit_verdict"])
        if "audit_verdict_verification" in verification:
            print_audit_verdict_verification(
                verification["audit_verdict_verification"]
            )
        if "audit_verdict_red_team" in verification:
            print_audit_verdict_red_team(verification["audit_verdict_red_team"])
        if "audit_proof_graph" in verification:
            print_audit_proof_graph(verification["audit_proof_graph"])
        if "audit_proof_graph_verification" in verification:
            print_audit_proof_graph_verification(
                verification["audit_proof_graph_verification"]
            )
        if "audit_proof_graph_red_team" in verification:
            print_audit_proof_graph_red_team(
                verification["audit_proof_graph_red_team"]
            )
        if "audit_capsule" in verification:
            print_audit_capsule(verification["audit_capsule"])
        if "audit_capsule_verification" in verification:
            print_audit_capsule_verification(
                verification["audit_capsule_verification"]
            )
        if "audit_capsule_red_team" in verification:
            print_audit_capsule_red_team(verification["audit_capsule_red_team"])
        if "audit_capsule_archive" in verification:
            print_audit_capsule_archive(verification["audit_capsule_archive"])
        if "audit_capsule_archive_verification" in verification:
            print_audit_capsule_archive_verification(
                verification["audit_capsule_archive_verification"]
            )
        if "audit_capsule_archive_red_team" in verification:
            print_audit_capsule_archive_red_team(
                verification["audit_capsule_archive_red_team"]
            )
        if "audit_challenge_transcript" in verification:
            print_audit_challenge_transcript(
                verification["audit_challenge_transcript"]
            )
        if "audit_challenge_transcript_verification" in verification:
            print_audit_challenge_transcript_verification(
                verification["audit_challenge_transcript_verification"]
            )
        if "audit_decision" in verification:
            print_audit_decision_certificate(verification["audit_decision"])
        if "audit_decision_verification" in verification:
            print_audit_decision_verification(
                verification["audit_decision_verification"]
            )
        if "audit_board" in verification:
            print_audit_board(verification["audit_board"])
        if "audit_board_verification" in verification:
            print_audit_board_verification(verification["audit_board_verification"])
        if "audit_facts" in verification:
            print_audit_facts(verification["audit_facts"])
        if "audit_facts_verification" in verification:
            print_audit_facts_verification(verification["audit_facts_verification"])
    passed = all(verification["checks"].values()) and (
        red_team is None or bool(red_team["red_team_rejections_pass"])
    ) and (
        "forensic_seal_sweep" not in verification
        or bool(verification["forensic_seal_sweep"]["seal_sweep_pass"])
    ) and (
        "forensic_packet_red_team" not in verification
        or bool(verification["forensic_packet_red_team"]["packet_red_team_pass"])
    ) and (
        "evidence_index_red_team" not in verification
        or bool(verification["evidence_index_red_team"]["evidence_index_red_team_pass"])
    ) and (
        "claim_sweep" not in verification
        or bool(verification["claim_sweep"]["checks"]["claim_sweep_verified"])
    ) and (
        "claim_certificate" not in verification
        or bool(
            verification["claim_certificate"]["checks"]["claim_certificate_verified"]
        )
    ) and (
        "claim_certificate_red_team" not in verification
        or bool(
            verification["claim_certificate_red_team"][
                "claim_certificate_red_team_pass"
            ]
        )
    ) and (
        "audit_verdict" not in verification
        or bool(verification["audit_verdict"].get("verdict") == "PASS")
    ) and (
        "audit_verdict_verification" not in verification
        or bool(
            verification["audit_verdict_verification"]["checks"][
                "audit_verdict_verified"
            ]
        )
    ) and (
        "audit_verdict_red_team" not in verification
        or bool(
            verification["audit_verdict_red_team"]["audit_verdict_red_team_pass"]
        )
    ) and (
        "audit_proof_graph" not in verification
        or bool(verification["audit_proof_graph"].get("verdict") == "PASS")
    ) and (
        "audit_proof_graph_verification" not in verification
        or bool(
            verification["audit_proof_graph_verification"]["checks"][
                "audit_proof_graph_verified"
            ]
        )
    ) and (
        "audit_proof_graph_red_team" not in verification
        or bool(
            verification["audit_proof_graph_red_team"][
                "audit_proof_graph_red_team_pass"
            ]
        )
    ) and (
        "audit_capsule" not in verification
        or bool(verification["audit_capsule"].get("audit_capsule_sha256"))
    ) and (
        "audit_capsule_verification" not in verification
        or bool(
            verification["audit_capsule_verification"]["checks"][
                "audit_capsule_verified"
            ]
        )
    ) and (
        "audit_capsule_red_team" not in verification
        or bool(
            verification["audit_capsule_red_team"]["audit_capsule_red_team_pass"]
        )
    ) and (
        "audit_capsule_archive" not in verification
        or bool(verification["audit_capsule_archive"].get("archive_sha256"))
    ) and (
        "audit_capsule_archive_verification" not in verification
        or bool(
            verification["audit_capsule_archive_verification"]["checks"][
                "audit_capsule_archive_verified"
            ]
        )
    ) and (
        "audit_capsule_archive_red_team" not in verification
        or bool(
            verification["audit_capsule_archive_red_team"][
                "audit_capsule_archive_red_team_pass"
            ]
        )
    ) and (
        "audit_challenge_transcript" not in verification
        or bool(verification["audit_challenge_transcript"].get("verdict") == "PASS")
    ) and (
        "audit_challenge_transcript_verification" not in verification
        or bool(
            verification["audit_challenge_transcript_verification"]["checks"][
                "audit_challenge_transcript_verified"
            ]
        )
    ) and (
        "audit_decision" not in verification
        or bool(verification["audit_decision"].get("verdict") == "PASS")
    ) and (
        "audit_decision_verification" not in verification
        or bool(
            verification["audit_decision_verification"]["checks"][
                "audit_decision_verified"
            ]
        )
    ) and (
        "audit_board" not in verification
        or bool(verification["audit_board"].get("verdict") == "PASS")
    ) and (
        "audit_board_verification" not in verification
        or bool(
            verification["audit_board_verification"]["checks"][
                "audit_board_verified"
            ]
        )
    ) and (
        "audit_facts" not in verification
        or bool(verification["audit_facts"].get("verdict") == "PASS")
    ) and (
        "audit_facts_verification" not in verification
        or bool(
            verification["audit_facts_verification"]["checks"][
                "audit_facts_verified"
            ]
        )
    )
    return 0 if not args.strict or passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
