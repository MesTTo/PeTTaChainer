import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.verify_showcase import (
    canonical_json_sha256,
    canonical_object_sha256,
    hash_file,
    run_audit_capsule_red_team,
    run_audit_capsule_archive_red_team,
    run_audit_proof_graph_red_team,
    run_audit_verdict_red_team,
    run_claim_certificate_red_team,
    run_evidence_index_red_team,
    run_forensic_packet_red_team,
    verify_artifact_inclusion,
    verify_audit_capsule,
    verify_audit_capsule_archive,
    verify_audit_board,
    verify_audit_challenge_transcript,
    verify_audit_decision_certificate,
    verify_audit_facts,
    verify_audit_policy,
    verify_audit_receipt,
    verify_audit_provenance_attestation,
    verify_audit_proof_graph,
    verify_audit_verdict,
    verify_all_claims,
    verify_claim_certificate,
    verify_claim_evidence,
    verify_forensic_packet,
    verify_forensic_packet_details,
    verify_runtime_manifest,
    write_audit_capsule,
    write_audit_capsule_archive,
    write_audit_board,
    write_audit_challenge_transcript,
    write_audit_decision_certificate,
    write_audit_facts,
    write_audit_proof_graph,
    write_audit_verdict,
    write_forensic_packet,
)


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TestForensicPacket(unittest.TestCase):
    def test_recomputed_root_cannot_hide_semantic_context_forgery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir) / "showcase"
            proof_dir = artifact_dir / "incident-bundle"
            proof_dir.mkdir(parents=True)

            report_path = artifact_dir / "showcase-report.md"
            report_path.write_text("verified showcase report\n", encoding="utf-8")
            proof_path = proof_dir / "proof-structure.json"
            proof_source = {
                "certificate_passes": True,
                "checks": {"structural_audit_passes": True},
                "operator_counts": {"And": 1},
                "forbidden_label_counts": {},
                "proof_sha256": "a" * 64,
            }
            write_json(proof_path, proof_source)

            context_evidence = {
                "checks": {"generated_context_showcase_checks_pass": True},
                "noise_stability": [
                    {
                        "extra_packets": 50,
                        "best_guard": ["type:Penguin"],
                        "ranking_margin": 0.1,
                        "stable": True,
                    }
                ],
                "counterfactuals": [
                    {
                        "name": "remove_penguin_exception",
                        "best_guard": ["habitat:temperate"],
                        "passed": True,
                    }
                ],
            }
            witness = {
                "witness_root_sha256": "b" * 64,
                "artifact_hashes": {
                    "showcase-report.md": hash_file(report_path),
                    "incident-bundle/proof-structure.json": hash_file(proof_path),
                },
                "dispatch_evidence": {"smart_dispatch_direct_call": True},
                "context_evidence": context_evidence,
                "complementary_evidence": {
                    "checks": {"additive_complement_selected": True},
                    "metta_file": "complementary-evidence/additive-complement.metta",
                    "summary_lines": [
                        "merge/additive-complement preserves exception evidence"
                    ],
                    "summary_sha256": "c" * 64,
                },
                "noise_evidence": {
                    "cases": [{"extra_edges": 50, "stable": True}],
                    "max_extra_edges": 50,
                },
            }
            write_json(artifact_dir / "showcase-witness.json", witness)
            write_json(
                artifact_dir / "showcase-result.json",
                {
                    "incident": {
                        "query_counts": {"isolate": 1},
                        "proof_sha256": "a" * 64,
                        "proof_structure": {"certificate_passes": True},
                    }
                },
            )

            verification = {
                "output_dir": str(artifact_dir),
                "checks": {
                    "context_showcase_artifacts_verify": True,
                    "witness_certificate_verified": True,
                },
            }
            verification["claim_coverage"] = {
                "generated_context_inference_control": {
                    "description": "context behavior is verified from artifacts",
                    "enforced_by": ["context_showcase_artifacts_verify"],
                    "check_status": {"context_showcase_artifacts_verify": True},
                    "missing_checks": [],
                    "evidence": [
                        {
                            "check": "context_showcase_artifacts_verify",
                            "artifact": "showcase-verifier-result.json",
                            "json_path": "/checks/context_showcase_artifacts_verify",
                            "passed": True,
                        }
                    ],
                    "evidence_complete": True,
                    "covered": True,
                },
                "forensic_packet_semantic_binding": {
                    "description": "packet semantics are bound to source evidence",
                    "enforced_by": ["witness_certificate_verified"],
                    "check_status": {"witness_certificate_verified": True},
                    "missing_checks": [],
                    "evidence": [
                        {
                            "check": "witness_certificate_verified",
                            "artifact": "showcase-verifier-result.json",
                            "json_path": "/checks/witness_certificate_verified",
                            "passed": True,
                        }
                    ],
                    "evidence_complete": True,
                    "covered": True,
                },
            }
            write_json(
                artifact_dir / "showcase-verifier-result.json",
                {
                    "checks": verification["checks"],
                    "claim_coverage": verification["claim_coverage"],
                },
            )
            red_team = {
                "red_team_rejections_pass": True,
                "mutation_families": ["context"],
                "cases": {
                    "context_log_semantic_forgery": {
                        "mutation_family": "context",
                        "expected_failed_checks": ["context_evidence_matches_witness"],
                        "actual_failed_checks": ["context_evidence_matches_witness"],
                        "rejected": True,
                    }
                },
            }
            write_json(artifact_dir / "showcase-verifier-red-team-result.json", red_team)

            packet = write_forensic_packet(verification, red_team)
            packet_path = Path(packet["json_path"])
            packet_json = json.loads(packet_path.read_text(encoding="utf-8"))
            forged = json.loads(packet_path.read_text(encoding="utf-8"))
            forged["context_evidence"]["counterfactuals"][0]["passed"] = False
            forged_body = {
                key: value for key, value in forged.items() if key != "packet_root_sha256"
            }
            forged_body["packet_root_sha256"] = canonical_json_sha256(forged_body)
            forged_path = artifact_dir / "semantic-forged-forensic-packet.json"
            write_json(forged_path, forged_body)

            claim_forged = json.loads(packet_path.read_text(encoding="utf-8"))
            claim_forged["claim_ledger"]["generated_context_inference_control"][
                "evidence"
            ][0]["artifact"] = "fake-verifier-result.json"
            claim_body = {
                key: value
                for key, value in claim_forged.items()
                if key != "packet_root_sha256"
            }
            claim_body["packet_root_sha256"] = canonical_json_sha256(claim_body)
            claim_forged_path = artifact_dir / "claim-forged-forensic-packet.json"
            write_json(claim_forged_path, claim_body)

            incident_forged = json.loads(packet_path.read_text(encoding="utf-8"))
            incident_forged["incident_summary"]["proof_sha256"] = "0" * 64
            incident_body = {
                key: value
                for key, value in incident_forged.items()
                if key != "packet_root_sha256"
            }
            incident_body["packet_root_sha256"] = canonical_json_sha256(
                incident_body
            )
            incident_forged_path = artifact_dir / "incident-forged-forensic-packet.json"
            write_json(incident_forged_path, incident_body)

            packet_verifies = verify_forensic_packet(packet_path)
            inclusion_details = verify_artifact_inclusion(
                packet_path,
                Path("showcase-report.md"),
            )
            claim_details = verify_claim_evidence(
                packet_path,
                "generated_context_inference_control",
            )
            claim_sweep = verify_all_claims(packet_path)
            forged_verifies = verify_forensic_packet(forged_path)
            forged_details = verify_forensic_packet_details(forged_path)
            claim_forged_verifies = verify_forensic_packet(claim_forged_path)
            claim_forged_details = verify_forensic_packet_details(claim_forged_path)
            incident_forged_verifies = verify_forensic_packet(incident_forged_path)
            incident_forged_details = verify_forensic_packet_details(
                incident_forged_path
            )
            packet_red_team = run_forensic_packet_red_team(
                packet_path,
                red_team_dir=Path(tmpdir) / "packet-red-team",
            )
            evidence_index_red_team = run_evidence_index_red_team(
                artifact_dir,
                packet_path=packet_path,
                red_team_dir=Path(tmpdir) / "evidence-index-red-team",
            )
            claim_sweep_written = verify_all_claims(
                packet_path,
                result_path=artifact_dir / "showcase-claim-sweep-result.json",
            )
            claim_certificate_path = Path(
                str(claim_sweep_written["claim_certificate_path"])
            )
            claim_certificate_markdown_path = Path(
                str(claim_sweep_written["claim_certificate_markdown_path"])
            )
            claim_certificate_exists = claim_certificate_path.exists()
            claim_certificate_markdown_exists = claim_certificate_markdown_path.exists()
            claim_certificate = json.loads(
                claim_certificate_path.read_text(encoding="utf-8")
            )
            claim_certificate_body = {
                key: value
                for key, value in claim_certificate.items()
                if key != "certificate_sha256"
            }
            claim_certificate_markdown = (
                claim_certificate_markdown_path.read_text(encoding="utf-8")
            )
            claim_certificate_details = verify_claim_certificate(
                packet_path,
                claim_certificate_path,
                certificate_markdown_path=claim_certificate_markdown_path,
            )
            claim_certificate_red_team = run_claim_certificate_red_team(
                packet_path,
                claim_certificate_path,
                certificate_markdown_path=claim_certificate_markdown_path,
                red_team_dir=Path(tmpdir) / "claim-certificate-red-team",
            )
            packet_details = verify_forensic_packet_details(packet_path)
            audit_verdict = write_audit_verdict(
                packet_details,
                packet_red_team=packet_red_team,
                evidence_index_red_team=evidence_index_red_team,
                claim_sweep=claim_sweep_written,
                claim_certificate=claim_certificate_details,
                claim_certificate_red_team=claim_certificate_red_team,
                result_path=artifact_dir / "audit-verdict.json",
                markdown_path=artifact_dir / "audit-verdict.md",
            )
            audit_verdict_body = {
                key: value
                for key, value in audit_verdict.items()
                if key
                not in {
                    "audit_verdict_sha256",
                    "result_path",
                    "markdown_path",
                }
            }
            audit_verdict_json_exists = (artifact_dir / "audit-verdict.json").exists()
            audit_verdict_markdown = (artifact_dir / "audit-verdict.md").read_text(
                encoding="utf-8"
            )
            audit_verdict_details = verify_audit_verdict(
                packet_path,
                artifact_dir / "audit-verdict.json",
                markdown_path=artifact_dir / "audit-verdict.md",
            )
            audit_verdict_red_team = run_audit_verdict_red_team(
                packet_path,
                artifact_dir / "audit-verdict.json",
                markdown_path=artifact_dir / "audit-verdict.md",
                red_team_dir=Path(tmpdir) / "audit-verdict-red-team",
            )
            audit_proof_graph = write_audit_proof_graph(
                packet_path,
                artifact_dir / "audit-verdict.json",
                claim_certificate_path,
                result_path=artifact_dir / "audit-proof-graph.json",
                markdown_path=artifact_dir / "audit-proof-graph.md",
            )
            audit_proof_graph_body = {
                key: value
                for key, value in audit_proof_graph.items()
                if key
                not in {
                    "proof_graph_sha256",
                    "result_path",
                    "markdown_path",
                    "dot_path",
                }
            }
            audit_proof_graph_markdown = (
                artifact_dir / "audit-proof-graph.md"
            ).read_text(encoding="utf-8")
            audit_proof_graph_dot = (artifact_dir / "audit-proof-graph.dot").read_text(
                encoding="utf-8"
            )
            audit_proof_graph_details = verify_audit_proof_graph(
                packet_path,
                artifact_dir / "audit-proof-graph.json",
                audit_verdict_path=artifact_dir / "audit-verdict.json",
                audit_verdict_markdown_path=artifact_dir / "audit-verdict.md",
                claim_certificate_path=claim_certificate_path,
                claim_certificate_markdown_path=claim_certificate_markdown_path,
                graph_markdown_path=artifact_dir / "audit-proof-graph.md",
            )
            audit_proof_graph_red_team = run_audit_proof_graph_red_team(
                packet_path,
                artifact_dir / "audit-proof-graph.json",
                audit_verdict_path=artifact_dir / "audit-verdict.json",
                audit_verdict_markdown_path=artifact_dir / "audit-verdict.md",
                claim_certificate_path=claim_certificate_path,
                claim_certificate_markdown_path=claim_certificate_markdown_path,
                graph_markdown_path=artifact_dir / "audit-proof-graph.md",
                red_team_dir=Path(tmpdir) / "audit-proof-graph-red-team",
            )
            audit_capsule = write_audit_capsule(
                artifact_dir,
                result_path=artifact_dir / "audit-capsule.json",
                markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_capsule_body = {
                key: value
                for key, value in audit_capsule.items()
                if key
                not in {
                    "audit_capsule_sha256",
                    "result_path",
                    "markdown_path",
                }
            }
            audit_capsule_markdown = (artifact_dir / "audit-capsule.md").read_text(
                encoding="utf-8"
            )
            audit_capsule_details = verify_audit_capsule(
                artifact_dir,
                artifact_dir / "audit-capsule.json",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_capsule_red_team = run_audit_capsule_red_team(
                artifact_dir,
                artifact_dir / "audit-capsule.json",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
                red_team_dir=Path(tmpdir) / "audit-capsule-red-team",
            )
            audit_capsule_archive = write_audit_capsule_archive(
                artifact_dir,
                artifact_dir / "audit-capsule.json",
                artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_capsule_archive_exists = (artifact_dir / "audit-capsule.zip").exists()
            audit_capsule_archive_details = verify_audit_capsule_archive(
                artifact_dir,
                artifact_dir / "audit-capsule.zip",
                artifact_dir / "audit-capsule.json",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_capsule_archive_red_team = run_audit_capsule_archive_red_team(
                artifact_dir,
                artifact_dir / "audit-capsule.zip",
                artifact_dir / "audit-capsule.json",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
                red_team_dir=Path(tmpdir) / "audit-capsule-archive-red-team",
            )
            audit_decision = write_audit_decision_certificate(
                artifact_dir,
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_decision_body = {
                key: value
                for key, value in audit_decision.items()
                if key not in {"audit_decision_sha256", "result_path"}
            }
            audit_decision_details = verify_audit_decision_certificate(
                artifact_dir,
                artifact_dir / "showcase-audit-decision.json",
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_challenge_transcript = write_audit_challenge_transcript(
                artifact_dir,
            )
            audit_challenge_transcript_body = {
                key: value
                for key, value in audit_challenge_transcript.items()
                if key
                not in {
                    "audit_challenge_transcript_sha256",
                    "result_path",
                    "markdown_path",
                }
            }
            audit_challenge_transcript_details = verify_audit_challenge_transcript(
                artifact_dir,
                artifact_dir / "showcase-audit-challenge-transcript.json",
                markdown_path=artifact_dir / "showcase-audit-challenge-transcript.md",
            )
            audit_decision_verifier_path = (
                artifact_dir / "showcase-audit-decision-verifier.py"
            )
            audit_decision_verifier_exists = audit_decision_verifier_path.exists()
            audit_decision_verifier_result = subprocess.run(
                [
                    sys.executable,
                    str(audit_decision_verifier_path),
                    str(artifact_dir),
                    "--certificate",
                    str(artifact_dir / "showcase-audit-decision.json"),
                    "--capsule",
                    str(artifact_dir / "audit-capsule.json"),
                    "--archive",
                    str(artifact_dir / "audit-capsule.zip"),
                    "--capsule-markdown",
                    str(artifact_dir / "audit-capsule.md"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            audit_gauntlet_path = artifact_dir / "showcase-audit-gauntlet.py"
            audit_gauntlet_exists = audit_gauntlet_path.exists()
            audit_gauntlet_result = subprocess.run(
                [
                    sys.executable,
                    str(audit_gauntlet_path),
                    str(artifact_dir),
                    "--certificate",
                    str(artifact_dir / "showcase-audit-decision.json"),
                    "--capsule",
                    str(artifact_dir / "audit-capsule.json"),
                    "--archive",
                    str(artifact_dir / "audit-capsule.zip"),
                    "--capsule-markdown",
                    str(artifact_dir / "audit-capsule.md"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            audit_board = write_audit_board(
                artifact_dir,
                decision_path=artifact_dir / "showcase-audit-decision.json",
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_board_body = {
                key: value
                for key, value in audit_board.items()
                if key not in {"audit_board_sha256", "result_path", "markdown_path"}
            }
            audit_board_details = verify_audit_board(
                artifact_dir,
                artifact_dir / "showcase-audit-board.json",
                markdown_path=artifact_dir / "showcase-audit-board.md",
                decision_path=artifact_dir / "showcase-audit-decision.json",
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_facts = write_audit_facts(
                artifact_dir,
                board_path=artifact_dir / "showcase-audit-board.json",
                decision_path=artifact_dir / "showcase-audit-decision.json",
                transcript_path=artifact_dir
                / "showcase-audit-challenge-transcript.json",
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_facts_body = {
                key: value
                for key, value in audit_facts.items()
                if key not in {"audit_facts_sha256", "result_path", "metta_file_path"}
            }
            audit_facts_details = verify_audit_facts(
                artifact_dir,
                artifact_dir / "showcase-audit-facts.json",
                metta_path=artifact_dir / "showcase-audit-facts.metta",
                board_path=artifact_dir / "showcase-audit-board.json",
                decision_path=artifact_dir / "showcase-audit-decision.json",
                transcript_path=artifact_dir
                / "showcase-audit-challenge-transcript.json",
                capsule_path=artifact_dir / "audit-capsule.json",
                archive_path=artifact_dir / "audit-capsule.zip",
                capsule_markdown_path=artifact_dir / "audit-capsule.md",
            )
            audit_facts_metta = (
                artifact_dir / "showcase-audit-facts.metta"
            ).read_text(encoding="utf-8")
            standalone_verifier_path = artifact_dir / "showcase-standalone-verifier.py"
            standalone_verifier_exists = standalone_verifier_path.exists()
            standalone_verifier_result = subprocess.run(
                [
                    sys.executable,
                    str(standalone_verifier_path),
                    str(artifact_dir),
                    "--capsule",
                    str(artifact_dir / "audit-capsule.json"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            standalone_archive_verifier_path = (
                artifact_dir / "showcase-standalone-archive-verifier.py"
            )
            standalone_archive_verifier_exists = (
                standalone_archive_verifier_path.exists()
            )
            standalone_archive_verifier_result = subprocess.run(
                [
                    sys.executable,
                    str(standalone_archive_verifier_path),
                    str(artifact_dir / "audit-capsule.zip"),
                    "--capsule",
                    "audit-capsule.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            audit_dashboard_path = artifact_dir / "showcase-audit-dashboard.html"
            audit_dashboard_exists = audit_dashboard_path.exists()
            audit_dashboard_text = (
                audit_dashboard_path.read_text(encoding="utf-8")
                if audit_dashboard_exists
                else ""
            )
            one_command_verifier_path = artifact_dir / "showcase-verify-all.py"
            one_command_verifier_exists = one_command_verifier_path.exists()
            one_command_verifier_result = subprocess.run(
                [
                    sys.executable,
                    str(one_command_verifier_path),
                    str(artifact_dir),
                    "--capsule",
                    "audit-capsule.json",
                    "--archive",
                    "audit-capsule.zip",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            checksum_manifest_path = artifact_dir / "showcase-checksums.sha256"
            checksum_manifest_exists = checksum_manifest_path.exists()
            checksum_manifest_result = subprocess.run(
                ["sha256sum", "-c", checksum_manifest_path.name],
                cwd=artifact_dir,
                check=False,
                capture_output=True,
                text=True,
            )
            audit_policy_path = artifact_dir / "showcase-audit-policy.json"
            audit_policy_exists = audit_policy_path.exists()
            audit_policy = json.loads(audit_policy_path.read_text(encoding="utf-8"))
            audit_policy_details = verify_audit_policy(
                artifact_dir,
                audit_policy_path,
                capsule=audit_capsule,
            )
            runtime_manifest_path = artifact_dir / "showcase-runtime-manifest.json"
            runtime_manifest_exists = runtime_manifest_path.exists()
            runtime_manifest = json.loads(
                runtime_manifest_path.read_text(encoding="utf-8")
            )
            runtime_manifest_details = verify_runtime_manifest(
                artifact_dir,
                runtime_manifest_path,
            )
            provenance_attestation_path = (
                artifact_dir / "showcase-provenance.intoto.json"
            )
            provenance_attestation_exists = provenance_attestation_path.exists()
            provenance_attestation = json.loads(
                provenance_attestation_path.read_text(encoding="utf-8")
            )
            provenance_attestation_details = verify_audit_provenance_attestation(
                artifact_dir,
                provenance_attestation_path,
            )
            audit_receipt_path = artifact_dir / "showcase-audit-receipt.json"
            audit_receipt_exists = audit_receipt_path.exists()
            audit_receipt = json.loads(audit_receipt_path.read_text(encoding="utf-8"))
            audit_receipt_details = verify_audit_receipt(
                artifact_dir,
                audit_receipt_path,
            )
            evidence_index_path = Path(packet["evidence_index_path"])
            evidence_index = json.loads(evidence_index_path.read_text(encoding="utf-8"))
            evidence_index["evidence_summary"]["claim_count"] = 0
            write_json(evidence_index_path, evidence_index)
            index_tamper_verifies = verify_forensic_packet(packet_path)
            index_tamper_details = verify_forensic_packet_details(packet_path)
            report_path.write_text(
                report_path.read_text(encoding="utf-8")
                + "\nartifact-inclusion-tamper\n",
                encoding="utf-8",
            )
            tampered_inclusion_details = verify_artifact_inclusion(
                packet_path,
                Path("showcase-report.md"),
            )
            verifier_source = json.loads(
                (artifact_dir / "showcase-verifier-result.json").read_text(
                    encoding="utf-8"
                )
            )
            verifier_source["checks"]["context_showcase_artifacts_verify"] = False
            write_json(artifact_dir / "showcase-verifier-result.json", verifier_source)
            tampered_claim_details = verify_claim_evidence(
                packet_path,
                "generated_context_inference_control",
            )
            tampered_claim_sweep = verify_all_claims(packet_path)

        self.assertTrue(packet["packet_verified"])
        self.assertEqual(len(packet["evidence_index_sha256"]), 64)
        self.assertEqual(
            len(packet_json["roots"]["claim_ledger_root_sha256"]),
            64,
        )
        self.assertEqual(
            len(packet_json["roots"]["artifact_merkle_root_sha256"]),
            64,
        )
        self.assertEqual(
            packet_json["roots"]["artifact_merkle_root_sha256"],
            packet_json["artifact_merkle_tree"]["root_sha256"],
        )
        self.assertTrue(packet_verifies)
        self.assertTrue(inclusion_details["checks"]["inclusion_verified"])
        self.assertEqual(inclusion_details["artifact_key"], "showcase-report.md")
        self.assertTrue(claim_details["checks"]["claim_verified"])
        self.assertTrue(claim_details["checks"]["evidence_sources_sealed"])
        self.assertEqual(
            claim_details["evidence"][0]["source_hash_anchor"],
            "forensic_source_verifier_sha256",
        )
        self.assertEqual(
            claim_details["claim_id"],
            "generated_context_inference_control",
        )
        self.assertTrue(claim_sweep["checks"]["claim_sweep_verified"])
        self.assertEqual(claim_sweep["claim_count"], 2)
        self.assertEqual(claim_sweep["sealed_source_count"], 2)
        self.assertEqual(
            claim_sweep["source_anchor_counts"],
            {"forensic_source_verifier_sha256": 2},
        )
        self.assertEqual(claim_sweep["failed_claims"], [])
        self.assertTrue(claim_sweep_written["checks"]["claim_sweep_verified"])
        self.assertTrue(claim_certificate_exists)
        self.assertTrue(claim_certificate_markdown_exists)
        self.assertEqual(claim_certificate["claim_count"], 2)
        self.assertEqual(claim_certificate["sealed_source_count"], 2)
        self.assertEqual(
            claim_certificate["certificate_sha256"],
            canonical_object_sha256(claim_certificate_body),
        )
        self.assertEqual(
            claim_sweep_written["claim_certificate_sha256"],
            claim_certificate["certificate_sha256"],
        )
        self.assertIn("PeTTaChainer Claim Certificate", claim_certificate_markdown)
        self.assertIn("forensic_source_verifier_sha256", claim_certificate_markdown)
        self.assertTrue(
            claim_certificate_details["checks"]["claim_certificate_verified"],
            claim_certificate_details,
        )
        self.assertTrue(
            claim_certificate_red_team["claim_certificate_red_team_pass"],
            claim_certificate_red_team,
        )
        self.assertEqual(claim_certificate_red_team["case_count"], 5)
        self.assertFalse(
            claim_certificate_red_team["cases"]["claim_count_forgery"][
                "claim_certificate_verified"
            ]
        )
        self.assertNotIn(
            "certificate_hash_matches",
            claim_certificate_red_team["cases"]["claim_count_forgery"][
                "actual_failed_checks"
            ],
        )
        self.assertFalse(
            claim_certificate_red_team["cases"]["evidence_anchor_forgery"][
                "claim_certificate_verified"
            ]
        )
        self.assertTrue(audit_verdict_json_exists)
        self.assertEqual(audit_verdict["verdict"], "PASS")
        self.assertEqual(audit_verdict["claim_count"], 2)
        self.assertEqual(audit_verdict["verified_claim_count"], 2)
        self.assertEqual(audit_verdict["sealed_source_count"], 2)
        self.assertEqual(audit_verdict["red_team_case_count_total"], 25)
        self.assertEqual(
            audit_verdict["audit_verdict_sha256"],
            canonical_object_sha256(audit_verdict_body),
        )
        self.assertIn("PeTTaChainer Audit Verdict", audit_verdict_markdown)
        self.assertIn("Verdict: `PASS`", audit_verdict_markdown)
        self.assertTrue(
            audit_verdict_details["checks"]["audit_verdict_verified"],
            audit_verdict_details,
        )
        self.assertTrue(
            audit_verdict_red_team["audit_verdict_red_team_pass"],
            audit_verdict_red_team,
        )
        self.assertEqual(audit_verdict_red_team["case_count"], 5)
        self.assertFalse(
            audit_verdict_red_team["cases"]["component_check_forgery"][
                "audit_verdict_verified"
            ]
        )
        self.assertNotIn(
            "audit_verdict_hash_matches",
            audit_verdict_red_team["cases"]["component_check_forgery"][
                "actual_failed_checks"
            ],
        )
        self.assertFalse(
            audit_verdict_red_team["cases"]["component_hash_forgery"][
                "audit_verdict_verified"
            ]
        )
        self.assertEqual(audit_proof_graph["verdict"], "PASS")
        self.assertEqual(audit_proof_graph["claim_count"], 2)
        self.assertEqual(audit_proof_graph["verified_claim_count"], 2)
        self.assertGreater(audit_proof_graph["node_count"], 2)
        self.assertGreater(audit_proof_graph["edge_count"], 2)
        self.assertEqual(
            audit_proof_graph["proof_graph_sha256"],
            canonical_object_sha256(audit_proof_graph_body),
        )
        self.assertIn("PeTTaChainer Audit Proof Graph", audit_proof_graph_markdown)
        self.assertIn("generated_context_inference_control", audit_proof_graph_markdown)
        self.assertIn("digraph PeTTaChainerAuditProofGraph", audit_proof_graph_dot)
        self.assertIn("evidence_supports_claim", audit_proof_graph_dot)
        self.assertTrue(
            audit_proof_graph_details["checks"]["audit_proof_graph_verified"],
            audit_proof_graph_details,
        )
        self.assertTrue(
            audit_proof_graph_red_team["audit_proof_graph_red_team_pass"],
            audit_proof_graph_red_team,
        )
        self.assertEqual(audit_proof_graph_red_team["case_count"], 6)
        self.assertFalse(
            audit_proof_graph_red_team["cases"]["claim_edge_forgery"][
                "audit_proof_graph_verified"
            ]
        )
        self.assertFalse(
            audit_proof_graph_red_team["cases"]["evidence_seal_forgery"][
                "audit_proof_graph_verified"
            ]
        )
        self.assertFalse(
            audit_proof_graph_red_team["cases"]["dot_forgery"][
                "audit_proof_graph_verified"
            ]
        )
        self.assertNotIn(
            "proof_graph_hash_matches",
            audit_proof_graph_red_team["cases"]["claim_node_forgery"][
                "actual_failed_checks"
            ],
        )
        self.assertGreaterEqual(audit_capsule["file_count"], 8)
        self.assertEqual(
            audit_capsule["audit_capsule_sha256"],
            canonical_object_sha256(audit_capsule_body),
        )
        self.assertTrue(
            {
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
            }.issubset(set(audit_capsule["artifact_roles"]))
        )
        self.assertEqual(len(audit_capsule["transparency_log_root_sha256"]), 64)
        self.assertEqual(len(audit_capsule["provenance_attestation_sha256"]), 64)
        self.assertEqual(len(audit_capsule["audit_policy_sha256"]), 64)
        self.assertEqual(len(audit_capsule["runtime_manifest_sha256"]), 64)
        self.assertEqual(len(audit_capsule["audit_receipt_sha256"]), 64)
        self.assertEqual(
            len(audit_capsule["audit_receipt_subject_merkle_root_sha256"]),
            64,
        )
        self.assertGreater(audit_capsule["transparency_log_entry_count"], 0)
        self.assertGreater(audit_capsule["provenance_subject_count"], 0)
        self.assertGreater(audit_capsule["audit_receipt_subject_count"], 0)
        self.assertIn("PeTTaChainer Audit Capsule", audit_capsule_markdown)
        self.assertIn("standalone_verifier", audit_capsule_markdown)
        self.assertIn("standalone_archive_verifier", audit_capsule_markdown)
        self.assertIn("transparency_log", audit_capsule_markdown)
        self.assertIn("audit_dashboard", audit_capsule_markdown)
        self.assertIn("one_command_verifier", audit_capsule_markdown)
        self.assertIn("checksum_manifest", audit_capsule_markdown)
        self.assertIn("provenance_attestation", audit_capsule_markdown)
        self.assertIn("audit_receipt", audit_capsule_markdown)
        self.assertIn("audit_policy", audit_capsule_markdown)
        self.assertIn("runtime_manifest", audit_capsule_markdown)
        self.assertIn("Provenance attestation SHA-256", audit_capsule_markdown)
        self.assertIn("Audit policy SHA-256", audit_capsule_markdown)
        self.assertIn("Runtime manifest SHA-256", audit_capsule_markdown)
        self.assertIn("Audit receipt Merkle root", audit_capsule_markdown)
        self.assertIn("Transparency log root", audit_capsule_markdown)
        self.assertIn("audit_proof_graph_dot", audit_capsule_markdown)
        self.assertTrue(audit_dashboard_exists)
        self.assertIn("PeTTaChainer Audit Dashboard", audit_dashboard_text)
        self.assertTrue(audit_policy_exists)
        self.assertEqual(
            audit_policy["artifact_kind"],
            "pettachainer_showcase_audit_policy",
        )
        self.assertIn("audit_policy", audit_policy["required_roles"])
        self.assertIn("audit_policy_forgery", audit_policy["required_red_team_cases"]["audit_capsule"])
        self.assertTrue(
            audit_policy_details["checks"]["audit_policy_verified"],
            audit_policy_details,
        )
        self.assertTrue(runtime_manifest_exists)
        self.assertEqual(
            runtime_manifest["artifact_kind"],
            "pettachainer_showcase_runtime_manifest",
        )
        self.assertEqual(runtime_manifest["manifest_version"], 1)
        self.assertIn("source_files", runtime_manifest)
        self.assertIn("generated_tools", runtime_manifest)
        self.assertTrue(
            runtime_manifest_details["checks"]["runtime_manifest_verified"],
            runtime_manifest_details,
        )
        self.assertTrue(audit_receipt_exists)
        self.assertEqual(
            audit_receipt["artifact_kind"],
            "pettachainer_showcase_audit_receipt",
        )
        self.assertEqual(audit_receipt["receipt_version"], 1)
        self.assertEqual(len(audit_receipt["subject_merkle_root_sha256"]), 64)
        self.assertTrue(
            audit_receipt_details["checks"]["audit_receipt_verified"],
            audit_receipt_details,
        )
        self.assertTrue(provenance_attestation_exists)
        self.assertEqual(
            provenance_attestation["artifact_kind"],
            "pettachainer_showcase_provenance_attestation",
        )
        self.assertEqual(
            provenance_attestation["predicateType"],
            "https://slsa.dev/provenance/v1",
        )
        self.assertEqual(provenance_attestation["_type"], "https://in-toto.io/Statement/v1")
        self.assertTrue(
            provenance_attestation_details["checks"][
                "provenance_attestation_verified"
            ],
            provenance_attestation_details,
        )
        self.assertTrue(standalone_verifier_exists)
        self.assertEqual(standalone_verifier_result.returncode, 0)
        self.assertIn(
            "PASS audit capsule standalone verification",
            standalone_verifier_result.stdout,
        )
        self.assertTrue(standalone_archive_verifier_exists)
        self.assertEqual(standalone_archive_verifier_result.returncode, 0)
        self.assertIn(
            "PASS audit capsule archive standalone verification",
            standalone_archive_verifier_result.stdout,
        )
        self.assertTrue(one_command_verifier_exists)
        self.assertEqual(one_command_verifier_result.returncode, 0)
        self.assertIn(
            "PASS PeTTaChainer portable audit capsule",
            one_command_verifier_result.stdout,
        )
        self.assertTrue(checksum_manifest_exists)
        self.assertEqual(checksum_manifest_result.returncode, 0)
        self.assertTrue(
            audit_capsule_details["checks"]["audit_capsule_verified"],
            audit_capsule_details,
        )
        self.assertTrue(
            audit_capsule_red_team["audit_capsule_red_team_pass"],
            audit_capsule_red_team,
        )
        self.assertEqual(audit_capsule_red_team["case_count"], 14)
        self.assertFalse(
            audit_capsule_red_team["cases"]["artifact_drift_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["role_omission_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["command_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["one_command_verifier_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["checksum_manifest_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["provenance_attestation_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["audit_receipt_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["audit_policy_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["runtime_manifest_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["transparency_log_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_red_team["cases"]["audit_dashboard_forgery"][
                "audit_capsule_verified"
            ]
        )
        self.assertTrue(audit_capsule_archive_exists)
        self.assertEqual(
            audit_capsule_archive["entry_count"],
            audit_capsule["file_count"] + 2,
        )
        self.assertEqual(len(audit_capsule_archive["archive_sha256"]), 64)
        self.assertTrue(
            audit_capsule_archive_details["checks"][
                "audit_capsule_archive_verified"
            ],
            audit_capsule_archive_details,
        )
        self.assertTrue(
            audit_capsule_archive_red_team[
                "audit_capsule_archive_red_team_pass"
            ],
            audit_capsule_archive_red_team,
        )
        self.assertEqual(audit_capsule_archive_red_team["case_count"], 5)
        self.assertFalse(
            audit_capsule_archive_red_team["cases"]["archive_entry_drift"][
                "audit_capsule_archive_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_archive_red_team["cases"]["archive_metadata_forgery"][
                "audit_capsule_archive_verified"
            ]
        )
        self.assertFalse(
            audit_capsule_archive_red_team["cases"]["archive_duplicate_entry"][
                "audit_capsule_archive_verified"
            ]
        )
        self.assertEqual(audit_decision["verdict"], "PASS")
        self.assertEqual(
            audit_decision["audit_decision_sha256"],
            canonical_object_sha256(audit_decision_body),
        )
        self.assertEqual(audit_decision["subject_base"], "external-over-sealed-capsule")
        self.assertEqual(audit_decision["subject_count"], 13)
        self.assertTrue(
            audit_decision_details["checks"]["audit_decision_verified"],
            audit_decision_details,
        )
        self.assertTrue(audit_decision_verifier_exists)
        self.assertEqual(audit_decision_verifier_result.returncode, 0)
        self.assertIn(
            "PASS audit decision standalone verification",
            audit_decision_verifier_result.stdout,
        )
        self.assertTrue(
            audit_decision["checks"]["standalone_decision_verifier_matches_expected"]
        )
        self.assertTrue(audit_gauntlet_exists)
        self.assertEqual(audit_gauntlet_result.returncode, 0)
        self.assertIn(
            "PASS PeTTaChainer portable audit gauntlet",
            audit_gauntlet_result.stdout,
        )
        self.assertTrue(audit_decision["checks"]["audit_gauntlet_matches_expected"])
        self.assertTrue(
            audit_decision["checks"]["audit_capsule_red_team_covers_required_cases"]
        )
        self.assertTrue(
            audit_decision["checks"][
                "audit_capsule_archive_red_team_covers_required_cases"
            ]
        )
        self.assertEqual(
            audit_decision["red_team_summary"]["audit_capsule"]["case_count"],
            14,
        )
        self.assertEqual(
            audit_decision["red_team_summary"]["audit_capsule_archive"][
                "case_count"
            ],
            5,
        )
        self.assertEqual(audit_challenge_transcript["verdict"], "PASS")
        self.assertEqual(
            audit_challenge_transcript["audit_challenge_transcript_sha256"],
            canonical_object_sha256(audit_challenge_transcript_body),
        )
        self.assertEqual(audit_challenge_transcript["observed_case_count"], 19)
        self.assertEqual(audit_challenge_transcript["rejected_case_count"], 19)
        self.assertTrue(
            audit_challenge_transcript["coverage"]["all_required_cases_observed"]
        )
        self.assertTrue(
            audit_challenge_transcript_details["checks"][
                "audit_challenge_transcript_verified"
            ],
            audit_challenge_transcript_details,
        )
        self.assertTrue(
            audit_decision["checks"]["audit_challenge_transcript_verified"]
        )
        self.assertEqual(
            audit_decision["audit_challenge_transcript_sha256"],
            audit_challenge_transcript["audit_challenge_transcript_sha256"],
        )
        self.assertEqual(audit_decision["audit_challenge_transcript_rejected_cases"], 19)
        self.assertEqual(audit_board["verdict"], "PASS")
        self.assertEqual(
            audit_board["audit_board_sha256"],
            canonical_object_sha256(audit_board_body),
        )
        self.assertEqual(audit_board["audit_decision_sha256"], audit_decision["audit_decision_sha256"])
        self.assertEqual(audit_board["red_team_rejected_cases"], 19)
        self.assertEqual(
            audit_board["audit_challenge_transcript_sha256"],
            audit_challenge_transcript["audit_challenge_transcript_sha256"],
        )
        self.assertGreaterEqual(len(audit_board["controls"]), 11)
        self.assertTrue(
            audit_board_details["checks"]["audit_board_verified"],
            audit_board_details,
        )
        self.assertEqual(audit_facts["verdict"], "PASS")
        self.assertEqual(
            audit_facts["audit_facts_sha256"],
            canonical_object_sha256(audit_facts_body),
        )
        self.assertEqual(
            audit_facts["audit_board_sha256"],
            audit_board["audit_board_sha256"],
        )
        self.assertEqual(
            audit_facts["audit_challenge_transcript_sha256"],
            audit_challenge_transcript["audit_challenge_transcript_sha256"],
        )
        self.assertEqual(audit_facts["red_team_rejected_cases"], 19)
        self.assertEqual(audit_facts["audit_challenge_transcript_rejected_cases"], 19)
        self.assertGreaterEqual(audit_facts["control_count"], 11)
        self.assertIn("!(test (audit-facts-verdict) PASS)", audit_facts_metta)
        self.assertIn(
            '!(test (audit-control-status "challenge transcript verifies") PASS)',
            audit_facts_metta,
        )
        self.assertTrue(
            audit_facts_details["checks"]["audit_facts_verified"],
            audit_facts_details,
        )
        self.assertFalse(forged_verifies)
        self.assertTrue(forged_details["checks"]["root_hash_matches"])
        self.assertFalse(forged_details["checks"]["context_evidence_matches_witness"])
        self.assertFalse(forged_details["checks"]["packet_verified"])
        self.assertFalse(claim_forged_verifies)
        self.assertTrue(claim_forged_details["checks"]["root_hash_matches"])
        self.assertFalse(claim_forged_details["checks"]["claim_ledger_matches_source"])
        self.assertFalse(claim_forged_details["checks"]["packet_verified"])
        self.assertFalse(incident_forged_verifies)
        self.assertTrue(incident_forged_details["checks"]["root_hash_matches"])
        self.assertFalse(
            incident_forged_details["checks"]["incident_summary_matches_source"]
        )
        self.assertFalse(incident_forged_details["checks"]["packet_verified"])
        self.assertFalse(index_tamper_verifies)
        self.assertFalse(index_tamper_details["checks"]["evidence_index_matches_packet"])
        self.assertFalse(index_tamper_details["checks"]["packet_verified"])
        self.assertFalse(tampered_inclusion_details["checks"]["inclusion_verified"])
        self.assertFalse(
            tampered_inclusion_details["checks"]["artifact_hash_matches_packet"]
        )
        self.assertTrue(tampered_inclusion_details["checks"]["proof_root_matches_packet"])
        self.assertFalse(tampered_claim_details["checks"]["claim_verified"])
        self.assertFalse(tampered_claim_details["checks"]["evidence_links_resolve"])
        self.assertFalse(tampered_claim_details["checks"]["evidence_sources_sealed"])
        self.assertFalse(tampered_claim_sweep["checks"]["claim_sweep_verified"])
        self.assertEqual(tampered_claim_sweep["sealed_source_count"], 0)
        self.assertEqual(
            tampered_claim_sweep["failed_claims"],
            [
                "forensic_packet_semantic_binding",
                "generated_context_inference_control",
            ],
        )
        self.assertTrue(packet_red_team["packet_red_team_pass"], packet_red_team)
        self.assertGreaterEqual(packet_red_team["case_count"], 17)
        self.assertEqual(packet_red_team["skipped_case_count"], 0)
        self.assertFalse(
            packet_red_team["cases"]["artifact_merkle_root_forgery"][
                "packet_verified"
            ]
        )
        self.assertFalse(
            packet_red_team["cases"]["artifact_merkle_proof_forgery"][
                "packet_verified"
            ]
        )
        self.assertFalse(
            packet_red_team["cases"]["aggregate_root_forgery"]["packet_verified"]
        )
        self.assertTrue(
            packet_red_team["cases"]["incident_summary_forgery"]["root_hash_matches"]
        )
        self.assertFalse(
            packet_red_team["cases"]["incident_summary_forgery"]["packet_verified"]
        )
        self.assertTrue(
            evidence_index_red_team["evidence_index_red_team_pass"],
            evidence_index_red_team,
        )
        self.assertEqual(evidence_index_red_team["case_count"], 2)
        self.assertFalse(
            evidence_index_red_team["cases"]["evidence_index_json_forgery"][
                "packet_verified"
            ]
        )
        self.assertFalse(
            evidence_index_red_team["cases"]["evidence_index_markdown_forgery"][
                "packet_verified"
            ]
        )


if __name__ == "__main__":
    unittest.main()
