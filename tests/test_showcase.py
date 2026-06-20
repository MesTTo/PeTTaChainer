import json
import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.showcase import canonical_json_sha256, run_showcase
from pettachainer.benchmarks.verify_showcase import (
    run_red_team_verifier,
    run_forensic_seal_sweep,
    run_forensic_packet_red_team,
    verify_recorded_context_noise,
    verify_recorded_context_counterfactuals,
    verify_recorded_noise,
    verify_forensic_packet,
    verify_forensic_packet_details,
    verify_showcase_artifacts,
    write_forensic_packet,
)


class TestShowcase(unittest.TestCase):
    def test_showcase_combines_dispatch_reasoning_and_replay_bundle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir) / "showcase"
            result = run_showcase(
                output_dir=artifact_dir,
                dispatch_iterations=8_000,
                dispatch_repeats=2,
                forward_steps=350,
                query_steps=120,
                noise_sweep_levels=(0, 10),
                context_noise_levels=(0, 50),
            )
            report = Path(result.report_path).read_text(encoding="utf-8")
            result_json = Path(result.result_path).read_text(encoding="utf-8")
            contract_json = Path(result.contract_path).read_text(encoding="utf-8")
            witness_json = Path(result.witness_path).read_text(encoding="utf-8")
            verification = verify_showcase_artifacts(artifact_dir, replay_noise=True)
            verifier_json = Path(verification["result_path"]).read_text(encoding="utf-8")
            red_team = run_red_team_verifier(
                artifact_dir,
                replay_noise=False,
                red_team_dir=Path(tmpdir) / "red-team",
            )
            forensic_packet = write_forensic_packet(verification, red_team)
            forensic_packet_json = Path(forensic_packet["json_path"]).read_text(
                encoding="utf-8"
            )
            forensic_packet_md = Path(forensic_packet["markdown_path"]).read_text(
                encoding="utf-8"
            )
            forensic_packet_verifies = verify_forensic_packet(
                Path(forensic_packet["json_path"])
            )
            forensic_packet_red_team = run_forensic_packet_red_team(
                Path(forensic_packet["json_path"]),
                artifact_dir=artifact_dir,
                red_team_dir=Path(tmpdir) / "forensic-packet-red-team",
            )
            forensic_seal_sweep = run_forensic_seal_sweep(
                artifact_dir,
                packet_path=Path(forensic_packet["json_path"]),
                sweep_dir=Path(tmpdir) / "forensic-seal-sweep",
            )
            tampered_packet = json.loads(forensic_packet_json)
            tampered_packet["red_team"]["case_count"] = 0
            tampered_packet_path = artifact_dir / "tampered-forensic-packet.json"
            tampered_packet_path.write_text(
                json.dumps(tampered_packet, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tampered_packet_verifies = verify_forensic_packet(tampered_packet_path)
            report_path = artifact_dir / "showcase-report.md"
            report_path.write_text(report + "\nforensic-packet-bound-artifact-tamper\n")
            tampered_artifact_details = verify_forensic_packet_details(
                Path(forensic_packet["json_path"])
            )
            tampered_artifact_verifies = verify_forensic_packet(
                Path(forensic_packet["json_path"])
            )
            semantic_forged_packet = json.loads(forensic_packet_json)
            semantic_forged_packet["context_evidence"]["counterfactuals"][0][
                "passed"
            ] = False
            semantic_body = {
                key: value
                for key, value in semantic_forged_packet.items()
                if key != "packet_root_sha256"
            }
            semantic_body["packet_root_sha256"] = canonical_json_sha256(
                semantic_body
            )
            semantic_forged_packet_path = (
                artifact_dir / "semantic-forged-forensic-packet.json"
            )
            semantic_forged_packet_path.write_text(
                json.dumps(semantic_body, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            semantic_forged_packet_details = verify_forensic_packet_details(
                semantic_forged_packet_path
            )
            semantic_forged_packet_verifies = verify_forensic_packet(
                semantic_forged_packet_path
            )

        self.assertTrue(all(result.checks.values()), result.checks)
        self.assertTrue(all(verification["checks"].values()), verification["checks"])
        self.assertTrue(verification["checks"]["contract_enforced"])
        self.assertTrue(all(result.dispatch.checks.values()), result.dispatch.checks)
        self.assertTrue(all(result.context.checks.values()), result.context.checks)
        self.assertTrue(all(result.complementary.checks.values()), result.complementary.checks)
        self.assertTrue(all(result.incident.checks.values()), result.incident.checks)
        self.assertTrue(all(result.bundle_verification.values()), result.bundle_verification)
        self.assertTrue(all(result.replay_verification.values()), result.replay_verification)
        self.assertTrue(result.checks["generated_context_showcase_checks_pass"])
        self.assertTrue(result.checks["generated_context_artifacts_written"])
        self.assertTrue(result.checks["generated_context_noise_stability_passes"])
        self.assertTrue(
            result.checks["generated_context_counterfactual_sensitivity_passes"]
        )
        self.assertTrue(result.checks["proof_structure_certificate_passes"])
        self.assertTrue(result.checks["semantic_forgery_rejected_by_replay"])
        self.assertTrue(result.checks["noise_stability_sweep_passes"])
        self.assertTrue(verification["checks"]["context_showcase_artifacts_verify"])
        self.assertTrue(
            verification["checks"]["recorded_context_noise_stability_passes"]
        )
        self.assertTrue(verification["checks"]["context_noise_replay_passes"])
        self.assertTrue(
            verification["checks"][
                "recorded_context_counterfactual_sensitivity_passes"
            ]
        )
        self.assertTrue(verification["checks"]["context_counterfactual_replay_passes"])
        counterfactuals = {case["name"]: case for case in result.context_counterfactuals}
        self.assertEqual(
            set(counterfactuals),
            {
                "remove_penguin_exception",
                "invert_penguin_exception",
                "ambiguous_penguin_exception",
            },
        )
        self.assertTrue(all(case["passed"] for case in counterfactuals.values()))
        self.assertNotEqual(
            counterfactuals["remove_penguin_exception"]["best_guard"],
            ["type:Penguin"],
        )
        self.assertGreater(
            counterfactuals["invert_penguin_exception"]["routed_strength"],
            0.95,
        )
        self.assertLess(
            counterfactuals["ambiguous_penguin_exception"]["ranking_margin"],
            0.05,
        )
        self.assertEqual(
            [case["extra_packets"] for case in result.context_noise_stability],
            [0, 50],
        )
        self.assertTrue(all(case["stable"] for case in result.context_noise_stability))
        self.assertTrue(
            all(case["best_guard"] == ["type:Penguin"] for case in result.context_noise_stability)
        )
        self.assertTrue(
            all(case["ranking_margin"] >= 0.05 for case in result.context_noise_stability)
        )
        self.assertTrue(
            all(
                case["runner_up_guard"] != case["best_guard"]
                for case in result.context_noise_stability
            )
        )
        self.assertTrue(
            all(case["noise_route_hits"] == 0 for case in result.context_noise_stability)
        )
        self.assertEqual([case["extra_edges"] for case in result.noise_stability], [0, 10])
        self.assertTrue(all(case["stable"] for case in result.noise_stability))
        self.assertTrue(
            all(
                case["proof_sha256"] == result.incident.proof_sha256
                for case in result.noise_stability
            )
        )
        self.assertTrue(
            all(case["injected_noise_tokens"] == 0 for case in result.noise_stability)
        )
        self.assertEqual(
            set(result.tamper_drill),
            {
                "hash_consistent_scenario_forgery",
                "metadata_consistent_semantic_forgery",
            },
        )
        self.assertTrue(
            all(case["hash_verification_passed"] for case in result.tamper_drill.values())
        )
        self.assertTrue(
            all(case["replay_rejected"] for case in result.tamper_drill.values())
        )
        self.assertIn("PeTTaChainer Full Showcase", report)
        self.assertIn("Smart Dispatch", report)
        self.assertIn("Generated Context Control", report)
        self.assertIn("Complementary Evidence Merge", report)
        self.assertIn("merge/additive-complement", report)
        self.assertIn("Generated Context Noise Stability", report)
        self.assertIn("Generated Context Counterfactuals", report)
        self.assertIn("ContextControlSelectionShiftSummary", report)
        self.assertIn("ContextBeamControlSelectionSummary", report)
        self.assertIn("Needle-in-Haystack Noise Sweep", report)
        self.assertIn("Adversarial Tamper Drill", report)
        self.assertIn("Causal Minimality Certificate", report)
        self.assertIn("generated_context_showcase_checks_pass", result_json)
        self.assertIn("generated_context_inference_control", contract_json)
        self.assertIn("generated_context_noise_stability", contract_json)
        self.assertIn("generated_context_counterfactual_sensitivity", contract_json)
        self.assertIn("complementary_evidence_additive_merge", contract_json)
        self.assertIn("structural_proof_audit", contract_json)
        self.assertIn("bundle_replay_verification_passes", result_json)
        self.assertIn("semantic_forgery_rejected_by_replay", result_json)
        self.assertIn("noise_stability_sweep_passes", result_json)
        self.assertIn("pettachainer_showcase_acceptance_contract", contract_json)
        self.assertIn("needle_in_haystack_noise_stability", contract_json)
        self.assertIn("machine_checkable_witness_certificate", contract_json)
        self.assertIn("pettachainer_showcase_witness_certificate", witness_json)
        self.assertIn("context_evidence", witness_json)
        self.assertIn("complementary_evidence", witness_json)
        self.assertIn("context_noise_stability", result_json)
        witness = json.loads(witness_json)
        self.assertEqual(len(witness["witness_root_sha256"]), 64)
        self.assertTrue(witness["context_evidence"]["checks"])
        self.assertTrue(witness["complementary_evidence"]["checks"])
        self.assertIn(
            "merge/additive-complement",
            "\n".join(witness["complementary_evidence"]["summary_lines"]),
        )
        self.assertTrue(witness["context_evidence"]["noise_stability"])
        self.assertTrue(witness["context_evidence"]["counterfactuals"])
        self.assertTrue(
            all(
                case["ranking_margin"] >= 0.05
                for case in witness["context_evidence"]["noise_stability"]
            )
        )
        self.assertTrue(
            all(
                demo["summary_sha256"]
                for demo in witness["context_evidence"]["demos"].values()
            )
        )
        self.assertTrue(
            witness["proof_evidence"]["proof_structure"]["certificate_passes"]
        )
        self.assertEqual(
            witness["proof_evidence"]["isolate_proof_sha256"],
            result.incident.proof_sha256,
        )
        self.assertIn("context-showcase/context-showcase-result.json", witness["artifact_hashes"])
        self.assertIn(
            "complementary-evidence/complementary-evidence-result.json",
            witness["artifact_hashes"],
        )
        self.assertIn("incident-bundle/proof-structure.json", witness["artifact_hashes"])
        self.assertIn("showcase-result.json", witness["artifact_hashes"])
        self.assertIn("tamper_artifacts_reject_on_replay", verifier_json)
        self.assertIn("noise_replay_passes", verifier_json)
        self.assertIn("context_showcase_artifacts_verify", verifier_json)
        self.assertIn("complementary_evidence_artifacts_verify", verifier_json)
        self.assertIn("replay_matches_recorded_summary", verifier_json)
        self.assertIn("context_noise_replay_passes", verifier_json)
        self.assertIn("context_counterfactual_replay_passes", verifier_json)
        self.assertIn("witness_certificate_verified", verifier_json)
        self.assertIn("contract_enforced", verifier_json)
        self.assertIn("claim_coverage", verifier_json)
        self.assertTrue(verification["witness_verification"]["context_evidence_match_result"])
        self.assertTrue(
            verification["witness_verification"]["complementary_evidence_match_result"]
        )
        self.assertTrue(verification["witness_verification"]["proof_structure_match_result"])
        self.assertTrue(verification["checks"]["complementary_evidence_artifacts_verify"])
        self.assertTrue(verification["checks"]["witness_certificate_verified"])
        self.assertTrue(forensic_packet_verifies)
        self.assertTrue(
            forensic_packet_red_team["packet_red_team_pass"],
            forensic_packet_red_team,
        )
        self.assertGreaterEqual(forensic_packet_red_team["case_count"], 10)
        self.assertEqual(forensic_packet_red_team["skipped_case_count"], 0)
        self.assertTrue(
            all(
                case["root_hash_matches"]
                for case in forensic_packet_red_team["cases"].values()
                if not case["skipped"]
            )
        )
        self.assertTrue(
            all(
                case["rejected"]
                for case in forensic_packet_red_team["cases"].values()
                if not case["skipped"]
            )
        )
        self.assertTrue(forensic_seal_sweep["seal_sweep_pass"], forensic_seal_sweep)
        self.assertEqual(
            forensic_seal_sweep["artifact_count"],
            len(json.loads(forensic_packet_json)["artifact_hashes"]),
        )
        self.assertTrue(
            all(case["rejected"] for case in forensic_seal_sweep["cases"].values()),
            forensic_seal_sweep,
        )
        self.assertFalse(tampered_packet_verifies)
        self.assertFalse(tampered_artifact_verifies)
        self.assertFalse(tampered_artifact_details["checks"]["artifact_hashes_match"])
        self.assertFalse(tampered_artifact_details["checks"]["packet_verified"])
        self.assertFalse(semantic_forged_packet_verifies)
        self.assertTrue(
            semantic_forged_packet_details["checks"]["root_hash_matches"]
        )
        self.assertFalse(
            semantic_forged_packet_details["checks"][
                "context_evidence_matches_witness"
            ]
        )
        self.assertFalse(semantic_forged_packet_details["checks"]["packet_verified"])
        self.assertIn("pettachainer_showcase_forensic_packet", forensic_packet_json)
        self.assertIn("structural_proof_audit", forensic_packet_json)
        self.assertIn("complementary_evidence", forensic_packet_json)
        self.assertIn("complementary_evidence_root_sha256", forensic_packet_json)
        self.assertIn("PeTTaChainer Forensic Packet", forensic_packet_md)
        self.assertIn("Packet root", forensic_packet_md)
        self.assertEqual(len(forensic_packet["packet_root_sha256"]), 64)
        self.assertTrue(
            all(
                value
                for key, value in verification["witness_verification"].items()
                if isinstance(value, bool)
            ),
            verification["witness_verification"],
        )
        self.assertTrue(
            all(claim["covered"] for claim in verification["claim_coverage"].values()),
            verification["claim_coverage"],
        )
        self.assertTrue(
            all(
                claim["evidence_complete"] and claim["evidence"]
                for claim in verification["claim_coverage"].values()
            ),
            verification["claim_coverage"],
        )

        corrupted_result = json.loads(result_json)
        corrupted_result["noise_stability"][0]["injected_noise_tokens"] = 1
        self.assertFalse(verify_recorded_noise(corrupted_result))
        corrupted_context_result = json.loads(result_json)
        corrupted_context_result["context_noise_stability"][0]["noise_route_hits"] = 1
        corrupted_context_result["context_noise_stability"][0]["stable"] = False
        self.assertFalse(verify_recorded_context_noise(corrupted_context_result))
        corrupted_ranking_result = json.loads(result_json)
        corrupted_ranking_result["context_noise_stability"][0]["ranking_margin"] = 0.0
        corrupted_ranking_result["context_noise_stability"][0]["runner_up_guard"] = [
            "type:Penguin"
        ]
        corrupted_ranking_result["context_noise_stability"][0]["stable"] = False
        self.assertFalse(verify_recorded_context_noise(corrupted_ranking_result))
        corrupted_counterfactual_result = json.loads(result_json)
        corrupted_counterfactual_result["context_counterfactuals"][0]["passed"] = False
        corrupted_counterfactual_result["context_counterfactuals"][0]["best_guard"] = [
            "type:Penguin"
        ]
        self.assertFalse(
            verify_recorded_context_counterfactuals(corrupted_counterfactual_result)
        )
        self.assertTrue(red_team["red_team_rejections_pass"], red_team)
        self.assertEqual(
            set(red_team["cases"]),
            {
                "noise_metadata_forgery",
                "context_noise_metadata_forgery",
                "context_ranking_metadata_forgery",
                "context_counterfactual_metadata_forgery",
                "tamper_metadata_forgery",
                "contract_threshold_forgery",
                "contract_claim_forgery",
                "witness_certificate_forgery",
                "witness_uncanonical_root_forgery",
                "witness_artifact_hash_forgery",
                "witness_claim_ids_forgery",
                "witness_dispatch_evidence_forgery",
                "witness_noise_evidence_forgery",
                "witness_context_noise_evidence_forgery",
                "witness_context_ranking_evidence_forgery",
                "witness_context_counterfactual_evidence_forgery",
                "witness_complementary_evidence_forgery",
                "witness_tamper_evidence_forgery",
                "witness_proof_structure_forgery",
                "report_section_forgery",
                "bundle_payload_forgery",
                "bundle_proof_structure_forgery",
                "context_log_semantic_forgery",
                "complementary_log_semantic_forgery",
            },
        )
        self.assertIn("witness_artifacts", red_team["mutation_families"])
        self.assertIn("witness_dispatch", red_team["mutation_families"])
        self.assertIn("witness_noise", red_team["mutation_families"])
        self.assertIn("witness_context_noise", red_team["mutation_families"])
        self.assertIn("witness_context_ranking", red_team["mutation_families"])
        self.assertIn("witness_context_counterfactual", red_team["mutation_families"])
        self.assertIn("witness_complementary", red_team["mutation_families"])
        self.assertIn("witness_tamper", red_team["mutation_families"])
        self.assertIn("witness_proof_structure", red_team["mutation_families"])
        self.assertIn("bundle_proof_structure", red_team["mutation_families"])
        self.assertIn("complementary_evidence", red_team["mutation_families"])
        self.assertTrue(
            all(case["rejected"] for case in red_team["cases"].values()),
            red_team,
        )
        self.assertTrue(
            all(case["actual_failed_checks"] for case in red_team["cases"].values()),
            red_team,
        )


if __name__ == "__main__":
    unittest.main()
