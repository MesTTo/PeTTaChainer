import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.impressive_incident_response import (
    markdown_report,
    redirect_process_output,
    replay_audit_bundle,
    run_demo,
    verify_audit_bundle,
    write_audit_bundle,
)


class TestImpressiveIncidentResponseDemo(unittest.TestCase):
    def test_demo_proves_policy_decision_and_counterfactuals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_path = Path(tmpdir) / "trace.log"
            with redirect_process_output(trace_path):
                result = run_demo(forward_steps=350, query_steps=120, trace_path=trace_path)

        self.assertTrue(all(result.checks.values()), result.checks)
        self.assertEqual(result.query_counts["isolate_customerdb"], 1)
        self.assertEqual(result.query_counts["rotate_customerdb"], 1)
        self.assertEqual(result.query_counts["isolate_demodb"], 0)
        self.assertEqual(result.isolate_proof_tokens["lateral_move"], 6)
        self.assertEqual(result.isolate_proof_tokens["noise_"], 0)
        self.assertEqual(result.ingress_ranking[0].name, "primary_laptop_path")
        self.assertEqual(result.ingress_ranking[0].isolate_customerdb, 1)
        self.assertEqual(result.ingress_ranking[0].proof_tokens["trust_primary_"], 6)
        self.assertEqual(result.ingress_ranking[0].proof_tokens["trust_secondary_"], 0)
        self.assertEqual(result.ingress_ranking[0].proof_tokens["noise_"], 0)
        self.assertEqual(result.ingress_ranking[1].name, "fallback_tokenvault_path")
        self.assertEqual(result.ingress_ranking[1].isolate_customerdb, 1)
        self.assertGreaterEqual(result.ingress_ranking[1].proof_tokens["trust_secondary_"], 2)
        self.assertEqual(result.ingress_ranking[1].proof_tokens["noise_"], 0)
        self.assertGreater(result.ingress_confidence_margin, 0.0)
        self.assertTrue(all(result.causal_checks.values()), result.causal_checks)
        primary_ablation = [
            case for case in result.causal_ablation
            if case.mode == "primary_path_minimality"
        ]
        self.assertEqual(len(primary_ablation), 11)
        self.assertTrue(all(case.isolate_customerdb == 0 for case in primary_ablation))
        distractor_ablation = [
            case for case in result.causal_ablation
            if case.mode == "distractor_invariance"
        ]
        self.assertEqual(len(distractor_ablation), 1)
        self.assertEqual(distractor_ablation[0].isolate_customerdb, 1)
        self.assertEqual(distractor_ablation[0].proof_tokens["noise_"], 0)
        self.assertEqual(
            result.counterfactuals["without_customerdb_pii"]["isolate_customerdb"], 0
        )
        self.assertEqual(
            result.counterfactuals["without_initial_compromise"]["compromised_customerdb"], 0
        )
        self.assertEqual(
            result.counterfactuals["without_phishing_seed"]["isolate_customerdb"], 1
        )
        self.assertEqual(result.counterfactuals["without_phishing_seed"]["token_seed"], 1)
        self.assertGreaterEqual(
            result.counterfactuals["without_phishing_seed"]["trust_secondary_"], 2
        )
        self.assertEqual(result.counterfactuals["without_phishing_seed"]["noise_"], 0)
        self.assertEqual(
            result.counterfactuals["without_token_seed"]["isolate_customerdb"], 1
        )
        self.assertEqual(result.counterfactuals["without_token_seed"]["phish_laptop"], 1)
        self.assertEqual(result.counterfactuals["without_token_seed"]["trust_primary_"], 6)
        self.assertEqual(result.counterfactuals["without_token_seed"]["noise_"], 0)
        self.assertEqual(
            result.counterfactuals["without_isolate_policy"]["critical_customerdb"], 1
        )
        self.assertEqual(
            result.counterfactuals["without_isolate_policy"]["isolate_customerdb"], 0
        )

        report = markdown_report(result)
        self.assertIn("Showcase verdict: **PASS**", report)
        self.assertIn("```mermaid", report)
        self.assertIn("Ranked Ingress Explanations", report)
        self.assertIn("Causal Minimality Certificate", report)
        self.assertIn("Phase Timings", report)
        self.assertIn("primary_laptop_path", report)
        self.assertIn("fallback_tokenvault_path", report)
        self.assertIn("without_phishing_seed", report)
        self.assertIn("without_token_seed", report)
        self.assertIn("without_initial_compromise", report)
        self.assertEqual(len(result.proof_sha256), 64)
        self.assertEqual(len(result.scenario_sha256), 64)
        self.assertTrue(result.proof_structure["certificate_passes"], result.proof_structure)
        self.assertTrue(result.proof_structure["checks"]["primary_chain_found"])
        self.assertTrue(result.checks["proof_structure_certificate_passes"])

    def test_demo_writes_verifiable_audit_bundle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            trace_path = tmp_path / "trace.log"
            with redirect_process_output(trace_path):
                result = run_demo(forward_steps=350, query_steps=120, trace_path=trace_path)

            bundle_dir = tmp_path / "bundle"
            files = write_audit_bundle(result, bundle_dir)
            verification = verify_audit_bundle(bundle_dir)
            replay = replay_audit_bundle(bundle_dir, tmp_path / "replay.log")
            ledger_text = (bundle_dir / "explanation-ledger.json").read_text()
            scenario_text = (bundle_dir / "scenario.metta").read_text()
            graph_text = (bundle_dir / "proof.dot").read_text()
            proof_structure_text = (bundle_dir / "proof-structure.json").read_text()
            (bundle_dir / "scenario.metta").write_text(scenario_text + "; tampered\n")
            tampered = verify_audit_bundle(bundle_dir)

        self.assertTrue(all(verification.values()), verification)
        self.assertTrue(all(replay.values()), replay)
        self.assertFalse(tampered["file_hashes_match"], tampered)
        self.assertFalse(tampered["scenario_hash_matches"], tampered)
        self.assertEqual(
            set(files),
            {
                "explanation-ledger.json",
                "MANIFEST.json",
                "proof.dot",
                "proof-structure.json",
                "raw-isolate-proof.metta",
                "report.md",
                "result.json",
                "scenario.metta",
            },
        )
        self.assertIn("replay_requirements", ledger_text)
        self.assertIn("ranked_ingress_explanations", ledger_text)
        self.assertIn("causal_ablation", ledger_text)
        self.assertIn("pettachainer_structural_proof_audit", proof_structure_text)
        self.assertIn("primary_chain_found", proof_structure_text)
        self.assertIn("lateral_move", scenario_text)
        self.assertIn("Action Isolate CustomerDB", graph_text)


if __name__ == "__main__":
    unittest.main()
