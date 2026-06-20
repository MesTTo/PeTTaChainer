import json
import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.complementary_evidence import (
    run_complementary_evidence_showcase,
)
from pettachainer.benchmarks.context_showcase import sha256_file, sha256_json
from pettachainer.benchmarks.verify_complementary_evidence import (
    verify_complementary_evidence_artifacts,
)


class TestComplementaryEvidence(unittest.TestCase):
    def test_complementary_evidence_showcase_runs_and_records_proof(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_complementary_evidence_showcase(
                output_dir=Path(tmpdir),
                timeout_s=30,
            )
            result_json = Path(result.result_path).read_text(encoding="utf-8")
            report = Path(result.report_path).read_text(encoding="utf-8")
            verification = verify_complementary_evidence_artifacts(
                Path(tmpdir),
                replay=True,
                timeout_s=30,
            )

        payload = json.loads(result_json)
        self.assertTrue(all(result.checks.values()), result.checks)
        self.assertTrue(all(payload["checks"].values()), payload["checks"])
        self.assertTrue(verification["passed"], verification)
        self.assertIn("merge/additive-complement", report)
        self.assertIn("(rule-proof neg-branch (negated d))", report)
        self.assertIn("(rule-proof pos-branch d)", report)
        self.assertIn("(STV 0.5 0.5)", report)
        self.assertEqual(payload["summary_sha256"], sha256_json(payload["summary_lines"]))

    def test_complementary_verifier_rejects_hash_consistent_log_forgery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            run_complementary_evidence_showcase(output_dir=output_dir, timeout_s=30)

            log_path = output_dir / "additive-complement-merge.log"
            log_path.write_text(
                log_path.read_text(encoding="utf-8").replace(
                    "merge/additive-complement",
                    "merge/highest-confidence",
                ),
                encoding="utf-8",
            )
            manifest_path = output_dir / "complementary-evidence-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["additive-complement-merge.log"] = sha256_file(log_path)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            forged = verify_complementary_evidence_artifacts(
                output_dir,
                replay=False,
            )

        self.assertFalse(forged["passed"], forged)
        self.assertTrue(forged["checks"]["file_hashes_match"], forged)
        self.assertFalse(forged["checks"]["logs_prove_expected_terms"], forged)

    def test_complementary_verifier_rejects_hash_consistent_summary_forgery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            run_complementary_evidence_showcase(output_dir=output_dir, timeout_s=30)

            result_path = output_dir / "complementary-evidence-result.json"
            report_path = output_dir / "complementary-evidence-report.md"
            manifest_path = output_dir / "complementary-evidence-manifest.json"

            result = json.loads(result_path.read_text(encoding="utf-8"))
            forged_line = "(forged-complementary-proof-line)"
            result["summary_lines"].append(forged_line)
            result["summary_sha256"] = sha256_json(result["summary_lines"])
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report_path.write_text(
                report_path.read_text(encoding="utf-8") + forged_line + "\n",
                encoding="utf-8",
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["summary_sha256"] = result["summary_sha256"]
            manifest["files"]["complementary-evidence-result.json"] = sha256_file(
                result_path
            )
            manifest["files"]["complementary-evidence-report.md"] = sha256_file(
                report_path
            )
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            forged = verify_complementary_evidence_artifacts(
                output_dir,
                replay=True,
                timeout_s=30,
            )

        self.assertFalse(forged["passed"], forged)
        self.assertTrue(forged["checks"]["file_hashes_match"], forged)
        self.assertTrue(forged["checks"]["manifest_summary_hashes_match"], forged)
        self.assertTrue(forged["checks"]["logs_prove_expected_terms"], forged)
        self.assertFalse(forged["checks"]["replay_matches_recorded_summary"], forged)


if __name__ == "__main__":
    unittest.main()
