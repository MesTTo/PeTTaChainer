import json
import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.context_showcase import (
    run_context_showcase,
    sha256_file,
    sha256_json,
)
from pettachainer.benchmarks.verify_context_showcase import (
    verify_context_showcase_artifacts,
)


class TestContextShowcase(unittest.TestCase):
    def test_context_showcase_runs_petta_demos_and_extracts_audits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_context_showcase(output_dir=Path(tmpdir), timeout_s=30)
            result_json = Path(result.result_path).read_text(encoding="utf-8")
            report = Path(result.report_path).read_text(encoding="utf-8")

        payload = json.loads(result_json)
        self.assertTrue(all(result.checks.values()), result.checks)
        self.assertTrue(all(payload["checks"].values()), payload["checks"])
        self.assertTrue(all(demo["summary_sha256"] for demo in payload["demos"]))
        self.assertIn("adaptive-control:shift_to_grounding", payload["checks"])
        self.assertIn("beam-needle-control:depth4_guard", payload["checks"])
        self.assertIn("Generated Context Showcase", report)
        self.assertIn("ContextControlSelectionShiftSummary", report)
        self.assertIn("ContextBeamControlSelectionSummary", report)
        self.assertIn("beam-needle-grounding", report)
        self.assertIn("beam-needle-default-flight", report)

    def test_context_showcase_verifier_rejects_semantic_log_forgery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            run_context_showcase(output_dir=output_dir, timeout_s=30)
            verification = verify_context_showcase_artifacts(
                output_dir,
                replay=True,
                timeout_s=30,
            )

            log_path = output_dir / "beam-needle-control.log"
            log_path.write_text(
                log_path.read_text(encoding="utf-8").replace(
                    "beam-needle-grounding",
                    "beam-needle-forged-grounding",
                ),
                encoding="utf-8",
            )
            manifest_path = output_dir / "context-showcase-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["beam-needle-control.log"] = sha256_file(log_path)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            forged = verify_context_showcase_artifacts(output_dir, replay=False)

        self.assertTrue(verification["passed"], verification)
        self.assertTrue(verification["checks"]["replay_matches_recorded_summary"])
        self.assertFalse(forged["passed"], forged)
        self.assertTrue(forged["checks"]["file_hashes_match"], forged)
        self.assertFalse(forged["checks"]["logs_prove_expected_terms"], forged)

    def test_context_showcase_verifier_rejects_hash_consistent_summary_forgery(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            run_context_showcase(output_dir=output_dir, timeout_s=30)

            result_path = output_dir / "context-showcase-result.json"
            report_path = output_dir / "context-showcase-report.md"
            manifest_path = output_dir / "context-showcase-manifest.json"

            result = json.loads(result_path.read_text(encoding="utf-8"))
            forged_line = "(forged-extra-summary-line)"
            result["demos"][0]["summary_lines"].append(forged_line)
            result["demos"][0]["summary_sha256"] = sha256_json(
                result["demos"][0]["summary_lines"]
            )
            result_path.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report_path.write_text(
                report_path.read_text(encoding="utf-8") + forged_line + "\n",
                encoding="utf-8",
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["demo_summary_sha256"][result["demos"][0]["name"]] = result[
                "demos"
            ][0]["summary_sha256"]
            manifest["files"]["context-showcase-result.json"] = sha256_file(result_path)
            manifest["files"]["context-showcase-report.md"] = sha256_file(report_path)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            forged = verify_context_showcase_artifacts(
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
