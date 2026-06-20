#!/usr/bin/env python3
"""Verify a saved complementary-evidence showcase artifact directory."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from pettachainer.benchmarks.complementary_evidence import (
    COMPLEMENTARY_EVIDENCE_DEMO,
    run_complementary_evidence_showcase,
)
from pettachainer.benchmarks.context_showcase import sha256_file, sha256_json


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def candidate_output_lines(log_text: str) -> list[str]:
    return [
        line.strip()
        for line in log_text.splitlines()
        if line.strip()
        and (
            line.strip().startswith("(")
            or line.strip() in {"true", "false"}
        )
        and not line.strip().startswith("(=")
    ]


def matching_line(log_text: str, expected: str) -> str:
    return next(
        (line for line in reversed(candidate_output_lines(log_text)) if expected in line),
        "",
    )


def verify_file_hashes(output_dir: Path, manifest: dict[str, Any]) -> dict[str, bool]:
    hashes: dict[str, str] = dict(manifest.get("files", {}))
    return {
        filename: (output_dir / filename).exists()
        and sha256_file(output_dir / filename) == expected_hash
        for filename, expected_hash in hashes.items()
    }


def verify_summary_hash(
    manifest: dict[str, Any],
    result: dict[str, Any],
) -> tuple[bool, dict[str, object]]:
    expected = str(manifest.get("summary_sha256", ""))
    actual = sha256_json(result.get("summary_lines", []))
    return expected == actual and actual == str(result.get("summary_sha256", "")), {
        "expected": expected,
        "actual": actual,
        "result": result.get("summary_sha256", ""),
    }


def verify_log_terms(
    output_dir: Path,
    manifest: dict[str, Any],
    result: dict[str, Any],
    report: str,
) -> tuple[bool, dict[str, object]]:
    log_path = output_dir / "additive-complement-merge.log"
    log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    summary_lines = set(result.get("summary_lines", []))
    checks = {str(check["name"]): check for check in result.get("check_details", [])}
    expected_terms = dict(COMPLEMENTARY_EVIDENCE_DEMO["expected_terms"])
    details: dict[str, object] = {
        "log_present": log_path.exists(),
        "checks": {},
    }
    all_passed = log_path.exists()
    for check_name, expected in expected_terms.items():
        line = matching_line(log_text, str(expected))
        result_check = checks.get(str(check_name), {})
        passed = (
            bool(line)
            and bool(result_check.get("passed", False))
            and result_check.get("matched_line") == line
            and line in summary_lines
            and line in report
        )
        details["checks"][str(check_name)] = {
            "expected": expected,
            "matched_line": line,
            "passed": passed,
        }
        all_passed = all_passed and passed

    manifest_demo = dict(manifest.get("demo", {}))
    shape_ok = (
        manifest_demo.get("name") == COMPLEMENTARY_EVIDENCE_DEMO["name"]
        and manifest_demo.get("metta_file") == COMPLEMENTARY_EVIDENCE_DEMO["metta_file"]
        and dict(manifest_demo.get("expected_terms", {})) == expected_terms
        and result.get("metta_file") == COMPLEMENTARY_EVIDENCE_DEMO["metta_file"]
    )
    details["shape_ok"] = shape_ok
    return all_passed and shape_ok, details


def replay_summary_details(
    result: dict[str, Any],
    replayed_result: Any,
) -> tuple[bool, dict[str, object]]:
    saved_lines = list(result.get("summary_lines", []))
    replayed_lines = list(replayed_result.summary_lines)
    saved_hash = sha256_json(saved_lines)
    replayed_hash = sha256_json(replayed_lines)
    return saved_lines == replayed_lines and saved_hash == replayed_hash, {
        "summary_lines_match": saved_lines == replayed_lines,
        "saved_summary_sha256": saved_hash,
        "replayed_summary_sha256": replayed_hash,
        "saved_summary_lines": saved_lines,
        "replayed_summary_lines": replayed_lines,
    }


def verify_complementary_evidence_artifacts(
    output_dir: Path,
    *,
    replay: bool = False,
    timeout_s: int = 30,
) -> dict[str, Any]:
    manifest_path = output_dir / "complementary-evidence-manifest.json"
    result_path = output_dir / "complementary-evidence-result.json"
    report_path = output_dir / "complementary-evidence-report.md"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    result = load_json(result_path) if result_path.exists() else {}
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""

    hash_checks = verify_file_hashes(output_dir, manifest) if manifest else {}
    logs_ok, log_details = verify_log_terms(output_dir, manifest, result, report)
    summary_ok, summary_details = verify_summary_hash(manifest, result)
    manifest_checks = dict(manifest.get("checks", {}))
    result_checks = dict(result.get("checks", {}))

    replay_result: dict[str, Any] = {
        "enabled": replay,
        "passed": True,
        "matches_recorded_summary": True,
    }
    if replay:
        with tempfile.TemporaryDirectory() as tmpdir:
            replayed = run_complementary_evidence_showcase(
                output_dir=Path(tmpdir),
                timeout_s=timeout_s,
            )
            replay_matches_summary, replay_details = replay_summary_details(
                result,
                replayed,
            )
            replay_result = {
                "enabled": True,
                "passed": all(replayed.checks.values()) and replay_matches_summary,
                "checks": replayed.checks,
                "matches_recorded_summary": replay_matches_summary,
                "summary_details": replay_details,
            }

    checks = {
        "manifest_present": manifest_path.exists(),
        "result_present": result_path.exists(),
        "report_present": report_path.exists(),
        "manifest_kind_matches": (
            manifest.get("artifact_kind")
            == "pettachainer_complementary_evidence_manifest"
        ),
        "manifest_version_matches": manifest.get("manifest_version") == 1,
        "file_hashes_match": bool(hash_checks) and all(hash_checks.values()),
        "result_checks_pass": bool(result_checks) and all(result_checks.values()),
        "manifest_checks_match_result": manifest_checks == result_checks,
        "manifest_summary_hashes_match": summary_ok,
        "logs_prove_expected_terms": logs_ok,
        "report_has_pass_verdict": "Verdict: `PASS`" in report,
        "replay_passes": bool(replay_result["passed"]),
        "replay_matches_recorded_summary": bool(
            replay_result["matches_recorded_summary"]
        ),
    }
    return {
        "checks": checks,
        "hash_checks": hash_checks,
        "log_details": log_details,
        "summary_hash_details": summary_details,
        "replay": replay_result,
        "passed": all(checks.values()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--timeout-s", type=int, default=30)
    args = parser.parse_args(argv)

    result = verify_complementary_evidence_artifacts(
        args.output_dir,
        replay=args.replay,
        timeout_s=args.timeout_s,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
