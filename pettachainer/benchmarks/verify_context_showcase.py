#!/usr/bin/env python3
"""Verify a saved generated-context showcase artifact directory."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from pettachainer.benchmarks.context_showcase import (
    CONTEXT_DEMOS,
    run_context_showcase,
    sha256_file,
    sha256_json,
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def expected_demo_map() -> dict[str, dict[str, object]]:
    return {str(demo["name"]): demo for demo in CONTEXT_DEMOS}


def demo_result_map(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(demo["name"]): demo for demo in result.get("demos", [])}


def matching_line(log_text: str, expected: str) -> str:
    return next((line.strip() for line in log_text.splitlines() if expected in line), "")


def demo_summary_hashes(result: dict[str, Any]) -> dict[str, str]:
    return {
        str(demo.get("name")): sha256_json(demo.get("summary_lines", []))
        for demo in result.get("demos", [])
    }


def verify_file_hashes(output_dir: Path, manifest: dict[str, Any]) -> dict[str, bool]:
    hashes: dict[str, str] = dict(manifest.get("files", {}))
    return {
        filename: (output_dir / filename).exists()
        and sha256_file(output_dir / filename) == expected_hash
        for filename, expected_hash in hashes.items()
    }


def verify_log_terms(
    output_dir: Path,
    manifest: dict[str, Any],
    result: dict[str, Any],
    report: str,
) -> tuple[bool, dict[str, dict[str, object]]]:
    expected_demos = expected_demo_map()
    result_demos = demo_result_map(result)
    details: dict[str, dict[str, object]] = {}
    all_passed = True
    for name, expected_demo in expected_demos.items():
        result_demo = result_demos.get(name, {})
        log_path = output_dir / f"{name}.log"
        log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
        summary_lines = set(result_demo.get("summary_lines", []))
        checks = {str(check["name"]): check for check in result_demo.get("checks", [])}
        terms = dict(expected_demo["expected_terms"])
        demo_details: dict[str, object] = {
            "log_present": log_path.exists(),
            "checks": {},
        }
        for check_name, expected in terms.items():
            line = matching_line(log_text, str(expected))
            result_check = checks.get(str(check_name), {})
            passed = (
                bool(line)
                and bool(result_check.get("passed", False))
                and result_check.get("matched_line") == line
                and line in summary_lines
                and line in report
            )
            demo_details["checks"][str(check_name)] = {
                "expected": expected,
                "matched_line": line,
                "passed": passed,
            }
            all_passed = all_passed and passed
        details[name] = demo_details

    manifest_demos = {str(demo.get("name")) for demo in manifest.get("demos", [])}
    result_demo_names = set(result_demos)
    expected_demo_names = set(expected_demos)
    shape_ok = manifest_demos == expected_demo_names and result_demo_names == expected_demo_names
    return all_passed and shape_ok, {
        "expected_demo_names": sorted(expected_demo_names),
        "manifest_demo_names": sorted(manifest_demos),
        "result_demo_names": sorted(result_demo_names),
        "shape_ok": shape_ok,
        "demos": details,
    }


def verify_summary_hashes(
    manifest: dict[str, Any],
    result: dict[str, Any],
) -> tuple[bool, dict[str, object]]:
    expected = dict(manifest.get("demo_summary_sha256", {}))
    actual = demo_summary_hashes(result)
    expected_names = set(expected_demo_map())
    return expected == actual and set(expected) == expected_names, {
        "expected": expected,
        "actual": actual,
        "shape_ok": set(expected) == expected_names,
    }


def replay_summary_details(
    result: dict[str, Any],
    replayed_result: Any,
) -> tuple[bool, dict[str, object]]:
    saved_demos = demo_result_map(result)
    replayed_demos = {demo.name: demo for demo in replayed_result.demos}
    details: dict[str, object] = {}
    all_passed = result.get("checks", {}) == replayed_result.checks
    for name in sorted(expected_demo_map()):
        saved_demo = saved_demos.get(name, {})
        replayed_demo = replayed_demos.get(name)
        saved_lines = list(saved_demo.get("summary_lines", []))
        replayed_lines = list(replayed_demo.summary_lines) if replayed_demo else []
        saved_hash = sha256_json(saved_lines)
        replayed_hash = sha256_json(replayed_lines)
        passed = saved_lines == replayed_lines and saved_hash == replayed_hash
        details[name] = {
            "summary_lines_match": passed,
            "saved_summary_sha256": saved_hash,
            "replayed_summary_sha256": replayed_hash,
            "saved_summary_lines": saved_lines,
            "replayed_summary_lines": replayed_lines,
        }
        all_passed = all_passed and passed
    return all_passed, {
        "checks_match": result.get("checks", {}) == replayed_result.checks,
        "demos": details,
    }


def verify_context_showcase_artifacts(
    output_dir: Path,
    *,
    replay: bool = False,
    timeout_s: int = 30,
) -> dict[str, Any]:
    manifest_path = output_dir / "context-showcase-manifest.json"
    result_path = output_dir / "context-showcase-result.json"
    report_path = output_dir / "context-showcase-report.md"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    result = load_json(result_path) if result_path.exists() else {}
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""

    hash_checks = verify_file_hashes(output_dir, manifest) if manifest else {}
    logs_ok, log_details = verify_log_terms(output_dir, manifest, result, report)
    summaries_ok, summary_details = verify_summary_hashes(manifest, result)
    manifest_checks = dict(manifest.get("checks", {}))
    result_checks = dict(result.get("checks", {}))

    replay_result: dict[str, Any] = {
        "enabled": replay,
        "passed": True,
        "matches_recorded_summary": True,
    }
    if replay:
        with tempfile.TemporaryDirectory() as tmpdir:
            replayed = run_context_showcase(output_dir=Path(tmpdir), timeout_s=timeout_s)
            replay_matches_summary, replay_details = replay_summary_details(result, replayed)
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
            == "pettachainer_generated_context_showcase_manifest"
        ),
        "manifest_version_matches": manifest.get("manifest_version") == 2,
        "file_hashes_match": bool(hash_checks) and all(hash_checks.values()),
        "result_checks_pass": bool(result_checks) and all(result_checks.values()),
        "manifest_checks_match_result": manifest_checks == result_checks,
        "manifest_summary_hashes_match": summaries_ok,
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

    result = verify_context_showcase_artifacts(
        args.output_dir,
        replay=args.replay,
        timeout_s=args.timeout_s,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
