#!/usr/bin/env python3
"""Run the complementary-evidence merge showcase through PeTTa."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from pettachainer.benchmarks.context_showcase import (
    METTA_DIR,
    petta_env,
    resolve_petta,
    sha256_file,
    sha256_json,
    strip_ansi,
)


@dataclass(frozen=True)
class ComplementaryEvidenceCheck:
    name: str
    passed: bool
    expected: str
    matched_line: str


@dataclass(frozen=True)
class ComplementaryEvidenceResult:
    runtime_s: float
    output_dir: str
    metta_file: str
    log_path: str
    summary_lines: list[str]
    summary_sha256: str
    checks: dict[str, bool]
    check_details: list[ComplementaryEvidenceCheck]
    result_path: str
    report_path: str
    manifest_path: str


COMPLEMENTARY_EVIDENCE_DEMO = {
    "name": "additive-complement-merge",
    "metta_file": "benchmarks/demo_additive_complement_merge.metta",
    "expected_terms": {
        "additive_merge_operator": "merge/additive-complement",
        "negated_branch_preserved": "(rule-proof neg-branch (negated d))",
        "positive_branch_preserved": "(rule-proof pos-branch d)",
        "merged_truth_value": "(STV 0.5 0.5)",
        "complement_detector": "true",
    },
}


def candidate_output_lines(cleaned_output: str) -> list[str]:
    return [
        line.strip()
        for line in cleaned_output.splitlines()
        if line.strip()
        and (
            line.strip().startswith("(")
            or line.strip() in {"true", "false"}
        )
        and not line.strip().startswith("(=")
    ]


def last_matching_line(lines: list[str], expected: str) -> str:
    return next((line for line in reversed(lines) if expected in line), "")


def run_complementary_evidence_showcase(
    *,
    output_dir: Path,
    timeout_s: int = 30,
) -> ComplementaryEvidenceResult:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    petta = resolve_petta()
    metta_file = str(COMPLEMENTARY_EVIDENCE_DEMO["metta_file"])
    completed = subprocess.run(
        [str(petta), metta_file],
        cwd=METTA_DIR,
        env=petta_env(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_s,
        check=False,
    )
    runtime_s = time.perf_counter() - started
    cleaned_output = strip_ansi(completed.stdout)
    log_path = output_dir / "additive-complement-merge.log"
    log_path.write_text(cleaned_output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"{metta_file} exited {completed.returncode}; see {log_path}")

    candidates = candidate_output_lines(cleaned_output)
    check_details: list[ComplementaryEvidenceCheck] = []
    for check_name, expected in dict(COMPLEMENTARY_EVIDENCE_DEMO["expected_terms"]).items():
        matched = last_matching_line(candidates, str(expected))
        check_details.append(
            ComplementaryEvidenceCheck(
                name=str(check_name),
                passed=bool(matched),
                expected=str(expected),
                matched_line=matched,
            )
        )
    summary_lines = list(
        dict.fromkeys(check.matched_line for check in check_details if check.matched_line)
    )
    checks = {check.name: check.passed for check in check_details}
    result = ComplementaryEvidenceResult(
        runtime_s=runtime_s,
        output_dir=str(output_dir),
        metta_file=metta_file,
        log_path=str(log_path),
        summary_lines=summary_lines,
        summary_sha256=sha256_json(summary_lines),
        checks=checks,
        check_details=check_details,
        result_path=str(output_dir / "complementary-evidence-result.json"),
        report_path=str(output_dir / "complementary-evidence-report.md"),
        manifest_path=str(output_dir / "complementary-evidence-manifest.json"),
    )
    Path(result.result_path).write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(result.report_path).write_text(markdown_report(result), encoding="utf-8")
    manifest_files = {
        Path(result.result_path).name: sha256_file(Path(result.result_path)),
        Path(result.report_path).name: sha256_file(Path(result.report_path)),
        Path(result.log_path).name: sha256_file(Path(result.log_path)),
    }
    Path(result.manifest_path).write_text(
        json.dumps(
            {
                "artifact_kind": "pettachainer_complementary_evidence_manifest",
                "manifest_version": 1,
                "demo": COMPLEMENTARY_EVIDENCE_DEMO,
                "summary_sha256": result.summary_sha256,
                "files": manifest_files,
                "checks": checks,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if not all(checks.values()):
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise AssertionError(f"complementary evidence checks failed: {failed}")
    return result


def markdown_report(result: ComplementaryEvidenceResult) -> str:
    lines = [
        "# Complementary Evidence Showcase",
        "",
        f"Runtime: `{result.runtime_s:.3f}s`",
        f"Verdict: `{'PASS' if all(result.checks.values()) else 'FAIL'}`",
        "",
        "## Checks",
        "",
    ]
    for check in result.check_details:
        lines.append(f"- `{check.name}`: `{check.passed}`")
        lines.append(f"  - expected substring: `{check.expected}`")
        if check.matched_line:
            lines.append(f"  - matched: `{check.matched_line}`")
    lines.extend(["", "## Summary", "", "```text", *result.summary_lines, "```", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/pettachainer-complementary-evidence"),
    )
    parser.add_argument("--timeout-s", type=int, default=30)
    args = parser.parse_args(argv)

    result = run_complementary_evidence_showcase(
        output_dir=args.output_dir,
        timeout_s=args.timeout_s,
    )
    print(f"Report: {result.report_path}")
    print(f"JSON: {result.result_path}")
    print(f"Verdict: {'PASS' if all(result.checks.values()) else 'FAIL'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
