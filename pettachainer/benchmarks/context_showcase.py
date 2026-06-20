#!/usr/bin/env python3
"""Run and verify the generated-context PeTTa showcase demos."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
METTA_DIR = REPO_ROOT / "pettachainer" / "metta"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True)
class DemoCheck:
    name: str
    passed: bool
    expected: str
    matched_line: str


@dataclass(frozen=True)
class DemoRun:
    name: str
    metta_file: str
    runtime_s: float
    log_path: str
    summary_lines: list[str]
    summary_sha256: str
    checks: list[DemoCheck]


@dataclass(frozen=True)
class ContextShowcaseResult:
    runtime_s: float
    output_dir: str
    demos: list[DemoRun]
    checks: dict[str, bool]
    result_path: str
    report_path: str
    manifest_path: str


CONTEXT_DEMOS: tuple[dict[str, object], ...] = (
    {
        "name": "adaptive-control",
        "metta_file": "piPLN_paper_explained/context_adaptive_control_demo.metta",
        "expected_terms": {
            "before_default_flight": "(before-winner adaptive-default-flight)",
            "shift_to_grounding": (
                "(adaptive-shift (ContextControlSelectionShiftSummary "
                "adaptive-default-flight adaptive-grounding"
            ),
            "after_grounding": "(after-proof-branch adaptive-grounding)",
        },
    },
    {
        "name": "beam-needle-control",
        "metta_file": "piPLN_paper_explained/context_beam_needle_control_demo.metta",
        "expected_terms": {
            "selected_grounding": "(selected-branch beam-needle-grounding)",
            "depth4_guard": (
                "(selected-guard (ContextAnd (type NeedleMicroDrone) "
                "(ContextAnd (weather needle-crosswind)"
            ),
            "default_pruned": (
                "(ContextBranchDecision prune beam-needle-default-flight "
                "(try-needle-default-flight))"
            ),
            "selected_statement": (
                "(selected-statement "
                "(Ground needle-micro-crosswind-fragile-rooftop))"
            ),
        },
    },
)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_text(path.read_text(encoding="utf-8"))


def sha256_json(payload: object) -> str:
    return sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def resolve_petta() -> Path:
    candidates = [
        shutil.which("petta"),
        str(REPO_ROOT / ".venv" / "bin" / "petta"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return Path(candidate)
    raise FileNotFoundError("petta binary not found on PATH or in .venv/bin")


def petta_env() -> dict[str, str]:
    env = os.environ.copy()
    venv_bin = REPO_ROOT / ".venv" / "bin"
    # The SWI runtime is taken from the environment (see the README runtime notes).
    # SWIPL_HOME points at the SWI install; MORK_FFI (or an inherited LD_PRELOAD)
    # supplies the mork preload. Each is applied only when it resolves on disk.
    swipl_root = Path(os.environ.get("SWIPL_HOME", ""))
    swipl_bin = swipl_root / "bin"
    swipl_exe = swipl_bin / "swipl"
    swipl_lib = swipl_root / "lib" / "swipl" / "lib" / "x86_64-linux"
    mork_ffi = Path(os.environ.get("MORK_FFI", ""))

    path_parts = [str(venv_bin), str(swipl_bin), env.get("PATH", "")]
    env["PATH"] = os.pathsep.join(part for part in path_parts if part)
    if swipl_exe.exists():
        env["PETTA_SWIPL"] = str(swipl_exe)
    if swipl_lib.exists():
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            part for part in (str(swipl_lib), env.get("LD_LIBRARY_PATH", "")) if part
        )
    if mork_ffi.exists():
        env["LD_PRELOAD"] = str(mork_ffi)
    return env


def run_petta_demo(
    *,
    name: str,
    metta_file: str,
    expected_terms: dict[str, str],
    output_dir: Path,
    timeout_s: int,
) -> DemoRun:
    petta = resolve_petta()
    started = time.perf_counter()
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
    log_path = output_dir / f"{name}.log"
    log_path.write_text(cleaned_output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"{metta_file} exited {completed.returncode}; see {log_path}")

    candidate_lines = [
        line.strip()
        for line in cleaned_output.splitlines()
        if line.startswith("(")
        and not line.startswith("(=")
        and not line.startswith("(Context")
    ]
    checks = []
    for check_name, expected in expected_terms.items():
        matched = next((line for line in candidate_lines if expected in line), "")
        checks.append(
            DemoCheck(
                name=check_name,
                passed=bool(matched),
                expected=expected,
                matched_line=matched,
            )
        )
    lines = list(dict.fromkeys(check.matched_line for check in checks if check.matched_line))

    return DemoRun(
        name=name,
        metta_file=metta_file,
        runtime_s=runtime_s,
        log_path=str(log_path),
        summary_lines=lines,
        summary_sha256=sha256_json(lines),
        checks=checks,
    )


def markdown_report(result: ContextShowcaseResult) -> str:
    lines = [
        "# Generated Context Showcase",
        "",
        f"Runtime: `{result.runtime_s:.3f}s`",
        f"Verdict: `{'PASS' if all(result.checks.values()) else 'FAIL'}`",
        "",
        "## Checks",
        "",
    ]
    for name, passed in result.checks.items():
        lines.append(f"- `{name}`: `{passed}`")
    for demo in result.demos:
        lines.extend(["", f"## {demo.name}", "", f"Runtime: `{demo.runtime_s:.3f}s`", ""])
        for check in demo.checks:
            lines.append(f"- `{check.name}`: `{check.passed}`")
            lines.append(f"  - expected substring: `{check.expected}`")
            if check.matched_line:
                lines.append(f"  - matched: `{check.matched_line}`")
        lines.extend(["", "```text", *demo.summary_lines, "```"])
    lines.append("")
    return "\n".join(lines)


def run_context_showcase(
    *,
    output_dir: Path,
    timeout_s: int = 30,
) -> ContextShowcaseResult:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    demos = [
        run_petta_demo(
            name=str(demo["name"]),
            metta_file=str(demo["metta_file"]),
            expected_terms=dict(demo["expected_terms"]),
            output_dir=output_dir,
            timeout_s=timeout_s,
        )
        for demo in CONTEXT_DEMOS
    ]
    checks = {
        f"{demo.name}:{check.name}": check.passed
        for demo in demos
        for check in demo.checks
    }
    result = ContextShowcaseResult(
        runtime_s=time.perf_counter() - started,
        output_dir=str(output_dir),
        demos=demos,
        checks=checks,
        result_path=str(output_dir / "context-showcase-result.json"),
        report_path=str(output_dir / "context-showcase-report.md"),
        manifest_path=str(output_dir / "context-showcase-manifest.json"),
    )
    Path(result.result_path).write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(result.report_path).write_text(markdown_report(result), encoding="utf-8")
    manifest_files = {
        Path(result.result_path).name: sha256_file(Path(result.result_path)),
        Path(result.report_path).name: sha256_file(Path(result.report_path)),
    }
    for demo in demos:
        manifest_files[Path(demo.log_path).name] = sha256_file(Path(demo.log_path))
    Path(result.manifest_path).write_text(
        json.dumps(
            {
                "artifact_kind": "pettachainer_generated_context_showcase_manifest",
                "manifest_version": 2,
                "demos": list(CONTEXT_DEMOS),
                "demo_summary_sha256": {
                    demo.name: demo.summary_sha256 for demo in demos
                },
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
        raise AssertionError(f"context showcase checks failed: {failed}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "context-showcase",
    )
    parser.add_argument("--timeout-s", type=int, default=30)
    args = parser.parse_args(argv)

    result = run_context_showcase(output_dir=args.output_dir, timeout_s=args.timeout_s)
    print(f"Report: {result.report_path}")
    print(f"JSON: {result.result_path}")
    print(f"Verdict: {'PASS' if all(result.checks.values()) else 'FAIL'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
