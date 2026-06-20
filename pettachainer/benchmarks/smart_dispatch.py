#!/usr/bin/env python3
"""Benchmark PeTTa Smart Dispatch against forced dynamic/interpreter dispatch."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from petta import PeTTa


VARIANTS = ("smart", "call", "reduce", "eval")


@dataclass
class DispatchTiming:
    name: str
    output: list[str]
    runs_s: list[float]
    median_s: float
    ratio_to_smart: float
    codegen_marker: str


@dataclass
class DispatchBenchmarkResult:
    iterations: int
    repeats: int
    trace_path: str
    timings: list[DispatchTiming]
    checks: dict[str, bool]


@contextmanager
def redirect_process_output(path: Path):
    """Redirect Python and SWI-Prolog stdout/stderr at file-descriptor level."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)
        try:
            os.dup2(handle.fileno(), 1)
            os.dup2(handle.fileno(), 2)
            yield
        finally:
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            os.close(saved_stdout)
            os.close(saved_stderr)


def definition_source(prefix: str, variant: str) -> str:
    function = f"{prefix}_{variant}"
    worker = f"{function}_tr"
    if variant == "smart":
        recursive_call = f"({worker} (- $n 1) (+ $a 1))"
    elif variant == "call":
        recursive_call = f"(call ({worker} (- $n 1) (+ $a 1)))"
    elif variant == "reduce":
        recursive_call = f"(reduce ({worker} (- $n 1) (+ $a 1)))"
    elif variant == "eval":
        recursive_call = f"(eval ({worker} (- $n 1) (+ $a 1)))"
    else:
        raise ValueError(f"Unknown dispatch variant: {variant}")
    return f"""
(= ({function} $n) ({worker} $n 0))
(= ({worker} $n $a)
   (if (== $n 0)
       $a
       {recursive_call}))
"""


def call_source(prefix: str, variant: str, iterations: int) -> str:
    return f"!({prefix}_{variant} {iterations})\n"


def codegen_marker(prefix: str, variant: str, trace_text: str) -> str:
    worker = f"{prefix}_{variant}_tr"
    if f"reduce([{worker}," in trace_text:
        return "dynamic_reduce"
    if f"eval([{worker}," in trace_text:
        return "runtime_eval"
    if f"{worker}(E, F, C)" in trace_text:
        return "direct_predicate_call"
    return "unknown"


def build_checks(
    timings: list[DispatchTiming],
    *,
    iterations: int,
) -> dict[str, bool]:
    by_name = {timing.name: timing for timing in timings}
    expected_output = [str(iterations)]
    return {
        "all_variants_return_iteration_count": all(
            timing.output == expected_output for timing in timings
        ),
        "smart_codegen_direct": by_name["smart"].codegen_marker == "direct_predicate_call",
        "call_codegen_direct": by_name["call"].codegen_marker == "direct_predicate_call",
        "reduce_codegen_dynamic": by_name["reduce"].codegen_marker == "dynamic_reduce",
        "eval_codegen_runtime_eval": by_name["eval"].codegen_marker == "runtime_eval",
        "smart_beats_forced_reduce": (
            by_name["smart"].median_s < by_name["reduce"].median_s
        ),
        "reduce_beats_forced_eval": by_name["reduce"].median_s < by_name["eval"].median_s,
    }


def run_benchmark(
    *,
    iterations: int = 20_000,
    repeats: int = 3,
    trace_path: Path = Path("/tmp/pettachainer-smart-dispatch.log"),
) -> DispatchBenchmarkResult:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    if repeats <= 0:
        raise ValueError("repeats must be positive")

    prefix = f"sd_{uuid.uuid4().hex[:10]}"
    raw_timings: dict[str, tuple[list[str], list[float]]] = {}

    with redirect_process_output(trace_path):
        handler = PeTTa()
        for variant in VARIANTS:
            handler.process_metta_string(definition_source(prefix, variant))
        for variant in VARIANTS:
            output: list[str] = []
            runs: list[float] = []
            for _run in range(repeats):
                started = time.perf_counter()
                output = [
                    str(item)
                    for item in handler.process_metta_string(
                        call_source(prefix, variant, iterations)
                    )
                ]
                runs.append(time.perf_counter() - started)
            raw_timings[variant] = (output, runs)

    trace_text = trace_path.read_text(encoding="utf-8")
    smart_median = median(raw_timings["smart"][1])
    timings = []
    for variant in VARIANTS:
        output, runs = raw_timings[variant]
        variant_median = median(runs)
        timings.append(
            DispatchTiming(
                name=variant,
                output=output,
                runs_s=runs,
                median_s=variant_median,
                ratio_to_smart=variant_median / smart_median if smart_median else 0.0,
                codegen_marker=codegen_marker(prefix, variant, trace_text),
            )
        )

    return DispatchBenchmarkResult(
        iterations=iterations,
        repeats=repeats,
        trace_path=str(trace_path),
        timings=timings,
        checks=build_checks(timings, iterations=iterations),
    )


def print_text(result: DispatchBenchmarkResult) -> None:
    print("PeTTa Smart Dispatch benchmark")
    print(f"Iterations: {result.iterations}")
    print(f"Repeats: {result.repeats}")
    print()
    print("Timings")
    for timing in result.timings:
        print(
            f"- {timing.name}: median={timing.median_s:.6f}s, "
            f"ratio_to_smart={timing.ratio_to_smart:.2f}x, "
            f"codegen={timing.codegen_marker}, output={timing.output}"
        )
    print()
    print("Checks")
    for name, passed in result.checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"- {status} {name}")
    print()
    print(f"Generated Prolog trace: {result.trace_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20_000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--trace",
        type=Path,
        default=Path("/tmp/pettachainer-smart-dispatch.log"),
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero if a check fails")
    args = parser.parse_args()

    result = run_benchmark(
        iterations=args.iterations,
        repeats=args.repeats,
        trace_path=args.trace,
    )
    if args.json:
        print(json.dumps(asdict(result), indent=2, sort_keys=True))
    else:
        print_text(result)
    return 0 if not args.strict or all(result.checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
