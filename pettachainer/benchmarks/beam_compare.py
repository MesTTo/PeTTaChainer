#!/usr/bin/env python3
"""Compare the Prolog context beam against the pure-MeTTa beam head-to-head.

This runs both beams on the same fixtures, checks they pick the same guard, and
reports wall-clock time for each. The two beams under test are:

  - context_beam_for_query/6        (Prolog,  context_generation_beam.pl)
  - ContextBeamForQueryMeTTa        (MeTTa,   context_generation_beam_metta.metta)

Both return the same ContextBeamAnswer shape, so we pull the selected guard out of
each with the BeamAnswerGuard projector and compare the two guard atoms directly.

Run it:

    python -m pettachainer.benchmarks.beam_compare
    python -m pettachainer.benchmarks.beam_compare --repeats 5 --strict

With --strict the process exits nonzero if any fixture's two beams disagree.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from petta import PeTTa

from pettachainer.pettachainer import PeTTaChainer

METTA_DIR = REPO_ROOT / "pettachainer" / "metta"

# The three atoms loaded into the handler: both beams plus a guard projector.
_BEAM_BOOTSTRAP = (
    "!(import! &self context_generation_beam)",
    "!(import! &self context_generation_beam_metta)",
    "(= (BeamAnswerGuard (ContextBeamAnswer $_s $guard $_side $_e $_p $_su $_t $_b)) $guard)",
)


def _point_imports_at_metta_dir() -> None:
    """Point PeTTa's import resolution at the metta dir.

    In-process (janus) PeTTa resolves .metta imports against its working_dir
    fact and the Prolog "./context_generation_beam.pl" path against SWI's
    working_directory; both default to the PeTTa repo, so the pettachainer beam
    files are not found. Set both to the metta dir.
    """
    import janus_swi as janus

    md = str(METTA_DIR)
    janus.query_once("retractall(working_dir(_))")
    janus.query_once(f"assertz(working_dir('{md}'))")
    janus.query_once(f"working_directory(_, '{md}')")


@dataclass(frozen=True)
class BeamFixture:
    """One scenario: a statement, its packets, query features, and search bounds."""

    name: str
    statement: str
    packets: str
    query_features: str
    max_depth: int
    beam_width: int


@dataclass
class BeamTiming:
    """Wall-clock for one beam over `repeats` runs of one fixture."""

    backend: str  # "prolog" or "metta"
    guard: str
    runs_s: list[float]
    median_s: float


@dataclass
class FixtureComparison:
    name: str
    prolog: BeamTiming
    metta: BeamTiming
    guards_match: bool
    speedup_metta_over_prolog: float


@dataclass
class BeamCompareResult:
    repeats: int
    trace_path: str
    comparisons: list[FixtureComparison]
    all_guards_match: bool


@contextmanager
def redirect_process_output(path: Path):
    """Redirect Python and SWI-Prolog stdout/stderr at the file-descriptor level.

    PeTTa prints its compilation trace on stdout, so we send it to a file to keep
    the benchmark output readable. Same trick smart_dispatch.py uses.
    """
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


def beam_triple_fixture() -> BeamFixture:
    """The simple depth-3 case from test_context_generation_beam.metta."""
    packets = (
        "((EvidencePacket (Fly micro-crosswind-normal) (EC 300.0 0.0) "
        "((type MicroDrone) (weather crosswind) (payload normal)) micro-crosswind-normal-flight) "
        "(EvidencePacket (Fly micro-calm-fragile) (EC 300.0 0.0) "
        "((type MicroDrone) (weather calm) (payload fragile)) micro-calm-fragile-flight) "
        "(EvidencePacket (Fly heavy-crosswind-fragile) (EC 300.0 0.0) "
        "((type HeavyDrone) (weather crosswind) (payload fragile)) heavy-crosswind-fragile-flight) "
        "(EvidencePacket (Fly heavy-calm-normal) (EC 300.0 0.0) "
        "((type HeavyDrone) (weather calm) (payload normal)) heavy-calm-normal-flight) "
        "(EvidencePacket (Fly micro-crosswind-fragile) (EC 0.0 300.0) "
        "((type MicroDrone) (weather crosswind) (payload fragile)) micro-crosswind-fragile-incident))"
    )
    return BeamFixture(
        name="triple-depth-3",
        statement="(Fly micro-crosswind-fragile)",
        packets=packets,
        query_features="((type MicroDrone) (weather crosswind) (payload fragile))",
        max_depth=3,
        beam_width=5,
    )


def beam_quad_needle_fixture() -> BeamFixture:
    """The depth-4 needle case from test_context_generation_beam.metta.

    Four of five packets are clean and share the query features pairwise, so only
    the full four-feature conjunction isolates the single conflicting incident.
    """
    packets = (
        "((EvidencePacket (Fly quad-micro-crosswind-fragile-ground) (EC 300.0 0.0) "
        "((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-ground)) "
        "quad-micro-crosswind-fragile-ground-flight) "
        "(EvidencePacket (Fly quad-micro-crosswind-normal-rooftop) (EC 300.0 0.0) "
        "((type QuadMicroDrone) (weather quad-crosswind) (payload quad-normal) (habitat quad-rooftop)) "
        "quad-micro-crosswind-normal-rooftop-flight) "
        "(EvidencePacket (Fly quad-micro-calm-fragile-rooftop) (EC 300.0 0.0) "
        "((type QuadMicroDrone) (weather quad-calm) (payload quad-fragile) (habitat quad-rooftop)) "
        "quad-micro-calm-fragile-rooftop-flight) "
        "(EvidencePacket (Fly quad-heavy-crosswind-fragile-rooftop) (EC 300.0 0.0) "
        "((type QuadHeavyDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop)) "
        "quad-heavy-crosswind-fragile-rooftop-flight) "
        "(EvidencePacket (Fly quad-micro-crosswind-fragile-rooftop) (EC 0.0 300.0) "
        "((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop)) "
        "quad-micro-crosswind-fragile-rooftop-incident))"
    )
    return BeamFixture(
        name="quad-depth-4-needle",
        statement="(Fly quad-micro-crosswind-fragile-rooftop)",
        packets=packets,
        query_features=(
            "((type QuadMicroDrone) (weather quad-crosswind) "
            "(payload quad-fragile) (habitat quad-rooftop))"
        ),
        max_depth=4,
        beam_width=5,
    )


def _first_result(raw) -> str:
    """PeTTa returns a list of result atoms; take the single guard atom as text."""
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        text = str(item).strip()
        if text and text != "()":
            return text
    raise RuntimeError(f"beam returned no guard (got {raw!r})")


def _guard_call(backend: str, fixture: BeamFixture) -> str:
    head = "context_beam_for_query" if backend == "prolog" else "ContextBeamForQueryMeTTa"
    return (
        f"!(BeamAnswerGuard ({head} "
        f"{fixture.statement} {fixture.packets} {fixture.query_features} "
        f"{fixture.max_depth} {fixture.beam_width}))"
    )


def _time_beam(handler: PeTTa, backend: str, fixture: BeamFixture, repeats: int) -> BeamTiming:
    call = _guard_call(backend, fixture)
    guard = ""
    runs: list[float] = []
    for _run in range(repeats):
        started = time.perf_counter()
        raw = handler.process_metta_string(call)
        runs.append(time.perf_counter() - started)
        guard = _first_result(raw)
    return BeamTiming(
        backend=backend,
        guard=guard,
        runs_s=runs,
        median_s=median(runs),
    )


def run_benchmark(
    *,
    repeats: int = 3,
    fixtures: list[BeamFixture] | None = None,
    trace_path: Path = Path("/tmp/pettachainer-beam-compare.log"),
) -> BeamCompareResult:
    if repeats <= 0:
        raise ValueError("repeats must be positive")
    fixtures = fixtures or [beam_triple_fixture(), beam_quad_needle_fixture()]

    comparisons: list[FixtureComparison] = []
    with redirect_process_output(trace_path):
        # PeTTaChainer loads the library (incl. context_generation, which the
        # MeTTa beam scores with); then both beam files load into its handler.
        handler = PeTTaChainer().handler
        _point_imports_at_metta_dir()
        for atom in _BEAM_BOOTSTRAP:
            handler.process_metta_string(atom)
        for fixture in fixtures:
            prolog = _time_beam(handler, "prolog", fixture, repeats)
            metta = _time_beam(handler, "metta", fixture, repeats)
            speedup = prolog.median_s / metta.median_s if metta.median_s else 0.0
            comparisons.append(
                FixtureComparison(
                    name=fixture.name,
                    prolog=prolog,
                    metta=metta,
                    guards_match=prolog.guard == metta.guard,
                    speedup_metta_over_prolog=speedup,
                )
            )

    return BeamCompareResult(
        repeats=repeats,
        trace_path=str(trace_path),
        comparisons=comparisons,
        all_guards_match=all(c.guards_match for c in comparisons),
    )


def print_text(result: BeamCompareResult) -> None:
    print("PeTTaChainer beam comparison: Prolog vs pure MeTTa")
    print(f"Repeats: {result.repeats}")
    print()
    for comparison in result.comparisons:
        status = "MATCH" if comparison.guards_match else "MISMATCH"
        print(f"[{status}] {comparison.name}")
        print(f"  prolog: median={comparison.prolog.median_s:.6f}s")
        print(f"  metta:  median={comparison.metta.median_s:.6f}s")
        print(
            f"  prolog/metta wall-clock ratio: "
            f"{comparison.speedup_metta_over_prolog:.2f}x"
        )
        print(f"  prolog guard: {comparison.prolog.guard}")
        print(f"  metta  guard: {comparison.metta.guard}")
        print()
    overall = "PASS" if result.all_guards_match else "FAIL"
    print(f"Guard agreement across all fixtures: {overall}")
    print(f"Generated Prolog trace: {result.trace_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--trace",
        type=Path,
        default=Path("/tmp/pettachainer-beam-compare.log"),
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit nonzero if any fixture's two beams pick different guards",
    )
    args = parser.parse_args()

    result = run_benchmark(repeats=args.repeats, trace_path=args.trace)
    if args.json:
        print(json.dumps(asdict(result), indent=2, sort_keys=True))
    else:
        print_text(result)
    return 0 if not args.strict or result.all_guards_match else 1


if __name__ == "__main__":
    raise SystemExit(main())
