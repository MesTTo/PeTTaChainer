#!/usr/bin/env python3
import argparse
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pettachainer import PeTTaChainer  # noqa: E402


@dataclass(frozen=True)
class BenchmarkRow:
    source_rules: int
    compiled_target_rules: int
    queries: int
    repeats: int
    load_s: float
    first_query_s: float
    tail_queries_s: float
    all_queries_s: float
    load_plus_queries_s: float


def build_problem(handler: PeTTaChainer, rule_count: int) -> None:
    facts = [
        f"(: source_{i} (ScoreSource source_{i}) (STV 1.0 0.9))"
        for i in range(rule_count)
    ]
    facts.append("(: direct_target (ScoreTarget) (STV 1.0 1.0))")
    rules = [
        f"(: score_rule_{i} "
        f"(Implication (Premises (ScoreSource source_{i})) (Conclusions (ScoreTarget))) "
        f"(STV 1.0 {0.99 if i == 0 else 0.2 + (i % 5) * 0.04}))"
        for i in range(rule_count)
    ]
    handler.add_atoms_no_check(facts + rules)


def compiled_target_rule_count(handler: PeTTaChainer) -> int:
    result = handler.handler.process_metta_string(
        "!(length (collapse (match rules "
        f"($_id ((ScoreTarget) ({handler.kb} $_ctx $_vars) $_proof $_tv) $_args) $_id)))"
    )
    values = result if isinstance(result, list) else [result]
    if len(values) != 1:
        raise RuntimeError(f"Could not count compiled target rules: {result}")
    return int(str(values[0]).strip())


def run_once(rule_count: int, queries: int) -> tuple[int, float, float, float]:
    handler = PeTTaChainer()
    load_start = time.perf_counter()
    build_problem(handler, rule_count)
    load_s = time.perf_counter() - load_start
    compiled_rules = compiled_target_rule_count(handler)

    query_times: list[float] = []
    for _ in range(queries):
        query_start = time.perf_counter()
        answers = handler.query("(: $proof (ScoreTarget) $tv)", steps=1, timeout_sec=0)
        query_times.append(time.perf_counter() - query_start)
        if not answers:
            raise RuntimeError("The direct target fact was not returned")

    return compiled_rules, load_s, query_times[0], sum(query_times[1:])


def benchmark(rule_count: int, queries: int, repeats: int) -> BenchmarkRow:
    compiled_counts: list[int] = []
    load_runs: list[float] = []
    first_runs: list[float] = []
    tail_runs: list[float] = []
    for _ in range(repeats):
        compiled_rules, load_s, first_s, tail_s = run_once(rule_count, queries)
        compiled_counts.append(compiled_rules)
        load_runs.append(load_s)
        first_runs.append(first_s)
        tail_runs.append(tail_s)

    if len(set(compiled_counts)) != 1:
        raise RuntimeError(f"Compiled rule count changed between repeats: {compiled_counts}")

    load_s = statistics.median(load_runs)
    first_s = statistics.median(first_runs)
    tail_s = statistics.median(tail_runs)
    all_queries_s = first_s + tail_s
    return BenchmarkRow(
        source_rules=rule_count,
        compiled_target_rules=compiled_counts[0],
        queries=queries,
        repeats=repeats,
        load_s=load_s,
        first_query_s=first_s,
        tail_queries_s=tail_s,
        all_queries_s=all_queries_s,
        load_plus_queries_s=load_s + all_queries_s,
    )


def print_table(rows: list[BenchmarkRow]) -> None:
    print(
        "source_rules\tcompiled_target_rules\tload_s\tfirst_query_s\t"
        "tail_queries_s\tall_queries_s\tload_plus_queries_s"
    )
    for row in rows:
        print(
            f"{row.source_rules}\t{row.compiled_target_rules}\t{row.load_s:.6f}\t"
            f"{row.first_query_s:.6f}\t{row.tail_queries_s:.6f}\t"
            f"{row.all_queries_s:.6f}\t{row.load_plus_queries_s:.6f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Measure repeated one-step queries that must score every rule sharing a conclusion. "
            "A direct fact answers the query, so proof traversal does not dominate the result."
        )
    )
    parser.add_argument("--rules", default="40,80,160,320", help="Comma-separated source rule counts")
    parser.add_argument("--queries", type=int, default=3, help="Queries per loaded knowledge base")
    parser.add_argument("--repeats", type=int, default=3, help="Loaded knowledge bases per rule count")
    parser.add_argument("--json-out", default="", help="Optional JSON output path")
    args = parser.parse_args()

    rule_counts = [int(item.strip()) for item in args.rules.split(",") if item.strip()]
    if not rule_counts or any(count < 1 for count in rule_counts):
        raise ValueError("--rules must contain positive integers")
    if args.queries < 1:
        raise ValueError("--queries must be at least 1")
    if args.repeats < 1:
        raise ValueError("--repeats must be at least 1")

    warmup = PeTTaChainer()
    build_problem(warmup, 1)
    if not warmup.query("(: $proof (ScoreTarget) $tv)", steps=1, timeout_sec=0):
        raise RuntimeError("Warmup query returned no proof")

    rows = [benchmark(count, args.queries, args.repeats) for count in rule_counts]
    print_table(rows)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([asdict(row) for row in rows], indent=2) + "\n",
            encoding="ascii",
        )


if __name__ == "__main__":
    main()
