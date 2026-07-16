#!/usr/bin/env python3
import statistics
import time
from dataclasses import dataclass

if __package__:
    from pettachainer.benchmarks.rule_score_cache import (
        compiled_target_rule_count,
        parse_scaling_benchmark_args,
        write_benchmark_json,
    )
else:
    from rule_score_cache import (
        compiled_target_rule_count,
        parse_scaling_benchmark_args,
        write_benchmark_json,
    )

from pettachainer import PeTTaChainer


@dataclass(frozen=True)
class BenchmarkRow:
    source_rules: int
    compiled_target_rules: int
    queries: int
    repeats: int
    unfiltered_s: float
    filtered_s: float
    speedup: float


def build_sparse_problem(handler: PeTTaChainer, rule_count: int) -> None:
    statements = [
        "(: source_live (ScoreSource source_0) (STV 1.0 0.9))",
        "(: direct_target (ScoreTarget) (STV 1.0 1.0))",
        "(: score_rule_0 "
        "(Implication (Premises (ScoreSource source_0)) (Conclusions (ScoreTarget))) "
        "(STV 1.0 0.2))",
    ]
    statements.extend(
        f"(: (no_inverse score_rule_{index}) "
        f"(Implication (Premises (ScoreSource source_{index})) "
        "(Conclusions (ScoreTarget))) (STV 1.0 1.0))"
        for index in range(1, rule_count)
    )
    handler.add_atoms_no_check(statements)


def time_queries(handler: PeTTaChainer, queries: int, enabled: bool) -> tuple[float, list[set[str]]]:
    handler.set_backward_premise_prefilter(enabled)
    answers: list[set[str]] = []
    start = time.perf_counter()
    for _ in range(queries):
        result = set(handler.query("(: $proof (ScoreTarget) $tv)", steps=1, timeout_sec=0))
        if not result:
            raise RuntimeError("The direct target fact was not returned")
        answers.append(result)
    return time.perf_counter() - start, answers


def benchmark(rule_count: int, queries: int, repeats: int) -> BenchmarkRow:
    compiled_counts: list[int] = []
    unfiltered_runs: list[float] = []
    filtered_runs: list[float] = []
    for repeat in range(repeats):
        handler = PeTTaChainer()
        build_sparse_problem(handler, rule_count)
        compiled_counts.append(compiled_target_rule_count(handler))
        if repeat % 2 == 0:
            unfiltered_s, unfiltered_answers = time_queries(handler, queries, False)
            filtered_s, filtered_answers = time_queries(handler, queries, True)
        else:
            filtered_s, filtered_answers = time_queries(handler, queries, True)
            unfiltered_s, unfiltered_answers = time_queries(handler, queries, False)
        if filtered_answers != unfiltered_answers:
            raise RuntimeError("Filtered and unfiltered answers differ")
        unfiltered_runs.append(unfiltered_s)
        filtered_runs.append(filtered_s)

    if len(set(compiled_counts)) != 1:
        raise RuntimeError(f"Compiled rule count changed between repeats: {compiled_counts}")
    unfiltered_s = statistics.median(unfiltered_runs)
    filtered_s = statistics.median(filtered_runs)
    return BenchmarkRow(
        source_rules=rule_count,
        compiled_target_rules=compiled_counts[0],
        queries=queries,
        repeats=repeats,
        unfiltered_s=unfiltered_s,
        filtered_s=filtered_s,
        speedup=unfiltered_s / filtered_s,
    )


def print_table(rows: list[BenchmarkRow]) -> None:
    print("source_rules\tcompiled_target_rules\tunfiltered_s\tfiltered_s\tspeedup")
    for row in rows:
        print(
            f"{row.source_rules}\t{row.compiled_target_rules}\t{row.unfiltered_s:.6f}\t"
            f"{row.filtered_s:.6f}\t{row.speedup:.3f}"
        )


def main() -> None:
    rule_counts, queries, repeats, json_out = parse_scaling_benchmark_args(
        description=(
            "Compare one-step backward queries with conservative dead-premise filtering off and on. "
            "Only one rule has a source fact; every other rule has a ground dead premise."
        ),
        default_queries=5,
        queries_help="Queries per mode and repeat",
    )

    warmup = PeTTaChainer()
    build_sparse_problem(warmup, 1)
    time_queries(warmup, 1, False)
    time_queries(warmup, 1, True)

    rows = [benchmark(count, queries, repeats) for count in rule_counts]
    print_table(rows)
    write_benchmark_json(rows, json_out)


if __name__ == "__main__":
    main()
