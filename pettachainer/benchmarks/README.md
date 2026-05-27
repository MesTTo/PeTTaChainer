# Benchmark Notes

`particle_vs_nat.py` benchmarks direct distribution folding and threshold probability evaluation.

`forward_vs_backward.py` benchmarks a simple unary implication chain with optional distractor branches.
It reports:

- `backward_s`: query-only backward chaining time for the target
- `forward_goal_s`: forward chaining time with just enough steps to derive the target chain
- `forward_full_s`: forward chaining time with enough steps to drain all reachable derived facts

This is useful when forward chaining feels unexpectedly slow, because it separates:

- the cost of reaching the goal facts
- the cost of materializing unrelated reachable facts that backward search never touches

It compares:

- `NatDist`: exact fold via `NatDistAddBernoulliFromSTV`
- `ParticleDist`: approximate fold via `ParticleAddBernoulliFromSTV`

Both modes evaluate:

```metta
(DistGreaterThanFormula (fold-flat ... ) threshold)
```

## Run

```bash
python pettachainer/benchmarks/particle_vs_nat.py --sizes 100,500,1000 --particle-budgets 128,256,512 --repeats 2
```

```bash
.venv/bin/python pettachainer/benchmarks/forward_vs_backward.py --depths 10,25,50 --noise-branching 8 --repeats 3
```

## Output Columns

- `n`: number of Bernoulli updates folded into the distribution
- `budget`: particle budget (`ParticleSetBudget`) used for the particle run
- `nat_eval_s`: mean NatDist evaluation time
- `particle_eval_s`: mean ParticleDist evaluation time
- `speedup_nat_over_particle`: `nat_eval_s / particle_eval_s` (>1 means particle is faster)
- `nat_strength`: exact threshold probability
- `particle_strength`: approximated threshold probability
- `abs_err`: absolute difference between strengths
- `nat_conf`: NatDist confidence (currently 1.0)
- `particle_conf`: particle confidence from `N_eff / (N_eff + 20)`
- `particle_atoms`: number of stored particle atoms after evaluation

For `forward_vs_backward.py`:

- `depth`: length of the goal chain
- `noise_branching`: extra non-goal rules fired from each goal fact
- `rules`: total rules loaded into the KB
- `reachable_facts`: total facts reachable from the seed if forward chaining drains the agenda
- `backward_s`: mean backward query time
- `forward_goal_s`: mean forward time to derive the goal chain
- `forward_full_s`: mean forward time to drain all reachable work
- `goal_over_backward`: `forward_goal_s / backward_s`
- `full_over_backward`: `forward_full_s / backward_s`

## Bounded Queue Pruning

`bounded_queue.py` stresses priority agenda growth in both the backward and forward chainer paths.
It separates setup time from measured run time so the cost of compiling thousands of generated rules
does not hide the queue behavior.

Run the same command on two commits to compare the bounded queue implementation against the previous
unbounded heap behavior:

```bash
.venv/bin/python pettachainer/benchmarks/bounded_queue.py --fanouts 2000,8000 --steps 100 --repeats 3
```

Or compare pruning enabled and disabled within the same checkout:

```bash
.venv/bin/python pettachainer/benchmarks/bounded_queue.py --fanouts 2000,8000 --steps 100 --repeats 3 --compare-pruning
```

To test many goals that each have a small fanout below the pruning factor:

```bash
.venv/bin/python pettachainer/benchmarks/bounded_queue.py --mode forward_many_small --fanouts 32 --seeds 100 --steps 100 --repeats 3 --compare-pruning
```

The backward counterpart expands a chain of hub goals where each hub has only `fanout` dead-end
alternatives plus one link to the next hub:

```bash
.venv/bin/python pettachainer/benchmarks/bounded_queue.py --mode backward_many_small --fanouts 32 --seeds 100 --steps 100 --repeats 3 --compare-pruning
```

Output columns:

- `pruning`: whether bounded agenda pruning was enabled
- `mode`: backward query agenda, forward chaining agenda, or a many-small-fanout variant
- `fanout`: number of generated rules/facts that can accumulate in the agenda
- `seeds`: number of independent seed goals for `forward_many_small`
- `steps`: search or forward steps per run
- `setup_s`: mean KB construction time
- `run_s`: mean measured query/forward time
- `agenda_size`: saved forward agenda size after `forward-chain`; backward search does not persist its agenda
- `result_count`: number of backward query results

## Metta Tuffy Deep Variant

Run the deep-proof-tree tunable benchmark variant in-place:

```bash
python pettachainer/metta/benchmarks/bench_tuffy_scale.py --pairs 4,8 --runs 2 --variant deep-proof-tree --deep-depth 4 --deep-branching 2
```

## MeTTa Forward/Backward Compare

Run the fully MeTTa benchmark that uses `benchgen_metta` and reports three modes:

- `forward`
- `forward_then_backward`
- `backward`

```bash
cd pettachainer/metta
petta benchmarks/demo_benchgen_forward_backward_compare.metta
```
