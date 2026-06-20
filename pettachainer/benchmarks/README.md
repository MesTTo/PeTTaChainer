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

`smart_dispatch.py` benchmarks PeTTa's Smart Dispatch code generation against forced `call`,
`reduce`, and `eval` modes on the same tail-recursive loop. It captures the generated Prolog trace
and reports whether recursion compiled to a direct predicate call, dynamic `reduce`, or runtime
`eval`.

`beam_compare.py` runs the Prolog context beam (`context_beam_for_query`, from
`context_generation_beam.pl`) head to head against the pure-MeTTa beam (`ContextBeamForQueryMeTTa`,
from `context_generation_beam_metta.metta`) on the same fixtures, checks they pick the same guard,
and reports wall-clock for each. Both beams select the same guard on the depth-3 and depth-4-needle
cases; the Prolog beam runs about 3x faster, so the pure-MeTTa beam is the dependency-free
alternative rather than the default. Run it with:

```bash
.venv/bin/python -m pettachainer.benchmarks.beam_compare --strict
```

`backward_materialize.py` benchmarks the fact-materializing backward chainer.
In its default `same-target` mode, the plain run answers the same deep target repeatedly with normal
backward queries. The materialized run answers it once with `query-materialize`, which stores the
proof tree facts, then answers the remaining repetitions with a low step budget.

It also has `--mode sibling-targets`, which builds several related targets that all depend on the
same deepest chain fact. That mode measures reuse of a materialized intermediate fact rather than
reuse of the exact materialized target.

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

```bash
.venv/bin/python pettachainer/benchmarks/smart_dispatch.py --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.context_showcase --output-dir artifacts/context-showcase
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_context_showcase artifacts/context-showcase --replay
```

```bash
.venv/bin/python -m pettachainer.benchmarks.complementary_evidence --output-dir artifacts/complementary-evidence
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_complementary_evidence artifacts/complementary-evidence --replay
```

```bash
.venv/bin/python -m pettachainer.benchmarks.showcase --output-dir artifacts/showcase
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --forensic-packet-red-team --evidence-index-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-artifact-inclusion showcase-report.md --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-claim generated_context_inference_control --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-all-claims --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-claim-certificate artifacts/showcase/showcase-claim-certificate.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-claim-certificate artifacts/showcase/showcase-claim-certificate.json --claim-certificate-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --audit-verdict --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --audit-verdict --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --audit-verdict-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --audit-verdict-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --audit-verdict --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --audit-verdict-red-team --audit-proof-graph --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --audit-proof-graph-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --audit-verdict --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --audit-verdict-red-team --audit-proof-graph --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --audit-proof-graph-red-team --audit-capsule --verify-audit-capsule artifacts/showcase/showcase-audit-capsule.json --audit-capsule-red-team --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --audit-verdict --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --audit-verdict-red-team --audit-proof-graph --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --audit-proof-graph-red-team --audit-capsule --verify-audit-capsule artifacts/showcase/showcase-audit-capsule.json --audit-capsule-red-team --audit-capsule-archive --verify-audit-capsule-archive artifacts/showcase/showcase-audit-capsule.zip --audit-capsule-archive-red-team --audit-challenge-transcript --verify-audit-challenge-transcript artifacts/showcase/showcase-audit-challenge-transcript.json --audit-decision --verify-audit-decision artifacts/showcase/showcase-audit-decision.json --audit-board --verify-audit-board artifacts/showcase/showcase-audit-board.json --audit-facts --verify-audit-facts artifacts/showcase/showcase-audit-facts.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --verify-audit-capsule artifacts/showcase/showcase-audit-capsule.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-verdict artifacts/showcase/showcase-audit-verdict.json --verify-audit-proof-graph artifacts/showcase/showcase-audit-proof-graph.json --verify-audit-capsule artifacts/showcase/showcase-audit-capsule.json --verify-audit-capsule-archive artifacts/showcase/showcase-audit-capsule.zip --verify-audit-decision artifacts/showcase/showcase-audit-decision.json --strict
```

```bash
python artifacts/showcase/showcase-standalone-verifier.py artifacts/showcase
```

```bash
python artifacts/showcase/showcase-standalone-archive-verifier.py artifacts/showcase/showcase-audit-capsule.zip
```

```bash
python artifacts/showcase/showcase-audit-decision-verifier.py artifacts/showcase
```

```bash
python artifacts/showcase/showcase-audit-gauntlet.py artifacts/showcase
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-challenge-transcript artifacts/showcase/showcase-audit-challenge-transcript.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-board artifacts/showcase/showcase-audit-board.json --strict
```

```bash
.venv/bin/python -m pettachainer.benchmarks.verify_showcase artifacts/showcase --verify-forensic-packet artifacts/showcase/showcase-forensic-packet.json --verify-audit-facts artifacts/showcase/showcase-audit-facts.json --strict
```

```bash
../PeTTa/run.sh artifacts/showcase/showcase-audit-facts.metta
```

```bash
python artifacts/showcase/showcase-verify-all.py artifacts/showcase
```

```bash
cd artifacts/showcase && sha256sum -c showcase-checksums.sha256
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_audit_transparency_log; raise SystemExit(0 if verify_audit_transparency_log('artifacts/showcase')['checks']['transparency_log_verified'] else 1)"
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_audit_dashboard; raise SystemExit(0 if verify_audit_dashboard('artifacts/showcase')['checks']['audit_dashboard_verified'] else 1)"
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_audit_policy; raise SystemExit(0 if verify_audit_policy('artifacts/showcase')['checks']['audit_policy_verified'] else 1)"
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_runtime_manifest; raise SystemExit(0 if verify_runtime_manifest('artifacts/showcase')['checks']['runtime_manifest_verified'] else 1)"
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_audit_receipt; raise SystemExit(0 if verify_audit_receipt('artifacts/showcase')['checks']['audit_receipt_verified'] else 1)"
```

```bash
.venv/bin/python -c "from pettachainer.benchmarks.verify_showcase import verify_audit_provenance_attestation; raise SystemExit(0 if verify_audit_provenance_attestation('artifacts/showcase')['checks']['provenance_attestation_verified'] else 1)"
```

```bash
dot -Tsvg artifacts/showcase/showcase-audit-proof-graph.dot > artifacts/showcase/showcase-audit-proof-graph.svg
```

```bash
.venv/bin/python -m unittest tests.test_forensic_packet -v
```

```bash
.venv/bin/python pettachainer/benchmarks/backward_materialize.py --depths 5,10 --queries 200 --repeats 3
```

```bash
.venv/bin/python pettachainer/benchmarks/backward_materialize.py --mode sibling-targets --depths 5 --queries 20 --repeats 3
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

For `smart_dispatch.py`:

- `median_s`: median wall-clock time for repeated top-level calls
- `ratio_to_smart`: variant median divided by the Smart Dispatch median
- `codegen`: generated-Prolog category, such as direct predicate call, dynamic reduce, or runtime eval

For `context_showcase.py`:

- runs the adaptive PeTTa generated-context control demo and the depth-4 beam needle demo
- writes `context-showcase-result.json`, `context-showcase-report.md`, `context-showcase-manifest.json`, and raw demo logs
- fails unless the extracted PeTTa audit terms show default flight flipping to grounding, the depth-4 generated guard, default pruning, and the selected grounded statement
- records per-demo summary hashes for the extracted PeTTa audit lines

For `verify_context_showcase.py`:

- verifies the showcase manifest and artifact hashes
- rechecks the raw PeTTa logs against the expected audit terms instead of trusting only JSON booleans
- verifies the manifest summary hashes against the result JSON
- optionally replays the two PeTTa demos with `--replay` and requires the extracted audit lines to match the recorded summaries exactly

For `complementary_evidence.py` and `verify_complementary_evidence.py`:

- runs `benchmarks/demo_additive_complement_merge.metta` through PeTTa
- requires the runtime output to contain `merge/additive-complement`, both positive and negated proof branches, `(STV 0.5 0.5)`, and a `true` complementary-evidence detector result
- writes `complementary-evidence-result.json`, `complementary-evidence-report.md`, `complementary-evidence-manifest.json`, and `additive-complement-merge.log`
- the verifier checks hashes, raw log terms, summary hashes, report content, and optional replay against the recorded summary

For `showcase.py` and `verify_showcase.py`:

- runs Smart Dispatch timing, generated-context PeTTa demos, complementary-evidence proof, the incident-response proof, semantic tamper drills, and noise stability in one audited command
- writes a full report, JSON result, acceptance contract, and witness certificate
- the witness binds the generated-context logs, complementary-evidence log, and manifests alongside the incident proof bundle
- includes a generated-context noise sweep proving irrelevant context packets do not change the exception guard or routed context
- records the runner-up generated guard and score margin, so the verifier can reject ambiguous or forged context rankings
- includes counterfactual context cases showing that removing, inverting, or weakening the decisive exception evidence changes the generated context behavior in the expected direction
- the verifier enforces generated-context and complementary-evidence artifact checks, replays both demo families and the context-noise sweep by default, and red-team rejects forged context and complementary logs
- the verifier emits a claim-to-evidence ledger that maps each acceptance claim to concrete JSON artifact fields and passing checks
- the packet verifier can check a single acceptance claim by resolving every claim evidence link back into the source JSON artifact
- the packet verifier can sweep every acceptance claim and report whether each evidence source is sealed by the artifact Merkle tree or a packet source-hash root
- the all-claims sweep also writes `showcase-claim-certificate.json` and `.md`, a compact auditor-facing certificate listing each claim, its source anchors, JSON pointers, source hashes, and certificate hash
- the claim certificate verifier recomputes the certificate from the packet and source artifacts, then red-teams forged counts, source anchors, hashes, and Markdown drift
- the audit verdict mode runs the packet verifier, packet red-team, evidence-index red-team, claim sweep, claim-certificate verifier, and claim-certificate red-team in one command, then writes `showcase-audit-verdict.json` and `.md` with a compact PASS/FAIL attestation hash
- the audit verdict verifier recomputes the verdict from the forensic packet, red-team artifacts, claim sweep, and claim certificate, checks the Markdown and component hashes, then red-teams recomputed-hash verdict forgeries and Markdown drift
- the audit proof graph writes `showcase-audit-proof-graph.json`, `.md`, and `.dot`, a deterministic graph from verdict to packet, claim certificate, claims, evidence links, sealed source hashes, and component hashes; the verifier recomputes all three and red-teams hash, claim-node, evidence-seal, claim-edge, Markdown, and DOT forgeries
- the audit capsule writes `showcase-audit-capsule.json`, `.md`, `showcase-audit-dashboard.html`, `showcase-audit-policy.json`, `showcase-runtime-manifest.json`, `showcase-audit-receipt.json`, `showcase-provenance.intoto.json`, `showcase-checksums.sha256`, `showcase-transparency-log.jsonl`, `showcase-transparency-log.md`, `showcase-standalone-verifier.py`, `showcase-standalone-archive-verifier.py`, and `showcase-verify-all.py`, a handoff manifest over the top-level audit artifacts with file hashes, byte counts, required role bindings, verifier commands, a deterministic HTML audit dashboard, a machine-checkable audit policy declaring required roles/checks/red-team cases, a runtime manifest binding Python/platform/executable/source/generated-tool hashes, a Merkle audit receipt with per-file inclusion proofs, a deterministic in-toto/SLSA-style provenance attestation, a standard `sha256sum -c` checksum manifest, a hash-chained transparency ledger, pure-stdlib verifiers for offline directory and ZIP checks, and a single-command portable verifier; the verifier rejects capsule hash, file hash, role omission, command, artifact drift, dashboard drift, audit-policy drift, runtime-manifest drift, audit-receipt drift, provenance-attestation drift, checksum-manifest drift, transparency-log drift, one-command verifier drift, and Markdown forgeries
- the audit capsule archive writes deterministic `showcase-audit-capsule.zip` with fixed ZIP timestamps and modes, packages both standalone verifiers, the one-command verifier, the dashboard, checksum manifest, and transparency ledger, then verifies archive entries against the capsule manifest and rejects entry drift, entry omission, extra-entry, duplicate-entry, and metadata forgeries
- the audit challenge transcript writes `showcase-audit-challenge-transcript.json` and `.md`, a deterministic challenge log distilled from capsule and archive red-team result files; it records required cases, observed cases, expected failed checks, actual failed checks, rejected counts, source result hashes, and the gauntlet/verifier hashes, then verifies the JSON and Markdown against current red-team evidence
- the external audit decision certificate writes `showcase-audit-decision.json`, pure-stdlib `showcase-audit-decision-verifier.py`, and `showcase-audit-gauntlet.py` after the sealed capsule/archive, hashes the capsule, Markdown, ZIP, policy, runtime manifest, audit receipt, provenance attestation, both red-team result files, the challenge transcript, the decision verifier, and the gauntlet itself, then recomputes the full verdict during verification so the certificate cannot silently bless stale or forged sealed artifacts; the gauntlet runs baseline portable verifiers and forged-copy rejection drills for decision JSON, decision verifier, capsule, and archive tampering
- the audit board writes `showcase-audit-board.json` and `.md`, a compact board-level control matrix over the decision certificate, challenge transcript, sealed capsule, archive, runtime/provenance/receipt handles, portable verifier hashes, red-team coverage, transparency root, and handoff commands; board verification recomputes the board and Markdown from current artifacts
- the PeTTa audit facts export writes `showcase-audit-facts.json` and `showcase-audit-facts.metta`, a signed symbolic view of the board/decision/transcript hashes, rejected-case counts, control statuses, and self-tests; the JSON verifier recomputes the facts from the current board, and `../PeTTa/run.sh artifacts/showcase/showcase-audit-facts.metta` executes the exported facts through PeTTa
- the forensic packet writer also emits `showcase-evidence-index.json` and `.md`, a deterministic human-facing index derived from the packet; packet verification fails if the index is edited or drifts from the packet
- the forensic packet exposes aggregate SHA-256 roots for the artifact set, claim ledger, context evidence, complementary evidence, incident summary, proof structure, and red-team result, giving auditors compact handles for each evidence family
- the packet also includes a deterministic artifact Merkle tree with per-artifact inclusion proofs, a single-artifact inclusion verifier, and packet red-team forges Merkle roots/proofs to confirm the verifier rejects them
- the forensic packet verifier now cross-checks packet semantic fields against the source verifier result, witness, proof-structure certificate, and red-team result, so a packet with a recomputed root hash is still rejected if it lies about context evidence, complementary evidence, claim evidence, proof structure, or red-team cases

For `backward_materialize.py`:

- `mode`: `same-target` or `sibling-targets`
- `depth`: length of the shared implication chain
- `queries`: number of queries answered in the batch
- `rules`: total implication rules loaded into the KB
- `query_steps`: step budget used for the plain queries and first materializing query
- `cached_steps`: step budget used after materialization
- `plain_batch_s`: mean time to answer all targets with normal backward queries
- `materialize_first_s`: mean time for the first `query-materialize`
- `materialized_tail_s`: mean time for the remaining normal queries after materialization
- `materialized_batch_s`: `materialize_first_s + materialized_tail_s`
- `total_speedup`: `plain_batch_s / materialized_batch_s`
- `tail_speedup`: estimated non-materialized tail cost divided by `materialized_tail_s`

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
