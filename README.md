To install, clone this repo and its dependency into the same directory:

```bash
git clone https://github.com/patham9/PeTTa.git
git clone https://github.com/MesTTo/PeTTaChainer.git
```

That gives you the source checkout the demos and tests run from. To use it as a
library, install petta (it is not on PyPI) and then the chainer, which bundles its
MeTTa runtime:

```bash
pip install ./PeTTa
pip install ./PeTTaChainer
```

The runtime needs SWI-Prolog 9.3.x with `janus-swi`. Point `SWIPL_HOME` at the SWI
install and set `LD_LIBRARY_PATH` (and `LD_PRELOAD` for `libmork_ffi.so` on this
build) for the session. Then `from pettachainer import PeTTaChainer` works, with
the MeTTa runtime loaded from inside the installed package.

## πPLN: paraconsistent reasoning without a global probability space

This fork implements the operational core of πPLN, the paraconsistent PLN of Ben
Goertzel's draft *πPLN: Paraconsistent PLN Without a Global Probability Space*.
The idea: the durable state of a reasoner is not one probability distribution. It
is a context-indexed evidence metagraph. A statement's truth is a pair of evidence
counts `(EC pos neg)`, positive and negative support held separately, so a claim
can carry high support and high opposition at once. Priors live in contexts and
enter only when you project the counts to a PLN truth value. When a query needs
Bayesian coherence, the system builds a local chart, reasons inside it, and
projects the result back to evidence. Gluing local charts into one global model is
something you earn, not something you assume.

The capability this gives a reasoner is one a fixed-rule chainer does not have: it
can find the local context that isolates an exception, then project the answer
under it. Birds and penguins is the textbook case. The rule says birds fly; the
evidence says penguins do not; the system reads the evidence, generates the guard
`(type Penguin)` on its own, routes the query inside it, and projects a low
strength for "tweety flies". It was never told about penguins. It found the split
by reducing evidence conflict.

### Example: the penguin exception

```python
from pettachainer import PeTTaChainer

handler = PeTTaChainer()
handler.add_atoms_no_check([
    "(: bird_robin (Bird robin) (STV 1.0 0.99))",
    "(: bird_polly (Bird polly) (STV 1.0 0.99))",
    "(: bird_tweety (Bird tweety) (STV 1.0 0.99))",
    "(: penguin_polly (Penguin polly) (STV 1.0 0.99))",
    "(: penguin_tweety (Penguin tweety) (STV 1.0 0.99))",
    "(: fly_robin (Fly robin) (STV 0.95 0.99))",
    "(: fly_polly (Fly polly) (STV 0.0 0.99))",
    "(: bird_to_fly (Implication (Premises (Bird $x)) (Conclusions (Fly $x))) (STV 0.95 0.99))",
])

# The bird_to_fly rule alone would conclude tweety flies. The generated context
# notices tweety is a penguin (the evidence says penguins do not fly) and
# projects a low strength instead.
result = handler.contextual_query("(: $prf (Fly tweety) $tv)", timeout_sec=0)
print(result.projection)
# (: (generated-context) (Fly tweety) (STV 0.0095 0.99))
```

The full runnable script, with the SWI runtime setup, is in
[`examples/contextual_query_demo.py`](examples/contextual_query_demo.py).

### How the paper maps to the code

`pettachainer/metta/piPLN_paper_explained/paper_translation.metta` is a runnable,
section-by-section reading of the paper: each formula is a small MeTTa function
with `!(test ...)` examples. The live reasoner realizes the operational core:

| πPLN | where in the code |
| --- | --- |
| §4 p-bits, positive/negative evidence `(EC pos neg)` | `(EC ...)` throughout the chainer; `paper_translation.metta` |
| §8.1 evidence-count quantale (tensor = count addition, join = max) | `context_generation.metta` (`ContextAllEvidence`, `GeneratedContextSplitCounts`) |
| §8.2 / §8.3 projection to PLN STV and beta posterior | `context_generation.metta` (`ContextECToSTV`); `paper_translation.metta` (`ECToSTV`, `ECToBeta`) |
| §7.1 / §9.2 context-indexed evidence packets, the `Kt(φ,C)` query | `context_from_kb.metta` |
| §5.2 / §13.2 weakness-guided selection (the weakest adequate chart) | `context_generation.metta` scorer; pure and Prolog beams in `context_generation_beam*.metta` |
| §11 revision (same-context count addition, additive-complement, overlap dominance) | `chainer_utils.metta` (`mergetvs`, `merge-proof-atoms`), `backward_proof_store.metta` |
| §14 inference control over generated contexts (branch utility, execute/prune) | `context_inference_control*.metta` |
| §16.1 birds and penguins worked example | `metta_idiomatic_demo.metta`, `paper_translation.metta`, `chart_selection_prototype.metta` |

Run the section-by-section reading and the end-to-end showcase from
`pettachainer/metta`:

```bash
petta piPLN_paper_explained/paper_translation.metta
petta piPLN_paper_explained/metta_idiomatic_demo.metta
```

### Scope, stated plainly

The reasoning core is live and tested: the evidence-count substrate, the
projection to PLN truth values, generated local contexts scored by conflict
reduction (the weakest adequate chart), the pure-MeTTa and Prolog beams, the
revision merges, and the inference control are all exercised by the MeTTa tests
under `pettachainer/metta/tests/`.

`paper_translation.metta` covers the rest of the formalism as a runnable reading
guide: the quantale tower (§8.1-8.9), non-gluability (§10.2), the revision rules
(§11), implication and conjunction direct introduction (§12.3-12.4), and a minimal
quantale-valued factor graph with the conflict-diagnostic factor (§15.1, §15.3).
These are small executable cells with tests, not engines.

Two parts of the paper live as those reading-guide cells rather than as chainer
subsystems: the full residuated-weakness revision calculus (§11.8) and a general
quantale-valued factor-graph engine (§15). The chainer implements the specific
revision merges it needs and runs inference control directly.

Background: πPLN builds on Goertzel's *Paraconsistent Foundations for Probabilistic
Reasoning, Programming and Concept Formation* (arXiv:2012.14474) and the PLN book
(Goertzel, Iklé, Goertzel, Heljakka, Springer 2008). It is a riposte to the
global-probability-space νPLN formalization, not a rejection of it: restricted to a
single chart, πPLN's local calculations are exactly the νPLN ones (§10.1).

## Project layout

- `pettachainer/` is the Python package. `pettachainer.py` is the `PeTTaChainer`
  handler, `pln_validator.py` validates PLN forms, and `LANGUAGE_SPEC.md` /
  `LLM_RULE_SPEC.md` are the language specs.
- `pettachainer/metta/` is the MeTTa runtime, bundled into the installed package.
  `petta_chainer.metta` is the entry point and import root; `chainer/` holds the
  engine (`compile`, `chainer_utils`, `backward_chainer`, `forward_chainer`, the
  formulas, and the rest) and `context/` holds the πPLN context layer
  (`context_from_kb`, `context_generation`, the beams, the inference-control
  modules, and the Prolog beam `.pl`). `logic_configs/` has the selectable logic
  configs and `piPLN_paper_explained/` the runnable reading guide and demos. Its
  `tests/`, `benchmarks/`, and `linter/` are dev-only and not shipped. See
  `pettachainer/metta/README.md` for the full layout.
- `pettachainer/benchmarks/` holds the Python benchmark scripts (run from source,
  not shipped in the wheel).
- `examples/` has small runnable examples; `tests/` holds the Python tests.
- `profile_petta.sh` is a dev profiling wrapper, run from the repo root.

## Reasoning Semantics

PeTTaChainer tracks proof evidence sets while merging query results. When two proofs for the same
conclusion use complementary evidence, such as `(fact-ev ... d (Dog))` and
`(not-fact-ev ... d (Dog))`, the merger now emits `merge/additive-complement` and adds the
premise-weighted strengths/confidences instead of treating the branches as independent revision
samples. This models `Dog -> Animal` and `Not Dog -> Animal` as split parts of one total conditional
rather than averaging away support from complementary cases.

## Benchmarks

Run the full showcase:

```bash
.venv/bin/python pettachainer/benchmarks/showcase.py
```

This runs the Smart Dispatch benchmark, generated context-control showcase, complementary-evidence
merge proof, and replayable incident-response proof. It writes a combined Markdown/JSON report,
`showcase-contract.json`, and `showcase-witness.json` under `/tmp/pettachainer-showcase`, and fails if
compiler-level dispatch, context-control, additive complementary merge, structural proof audit, or
proof-level replay checks fail. The witness certificate binds the report, result, contract, generated
context artifacts, complementary-evidence log, bundle hashes, raw proof, structural proof certificate,
and compact proof evidence behind a canonical SHA-256 root. The showcase also runs a forged-bundle
drill that recomputes manifest hashes after removing a proof-critical atom and verifies semantic
replay still rejects the bundle. It also runs a needle-in-haystack sweep, adding extra irrelevant
`Trusts` facts and requiring the isolate proof hash to stay stable with zero noise tokens.

Audit an existing showcase directory without rerunning the full benchmark:

```bash
.venv/bin/python pettachainer/benchmarks/verify_showcase.py /tmp/pettachainer-showcase --strict --red-team
```

The verifier reloads the incident bundle, reruns semantic replay, verifies the witness certificate,
enforces `showcase-contract.json`, prints a claim-coverage ledger, writes
`showcase-forensic-packet.json` plus Markdown, confirms forged bundles are rejected, and replays the
recorded noise sweep levels against the saved proof hash. With `--red-team`,
it copies valid showcase artifacts, corrupts saved noise, tamper, contract, unsupported-claim,
witness proof/root/artifact/claim/dispatch/noise/complementary/tamper/proof-structure evidence,
report, context logs, complementary-evidence logs, bundle structural certificate, and bundle payload
data, then asserts the verifier fails each forged artifact directory.

Verify the forensic packet later without rerunning replay or red-team mutation:

```bash
.venv/bin/python pettachainer/benchmarks/verify_showcase.py /tmp/pettachainer-showcase \
  --verify-forensic-packet /tmp/pettachainer-showcase/showcase-forensic-packet.json --strict
```

Add `--forensic-seal-sweep` to copy the artifact directory, mutate every file bound by the packet,
and require the packet verifier to reject each copy.
Add `--forensic-packet-red-team` to forge packet fields, recompute each packet root, and require
semantic/source-binding checks to reject every forged packet.
Add `--evidence-index-red-team` to mutate the generated JSON/Markdown evidence index and require
the packet verifier to reject both forged indexes.

Run the proof-backed incident-response demo:

```bash
.venv/bin/python pettachainer/benchmarks/impressive_incident_response.py --strict
```

Use `--json` for machine-readable output, `--show-proof` to print the raw nested proof term, or
`--markdown-out /tmp/pettachainer-incident-report.md` to generate a Markdown/Mermaid proof report.
Use `--bundle-out /tmp/pettachainer-incident-bundle` to write the scenario atoms, raw proof,
DOT graph, report, explanation ledger, JSON result, and SHA-256 manifest as an audit bundle.
Then run `--replay-bundle /tmp/pettachainer-incident-bundle` to reload the scenario in a fresh
handler and verify the derived proof hash, query counts, and proof-token audit.
The strict demo proves a six-hop primary compromise path, verifies redundant fallback ingress
when either initial seed is removed, ranks competing ingress explanations by proof confidence,
certifies primary-path minimality with single-atom ablations, rejects distractor edges, and checks
policy counterfactuals.

Run the Smart Dispatch benchmark:

```bash
.venv/bin/python pettachainer/benchmarks/smart_dispatch.py --strict
```

It compares normal Smart Dispatch, forced `call`, forced dynamic `reduce`, and forced runtime
`eval` on the same tail-recursive loop. The report includes generated-Prolog markers so the
speedup is tied to direct predicate calls, not just wall-clock timing.

Run the NatDist vs ParticleDist benchmark:

```bash
python pettachainer/benchmarks/particle_vs_nat.py --sizes 100,500,1000 --particle-budgets 128,256,512 --repeats 2
```

Run the simple forward vs backward chaining benchmark:

```bash
.venv/bin/python pettachainer/benchmarks/forward_vs_backward.py --depths 10,25,50 --noise-branching 8 --repeats 3
```

Run the backward materialization benchmark:

```bash
.venv/bin/python pettachainer/benchmarks/backward_materialize.py --depths 5,10 --queries 200 --repeats 3
```

Run the bounded priority queue benchmark:

```bash
.venv/bin/python pettachainer/benchmarks/bounded_queue.py --fanouts 2000,8000 --steps 100 --repeats 3
```

Add `--compare-pruning` to compare pruning enabled and disabled within the same checkout.

Optional JSON export:

```bash
python pettachainer/benchmarks/particle_vs_nat.py --json-out /tmp/particle_bench.json
```

## Profiling MeTTa Runs

Profile a `.metta` file through the underlying SWI-Prolog invocation that `petta` uses:

```bash
./profile_petta.sh tests/testmining.metta
./profile_petta.sh --mode time tests/testmining.metta
./profile_petta.sh --mode perf benchmarks/demo_benchgen_forward_backward_compare.metta
```

Relative paths are resolved from `pettachainer/metta` by default.

## Python API: Language Spec String

```python
from pettachainer import get_language_spec

llm_spec = get_language_spec(llm_focused=True)
full_spec = get_language_spec(llm_focused=False)
```

## Python API: Shared PLN Validator

```python
from pettachainer import PeTTaChainer, check_query, check_stmt

handler = PeTTaChainer()

stmt_eval = handler.evaluate_statement("(: s1 (Dog fido) (STV 1.0 1.0))")
check_stmt(stmt_eval)

query_eval = handler.evaluate_query("(: $prf (Dog fido) $tv)")
check_query(query_eval)
```

## Python API: Forward Chaining

```python
from pettachainer import PeTTaChainer

handler = PeTTaChainer()
handler.add_atom("(: edge_ab (Edge A B) (STV 1.0 1.0))")
handler.add_atom("(: edge_bc (Edge B C) (STV 1.0 1.0))")
handler.add_atom("(: edge_to_path (Implication (Premises (Edge $x $y)) (Conclusions (Path $x $y))) (STV 1.0 1.0))")
handler.add_atom("(: path_step (Implication (Premises (Path $x $y) (Edge $y $z)) (Conclusions (Path $x $z))) (STV 1.0 1.0))")

handler.forward_chain(steps=50)
result = handler.query("(: $prf (Path A C) $tv)", timeout_sec=0)

handler.forward_chain(steps=1, term="(Edge A B)")
```

## License

MIT, see [LICENSE](LICENSE). PeTTaChainer is a fork of
[rTreutlein/PeTTaChainer](https://github.com/rTreutlein/PeTTaChainer).
