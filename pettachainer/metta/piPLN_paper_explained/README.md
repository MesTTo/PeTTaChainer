# piPLN Paper Translation in MeTTa

This folder translates the main formulas from `../../../piPLN_riposte_draft_v6.pdf`
into runnable MeTTa.

The main file is:

- `paper_translation.metta`
- `chart_selection_prototype.metta`
- `generated_contexts_demo.metta`
- `context_inference_control_demo.metta`
- `context_beam_inference_control_demo.metta`
- `context_beam_needle_control_demo.metta`
- `context_adaptive_control_demo.metta`
- `metta_idiomatic_demo.metta`

It is written as commented code:

- comments paraphrase the paper section by section
- MeTTa definitions replace the math formulas
- `!(test ...)` forms give explicit runnable examples

Run it from `pettachainer/metta`:

```bash
petta piPLN_paper_explained/paper_translation.metta
petta piPLN_paper_explained/chart_selection_prototype.metta
petta piPLN_paper_explained/generated_contexts_demo.metta
petta piPLN_paper_explained/context_inference_control_demo.metta
petta piPLN_paper_explained/context_beam_inference_control_demo.metta
petta piPLN_paper_explained/context_beam_needle_control_demo.metta
petta piPLN_paper_explained/context_adaptive_control_demo.metta
petta piPLN_paper_explained/metta_idiomatic_demo.metta
```

`metta_idiomatic_demo.metta` is the end-to-end showcase: it reads evidence off
the knowledge base, generates the textbook penguin exception, then the hard
four-feature failure mode that no single clue reveals (found by the pure-MeTTa
beam), certifies it against weaker guards, projects the answer, proves and audits
the decision by structure, and stress-tests it with a counterfactual. All in
MeTTa, self-checking with `!(test ...)`.

Covered topics:

- persistent context-indexed evidence
- p-bits as positive and negative evidence
- evidence-count quantale
- projection to PLN STVs
- beta-posterior projection
- Bayesian likelihood multiplication as count addition
- bounded p-bit propagation quantale
- evidence order versus truth order
- CD logic quantale
- local event quantale and why probability valuation is local/lax
- product control quantale carrying assumptions, evidence, weakness, cost, and provenance
- bird/penguin local-chart example
- distributional truth values in PeTTaChainer
- contradiction as information (high-and-balanced versus near-ignorance)
- non-gluability of locally consistent charts (the Vorob'ev/Bell obstruction, Theorem 10.2)
- revision as evidence transformation (same-context tensor, overlap discount, beta-binomial)
- implication and conjunction direct introduction by case counting
- the weakest adequate chart and the chainer step-priority projection
- a minimal quantale-valued factor graph and the conflict-diagnostic factor

`chart_selection_prototype.metta` is a smaller companion that focuses only on
runtime derivation of `TaskContext`: it shows candidate contexts, subtype-based
applicability, explicit specificity via `TypeDepth`, adequacy checks, selection,
chart construction, and query projection.

`generated_contexts_demo.metta` is the stronger companion for the open context
generation problem: it does not select among predeclared charts. It derives
atomic, pairwise, and depth-3 context guards from evidence packet features,
scores them by conflict reduction, and returns the selected evidence,
projection, support packet, and score trace. It can also emit a counterfactual
minimality report: each atomic feature in the generated context is removed and
rescored, making the proof explain why the full generated context beat its
ablations. Certified PeTTaChainer result variants carry that minimality
certificate inside the returned proof tree; the Prolog-backed variant also
carries the beam-ranked candidate list. It also demonstrates the optional
Prolog-backed beam scorer exposed back into PeTTa through `lib_import`, matching
the interop pattern in PeTTa's examples/prologimport.metta.
The beam demo includes a depth-4 exception where the pure PeTTa depth-3
enumerator cannot contain the exact guard, while the Prolog-backed search can
return a certified four-feature context.
Following PeTTa's examples/smartdispatch.metta, callable wrapper
names are kept distinct from returned proof-data constructors, so heads such as
`context-certified-generated-proof` and `context-certified-beam-generated-proof`
stay inert data under PeTTa smart dispatch.
Evidence can be supplied directly as packets or collected from a PeTTa atomspace
with `match`/`collapse`, following the local PeTTa examples. For atomspace
queries, the query feature list can also be inferred from the matching
`ContextEvidence` atoms for the statement or from separate
`ContextStatementFeatures` atoms for statements with no direct evidence, so the
caller can ask for a statement without manually supplying a preselected context.
The final result can also be projected into two local conventions: the probabilistic
the trueagi-io/chaining repo convention `(: truth-value proof-tree conclusion)`,
and PeTTaChainer's native query-result convention
`(: proof-tree statement truth-value)`. In both cases, the proof tree records
evidence collection, context generation, scoring, evidence selection, and
projection.

`context_inference_control_demo.metta` connects this to
the trueagi-io/chaining repo (experimental/pln-inf-ctl): instead of treating the
generated context as only an answer explanation, it uses the generated context
as an inference-control estimate for competing delayed branches. Each candidate
branch receives a context report, STV projection, utility score, and ablation
certificate; the controller emits an execute/prune decision list and returns a
PeTTaChainer-style result for the selected branch. The returned proof tree
stores branch reports sorted by utility, so the selected branch is backed by a
ranked audit trail rather than a hidden choice. A compact selection-audit view
also exposes the winner, runner-up, utility margin, and execute/prune decisions,
making it clear why a contradicted default branch was pruned. Branches can be
passed directly or discovered from `ContextControlCandidate`,
`ContextControlEvidence`, and `ContextControlQueryFeatures` atoms in a PeTTa
space, so both the branch set and the per-branch contexts can be generated at
query time. This makes the "context generated on the spot" step operational for
branch selection, not just for final answer projection.

`context_beam_inference_control_demo.metta` pushes the same branch-control
surface through the Prolog-backed beam scorer. The expensive branch report
generation and utility ranking run next to `context_beam_for_query`, while PeTTa
receives a normal proof tree with selected branch, ranked beam reports,
generated context, projected evidence, beam-search audit data, and the same
winner/runner-up margin audit. This keeps the high-level proof interface in
PeTTa while moving the deeper context search to Prolog.

`context_beam_needle_control_demo.metta` is the harder version of that demo. It
constructs near-miss evidence where every single feature and shallow
combination is misleading, then lets the Prolog beam scorer generate the
four-feature guard needed to isolate the exception. PeTTa receives the result as
a normal branch-control proof: selected branch, generated guard, runner-up,
margin, execute/prune decisions, and projected statement.

Modal logic is only a reference point for thinking about local worlds/charts.
The implementation here does not add modal operators or a modal proof calculus:
it generates PeTTa guards from evidence features, projects evidence under those
guards, and uses the projected truth values to control branch selection.

`context_adaptive_control_demo.metta` shows the same control problem changing
inside one PeTTa atomspace. Before exception evidence is added, the generated
context supports the broad default-flight branch. After crosswind/fragile
incident evidence and grounding evidence arrive, the controller regenerates the
local context from the new feature distribution and flips to the grounding
branch. This is the clearest executable answer to how contexts can be generated
on the spot: they are not static chart names, they are evidence-derived guards
recomputed at query time. The demo also emits a selection-shift report that
compares the saved pre-update audit with the post-update audit, exposing the old
winner, new winner, old guard, new guard, and updated utility margin.

This is not a full piPLN implementation. It is an executable reading guide where
the paper's formulas are represented as small MeTTa functions and tests.
