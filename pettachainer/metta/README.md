# PeTTaChainer MeTTa runtime

Layout of this folder:

- `petta_chainer.metta` is the entry point and the import root. The Python package
  loads this file, and it imports everything else. PeTTa resolves
  `import! &self X` against the working directory of the top-level loaded file,
  which is always this folder, so every module is imported relative to here (for
  example `chainer/compile`, `context/context_from_kb`).
- `chainer/` is the chaining engine: `compile`, `logic_config`,
  `chainer_utils`, `backward_chainer`, `backward_proof_store`, `forward_chainer`,
  `compiled_query_runtime`, `dist_formulas`, `tv_formulas`, `proof_structure_audit`.
  `backward_proof_store` groups equivalent subgoal outputs and exposes one merged
  representative to rule continuations and aggregates. User-authored implications
  contribute rule provenance unless their names are registered with `mark-logic-rule`.
  Predicates registered with `set-specializing-predicate` ground structural rule
  templates against matching facts and emit concrete-head rules in either add order.
  `compileadd` records source events per knowledge base. Named removal clears the
  compiled KB and replays the remaining events, which also invalidates derived facts.
  It also emits `merge/lifting` when common fact evidence can be factored out of
  otherwise independent total-MP proof paths.
- `context/` is the πPLN context layer: `context_from_kb`, `context_generation`,
  the pure-MeTTa and Prolog beams, the inference-control modules, and the Prolog
  beam source `context_generation_beam.pl`.
- `logic_configs/` are the selectable logic configs (`pln`, `predicate_logic`).
- `piPLN_paper_explained/` is the runnable, section-by-section πPLN reading guide
  (`paper_translation.metta`) plus the demos.
- `tests/` are the MeTTa tests. Run them with `bash test.sh` from this folder.
- `benchmarks/` and `linter/` are dev tooling (not shipped in the wheel).
