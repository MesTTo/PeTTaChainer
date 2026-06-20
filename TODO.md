# TODO

## Prepare PeTTaChainer as an installable library — done

The chainer is now an installable Python package. `pip install ./PeTTaChainer`
builds a wheel that bundles the MeTTa runtime and runs end to end. Verified by
installing the wheel into a clean venv and running a query plus `contextual_query`
from a neutral directory (so it can only use the bundled data).

- [x] Bundle the MeTTa runtime as package data. `MANIFEST.in` plus
  `include-package-data` ship `pettachainer/metta/**` (runtime modules, logic
  configs, the piPLN demos), the Prolog beam `.pl`, and the LLM specs. The
  installed package runs without the source tree.
- [x] Handle the petta dependency. petta is declared as a dependency and sourced
  from the sibling checkout for dev. The README documents that petta is not on
  PyPI and is installed from its repository first.
- [x] Decouple from workstation paths. No shipped module hardcodes a local path,
  the petta import raises a clear error when the runtime is missing, and the
  README documents the SWI-Prolog 9.3.x / janus / `LD_PRELOAD` requirements.
- [x] Pin the public API. `pettachainer/__init__.py` exports `PeTTaChainer`,
  `get_language_spec`, `check_query`, `check_stmt`, and `ContextualQueryResult`
  through a lazy loader, so `import pettachainer` needs no runtime.
- [x] Separate dev code from the wheel. `pettachainer.benchmarks` is excluded from
  the installed packages, and `metta/tests`, `metta/benchmarks`, `metta/linter`,
  and the profiling hook are pruned from the data.
- [x] Metadata: authors, keywords, classifiers, and project URLs are filled in.
- [x] Build and verify. `uv build` produces a wheel and an sdist; the wheel
  installs and runs in a clean venv.

The repository is MIT-licensed (`LICENSE`). It is a fork of upstream PeTTaChainer,
which carries no license of its own, so the MIT terms cover this fork's work.

Open: PyPI distribution is blocked because petta is not publishable as-is (it has a
native `mork_ffi` build).

## Organize the repository — done

- [x] Documented the project layout in the README (package, bundled MeTTa
  runtime, demos, dev tooling, examples, tests).
- [x] Removed leaked local `/home/user` paths from shipped and public files.
- [x] Kept `profile_petta.sh` at the repo root, since it resolves `../PeTTa` and
  `pettachainer/metta` from there, and kept the paper PDF at the root (it is
  already in upstream).
- [x] Reorganized `pettachainer/metta/`: the flat module pile is now
  `petta_chainer.metta` at the top plus `chainer/` (engine) and `context/` (the
  πPLN layer), all imports qualified relative to the metta root. Removed the dead
  `m.metta` scratch and the redundant in-folder profile scripts. Layout documented
  in `pettachainer/metta/README.md`. Verified by the full MeTTa suite, the demos,
  and a clean-venv wheel install.
