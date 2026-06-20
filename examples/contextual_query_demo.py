#!/usr/bin/env python3
"""Use PeTTaChainer.contextual_query directly: the penguin exception.

contextual_query runs an ordinary query and, alongside the rule-based proofs,
returns a generated-context projection. The context is derived from the stored
evidence by the MeTTa heads (no Python parsing); here it isolates the penguin
exception and projects a low strength for "tweety flies".

Run it with the SWI runtime (see AGENTS.md), from the repo root:

    SWIPL_HOME=/path/to/swipl \\
    PATH="$SWIPL_HOME/bin:$PATH" \\
    LD_LIBRARY_PATH="$SWIPL_HOME/lib/swipl/lib/x86_64-linux:${LD_LIBRARY_PATH:-}" \\
    LD_PRELOAD=../PeTTa/mork_ffi/target/release/libmork_ffi.so \\
    .venv/bin/python examples/contextual_query_demo.py
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pettachainer import PeTTaChainer


def main() -> None:
    handler = PeTTaChainer()

    # Birds fly (an implication), but the penguin evidence says polly does not.
    handler.add_atoms_no_check(
        [
            "(: bird_robin (Bird robin) (STV 1.0 0.99))",
            "(: bird_polly (Bird polly) (STV 1.0 0.99))",
            "(: bird_tweety (Bird tweety) (STV 1.0 0.99))",
            "(: penguin_polly (Penguin polly) (STV 1.0 0.99))",
            "(: penguin_tweety (Penguin tweety) (STV 1.0 0.99))",
            "(: fly_robin (Fly robin) (STV 0.95 0.99))",
            "(: fly_polly (Fly polly) (STV 0.0 0.99))",
            "(: bird_to_fly (Implication (Premises (Bird $x)) (Conclusions (Fly $x))) (STV 0.95 0.99))",
        ]
    )

    # Does tweety fly? The bird_to_fly rule says yes; the generated context flags
    # tweety as a penguin and projects a low strength.
    result = handler.contextual_query("(: $prf (Fly tweety) $tv)", steps=20, timeout_sec=0)

    print("Query: (Fly tweety)\n")

    print("Rule-based proofs (from bird_to_fly):")
    for proof in result.proofs:
        print(f"  {proof}")
    if not result.proofs:
        print("  (none)")
    print()

    print("Generated-context projection (the MeTTa-derived exception):")
    print(f"  {result.projection}")
    print()

    print("answers[0] is the context projection, then the proofs follow:")
    print(f"  {result.answers[0]}")


if __name__ == "__main__":
    main()
