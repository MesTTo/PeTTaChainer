"""Score synthetic evidence packets through the MeTTa context-generation heads.

Replaces the Python context_generation prototype for the showcase sweeps. A
packet is (statement, positive, negative, features, provenance) where features
is a set of "key:value" strings. Each "key:value" maps to a (key value) MeTTa
atom; a guard is one such atom or a ContextAnd-nest of them. The MeTTa model has
no "forbidden" set, so a routed context is just the guard's required atoms.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from pettachainer.pettachainer import PeTTaChainer


# ---- "key:value" string <-> MeTTa atom, both directions ----

def feature_to_atom(feature: str) -> str:
    key, value = feature.split(":", 1)
    return f"({key} {value})"


def atom_to_feature(atom: str) -> str:
    """(type Penguin) -> 'type:Penguin'. Input is one (key value) atom."""
    inner = atom.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1].strip()
    key, _, value = inner.partition(" ")
    return f"{key}:{value.strip()}"


def features_to_metta(features: Iterable[str]) -> str:
    return "(" + " ".join(feature_to_atom(f) for f in sorted(features)) + ")"


def packet_to_metta(statement: str, positive: float, negative: float,
                    features: Iterable[str], provenance: str) -> str:
    return (
        f"(EvidencePacket {statement} (EC {float(positive)} {float(negative)}) "
        f"{features_to_metta(features)} {provenance})"
    )


# ---- guard atom string -> sorted tuple of "key:value" (handles ContextAnd nests and none) ----

def _split_top_level(body: str) -> list[str]:
    """Split a space-separated atom body at top-level parens only."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == " " and depth == 0:
            if cur:
                parts.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def guard_to_features(guard: str) -> tuple[str, ...]:
    """'(type Penguin)' -> ('type:Penguin',);
       '(ContextAnd (type Bird) (type Penguin))' -> ('type:Bird','type:Penguin');
       'none' -> ()."""
    guard = guard.strip()
    if guard in ("none", "()", ""):
        return ()
    if guard.startswith("(ContextAnd "):
        body = guard[len("(ContextAnd "):-1]  # strip '(ContextAnd ' and trailing ')'
        left, right = _split_top_level(body)
        return tuple(sorted((*guard_to_features(left), *guard_to_features(right))))
    return (atom_to_feature(guard),)


# ---- result of scoring one packet set against one query-feature set ----

@dataclass(frozen=True)
class ContextEval:
    best_guard: tuple[str, ...]
    best_score: float
    runner_up_guard: tuple[str, ...]
    runner_up_score: float
    side: str
    strength: float

    @property
    def ranking_margin(self) -> float:
        return self.best_score - self.runner_up_score

    @property
    def routed_required(self) -> tuple[str, ...]:
        return self.best_guard

    @property
    def routed_forbidden(self) -> tuple[str, ...]:
        return ()  # MeTTa model has no forbidden set


def _first_atom(handler: PeTTaChainer, expr: str) -> str:
    raw = handler.handler.process_metta_string(expr)
    items = [raw] if isinstance(raw, str) else list(raw)
    for item in items:
        text = str(item).strip()
        if text and text != "()":
            return text
    raise RuntimeError(f"no MeTTa result for: {expr}\n  got: {items!r}")


def _parse_generated_context(text: str) -> tuple[str, str, float]:
    """(GeneratedContext stmt <guard> <side> (EC p n) (STV s c) <score>) -> (guard, side, strength)."""
    inner = text[len("(GeneratedContext "):-1]
    parts = _split_top_level(inner)
    # parts: [stmt, guard, side, (EC p n), (STV s c), score]
    guard = parts[1]
    side = parts[2]
    stv = parts[4]                       # "(STV s c)"
    strength = float(_split_top_level(stv[1:-1])[1])  # s
    return guard, side, strength


def _parse_ranked_pair(text: str) -> tuple[str, float, str, float]:
    """(RankedPair (ScoredGuard <g> <s>) (ScoredGuard <g> <s>)) -> (bg, bs, rg, rs)."""
    inner = text[len("(RankedPair "):-1]
    best, runner = _split_top_level(inner)

    def unpack(sg: str) -> tuple[str, float]:
        body = sg[len("(ScoredGuard "):-1]
        bits = _split_top_level(body)
        return bits[0], float(bits[-1])

    bg, bs = unpack(best)
    rg, rs = unpack(runner)
    return bg, bs, rg, rs


def evaluate_context(
    handler: PeTTaChainer,
    packets: Sequence[tuple[str, float, float, Iterable[str], str]],
    query_features: Iterable[str],
    *,
    statement: str = "(Fly Tweety)",
) -> ContextEval:
    """Score packets against query_features through the MeTTa heads."""
    pm = "(" + " ".join(packet_to_metta(*p) for p in packets) + ")"
    qm = features_to_metta(query_features)

    gc = _first_atom(handler, f"!(GeneratedContextForQuery {statement} {pm} {qm})")
    guard, side, strength = _parse_generated_context(gc)

    pair = _first_atom(handler, f"!(GeneratedContextTop2Guards {pm} {qm})")
    best_g, best_s, run_g, run_s = _parse_ranked_pair(pair)

    return ContextEval(
        best_guard=guard_to_features(best_g),
        best_score=best_s,
        runner_up_guard=guard_to_features(run_g),
        runner_up_score=run_s,
        side=side,
        strength=strength,
    )
