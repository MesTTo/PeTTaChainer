from importlib import import_module

__all__ = [
    "ContextualQueryResult",
    "PeTTaChainer",
    "check_query",
    "check_stmt",
    "get_language_spec",
]


def __getattr__(name):
    if name in {"ContextualQueryResult", "PeTTaChainer", "get_language_spec"}:
        mod = import_module(".pettachainer", __name__)
        return getattr(mod, name)
    if name in {"check_query", "check_stmt"}:
        mod = import_module(".pln_validator", __name__)
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
