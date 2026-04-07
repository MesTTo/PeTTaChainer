from importlib import import_module

__all__ = ["PeTTaChainer", "get_language_spec", "check_stmt", "check_query"]


def __getattr__(name):
    if name in {"PeTTaChainer", "get_language_spec"}:
        mod = import_module(".pettachainer", __name__)
        return getattr(mod, name)
    if name in {"check_query", "check_stmt"}:
        mod = import_module(".pln_validator", __name__)
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
