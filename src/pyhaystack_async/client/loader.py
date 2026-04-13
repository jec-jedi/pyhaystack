"""Session loader and factory for pyhaystack-async."""

from __future__ import annotations

from importlib import import_module
from typing import Any

# Short aliases → module.ClassName within this package
IMPLEMENTATION_ALIAS: dict[str, str] = {
    "niagara-ax": "niagara.NiagaraHaystackSession",
    "ax": "niagara.NiagaraHaystackSession",
    "niagara4": "niagara.Niagara4HaystackSession",
    "n4": "niagara.Niagara4HaystackSession",
    "skyspark2": "skyspark.SkysparkHaystackSession",
    "skyspark": "skyspark.SkysparkScramHaystackSession",
    "widesky": "widesky.WideskyHaystackSession",
}

_cache: dict[str, type] = {}


def get_implementation(name: str) -> type:
    """Resolve a session class by short alias or dotted path."""
    name = IMPLEMENTATION_ALIAS.get(name, name)
    if name in _cache:
        return _cache[name]

    parts = name.rsplit(".", 1)
    if len(parts) == 2:
        mod_name, cls_name = parts
    else:
        raise ImportError(f"Cannot resolve implementation: {name}")

    try:
        mod = import_module(f".{mod_name}", package="pyhaystack_async.client")
    except ImportError:
        mod = import_module(mod_name)

    cls = getattr(mod, cls_name, None)
    if cls is None:
        raise ImportError(f"No class {cls_name} in module {mod_name}")

    _cache[name] = cls
    return cls


def connect(implementation: str, *args: Any, **kwargs: Any) -> Any:
    """Create a session instance by name.

    Usage::

        session = connect(
            "skyspark", uri="https://...",
            username="<username>", password="<password>", project="<project>",
        )
    """
    cls = get_implementation(implementation) if isinstance(implementation, str) else implementation
    return cls(*args, **kwargs)
