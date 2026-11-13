"""Automatic source-adapter discovery, independent of dashboard and Teams."""
from __future__ import annotations

from importlib import import_module
from pkgutil import iter_modules

from . import adapters


def discover_sources() -> dict[str, object]:
    result = {}
    for entry in sorted(iter_modules(adapters.__path__), key=lambda x: x.name):
        if entry.name.startswith("_"):
            continue
        module = import_module(f"{adapters.__name__}.{entry.name}")
        name = getattr(module, "SOURCE_ID", "")
        collect = getattr(module, "collect", None)
        if not name or not isinstance(name, str) or not callable(collect):
            raise ValueError(f"Source adapter {entry.name} requires SOURCE_ID and collect()")
        if name in result:
            raise ValueError(f"Duplicate security source: {name}")
        result[name] = collect
    return result
