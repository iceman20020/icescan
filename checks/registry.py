from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from icescan.checks.base import BaseCheck
from icescan import checks as checks_pkg


def _iter_check_modules():
    root = Path(checks_pkg.__file__).parent
    for path in root.rglob("*.py"):
        if path.name in ("__init__.py", "base.py", "registry.py"):
            continue
        rel = path.relative_to(root).with_suffix("")
        parts = list(rel.parts)
        mod = "icescan.checks." + ".".join(parts)
        yield mod


def discover_checks() -> list[type[BaseCheck]]:
    found: list[type[BaseCheck]] = []
    seen: set[str] = set()

    for mod_name in _iter_check_modules():
        try:
            mod = importlib.import_module(mod_name)
        except Exception:
            continue
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseCheck)
                and attr is not BaseCheck
                and attr.__module__ == mod_name
            ):
                if attr.name in seen:
                    continue
                seen.add(attr.name)
                found.append(attr)
    return found


def load_checks(cfg) -> list[BaseCheck]:
    classes = discover_checks()
    include = set(cfg.tests or ["all"])
    exclude = set(cfg.exclude or [])

    instances: list[BaseCheck] = []
    for cls in classes:
        try:
            inst = cls()
        except Exception:
            continue
        if inst.level > cfg.level:
            continue
        if "all" not in include:
            if inst.category not in include and inst.name not in include:
                continue
        if inst.category in exclude or inst.name in exclude:
            continue
        instances.append(inst)

    instances.sort(key=lambda c: (c.level, c.category, c.name))
    return instances
