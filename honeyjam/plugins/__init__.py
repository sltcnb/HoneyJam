"""HoneyJam plugin framework: base class + auto-discovery."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Optional

from honeyjam.models import PluginResult
from honeyjam.parser.hive import Hive


class Plugin:
    """Base class for all HoneyJam plugins.

    Subclasses set ``name``, ``description`` and ``hives`` (the hive types the
    plugin applies to, e.g. ``["software", "ntuser"]``) and implement
    :meth:`run`.
    """

    name: str = "base"
    description: str = ""
    hives: list[str] = []
    author: str = "HoneyJam"
    version: str = "0.1.0"

    def applies_to(self, hive_type: str) -> bool:
        if not self.hives:
            return True
        return hive_type.lower() in [h.lower() for h in self.hives]

    def run(self, hive: Hive) -> PluginResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def _result(self) -> PluginResult:
        return PluginResult(plugin=self.name, description=self.description)


_REGISTRY: dict[str, Plugin] = {}


def discover_plugins(force: bool = False) -> dict[str, Plugin]:
    """Import every module under ``honeyjam.plugins`` and register Plugins."""
    global _REGISTRY
    if _REGISTRY and not force:
        return _REGISTRY
    registry: dict[str, Plugin] = {}
    package = importlib.import_module(__name__)
    for mod_info in pkgutil.iter_modules(package.__path__):
        if mod_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{mod_info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, Plugin)
                and obj is not Plugin
                and obj.__module__ == module.__name__
                # skip abstract intermediates that don't declare their own name
                and "name" in obj.__dict__
                and obj.name != Plugin.name
            ):
                instance = obj()
                registry[instance.name] = instance
    _REGISTRY = registry
    return registry


def get_plugins() -> list[Plugin]:
    return list(discover_plugins().values())


def get_plugin(name: str) -> Optional[Plugin]:
    return discover_plugins().get(name)


def get_plugins_for_hive(hive_type: str) -> list[Plugin]:
    return [p for p in get_plugins() if p.applies_to(hive_type)]


def run_all(hive: Hive) -> list[PluginResult]:
    """Run every plugin applicable to the given hive."""
    results: list[PluginResult] = []
    for plugin in get_plugins_for_hive(hive.hive_type):
        try:
            results.append(plugin.run(hive))
        except Exception as exc:  # keep going on plugin failure
            res = plugin._result()
            res.hive_type = hive.hive_type
            res.errors.append(f"{type(exc).__name__}: {exc}")
            results.append(res)
    return results


__all__ = [
    "Plugin",
    "discover_plugins",
    "get_plugins",
    "get_plugin",
    "get_plugins_for_hive",
    "run_all",
]
