"""AppCompatCache / ShimCache execution evidence (SYSTEM)."""

from __future__ import annotations

from honeyjam.models import Severity
from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class ShimCachePlugin(RegipyBackedPlugin):
    name = "shimcache"
    description = "AppCompatCache / ShimCache program execution evidence"
    hives = ["system"]
    regipy_module = "regipy.plugins.system.shimcache"
    regipy_class = "ShimCachePlugin"
    default_confidence = 45
    heuristic_keys = ("path",)
    timestamp_keys = ("last_mod_date", "last_modified", "last_write")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "path") or "(shimcache entry)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["execution", "shimcache"]
