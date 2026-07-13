"""Amcache program execution / presence evidence (amcache.hve)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class AmcachePlugin(RegipyBackedPlugin):
    name = "amcache"
    description = "Amcache application execution / file presence evidence (SHA1, paths)"
    hives = ["amcache"]
    regipy_module = "regipy.plugins.amcache.amcache"
    regipy_class = "AmCachePlugin"
    default_confidence = 55
    heuristic_keys = ("full_path", "path")
    timestamp_keys = ("timestamp", "last_modified_timestamp_2")

    def entry_title(self, entry: dict) -> str:
        path = _first(entry, "full_path", "path", "name") or "(amcache entry)"
        sha1 = entry.get("sha1")
        return f"{path}" + (f"  sha1={sha1}" if sha1 else "")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["execution", "amcache"]
