"""TypedPaths (Explorer address bar) and TypedURLs (IE) from NTUSER."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class TypedPathsPlugin(RegipyBackedPlugin):
    name = "typedpaths"
    description = "TypedPaths - paths typed into the Explorer address bar"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.typed_paths"
    regipy_class = "TypedPathsPlugin"
    default_confidence = 45
    heuristic_keys = ("value", "path", "entry")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "value", "path", "entry", "name") or "(typed path)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["file-access", "typedpaths"]


class TypedUrlsPlugin(RegipyBackedPlugin):
    name = "typedurls"
    description = "TypedURLs - URLs typed into Internet Explorer / Edge legacy"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.typed_urls"
    regipy_class = "TypedUrlsPlugin"
    default_confidence = 45
    heuristic_keys = ("value", "url", "entry")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "value", "url", "entry", "name") or "(typed url)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["browser", "typedurls"]
