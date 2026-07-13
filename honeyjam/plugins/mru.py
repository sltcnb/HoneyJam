"""Most-Recently-Used artifacts from NTUSER (RecentDocs, RunMRU, ComDlg32)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class RecentDocsPlugin(RegipyBackedPlugin):
    name = "recentdocs"
    description = "RecentDocs - recently opened files/folders (Explorer)"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.recentdocs"
    regipy_class = "RecentDocsPlugin"
    default_confidence = 45
    heuristic_keys = ("value", "name")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "name", "value", "entry") or "(recentdoc)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["file-access", "mru", "recentdocs"]


class RunMruPlugin(RegipyBackedPlugin):
    name = "runmru"
    description = "RunMRU - commands typed into the Run dialog"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.runmru"
    regipy_class = "RunMRUPlugin"
    default_confidence = 55
    heuristic_keys = ("value", "command", "name")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "value", "command", "name") or "(runmru)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["execution", "mru", "runmru"]


class OpenSaveMruPlugin(RegipyBackedPlugin):
    name = "opensave_mru"
    description = "ComDlg32 OpenSavePidlMRU / LastVisitedPidlMRU (open/save dialog history)"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.comdlg32"
    regipy_class = "ComDlg32Plugin"
    default_confidence = 45
    heuristic_keys = ("value", "name", "path")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "value", "name", "path") or "(opensave mru)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["file-access", "mru", "comdlg32"]
