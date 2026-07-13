"""Background Activity Moderator (BAM/DAM) - last-execution times (SYSTEM)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class BamPlugin(RegipyBackedPlugin):
    name = "bam"
    description = "Background Activity Moderator (BAM/DAM) executable last-run times"
    hives = ["system"]
    regipy_module = "regipy.plugins.system.bam"
    regipy_class = "BAMPlugin"
    default_confidence = 55
    heuristic_keys = ("name", "path")
    timestamp_keys = ("last_execution", "timestamp", "last_write")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "name", "path") or "(bam entry)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["execution", "bam"]
