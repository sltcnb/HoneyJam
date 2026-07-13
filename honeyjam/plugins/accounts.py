"""User accounts / profiles (ProfileList: SID -> user path) from SOFTWARE."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class ProfileListPlugin(RegipyBackedPlugin):
    name = "profilelist"
    description = "ProfileList - maps user SIDs to profile paths"
    hives = ["software"]
    regipy_module = "regipy.plugins.software.profilelist"
    regipy_class = "ProfileListPlugin"
    default_confidence = 70

    def entry_title(self, entry: dict) -> str:
        sid = _first(entry, "sid") or "(sid?)"
        path = _first(entry, "path", "profile_path") or ""
        return f"{sid} -> {path}"

    def entry_tags(self, entry: dict) -> list[str]:
        return ["account", "profile"]
