"""Installed programs (Uninstall keys) from SOFTWARE."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class InstalledProgramsPlugin(RegipyBackedPlugin):
    name = "installed_programs"
    description = "Installed programs enumerated from SOFTWARE Uninstall keys"
    hives = ["software"]
    regipy_module = "regipy.plugins.software.installed_programs"
    regipy_class = "InstalledProgramsSoftwarePlugin"
    default_confidence = 40
    timestamp_keys = ("timestamp", "install_date", "last_write")

    def entry_title(self, entry: dict) -> str:
        return str(
            _first(entry, "display_name", "service_name", "name") or "(program)"
        )

    def entry_tags(self, entry: dict) -> list[str]:
        return ["inventory", "installed-program"]
