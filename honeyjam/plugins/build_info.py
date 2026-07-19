"""OS build / version info and UAC/Defender security posture (SOFTWARE)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class WinVersionPlugin(RegipyBackedPlugin):
    name = "build_info"
    description = "Windows version / build / install date"
    hives = ["software"]
    regipy_module = "regipy.plugins.software.winver"
    regipy_class = "WinVersionPlugin"
    default_confidence = 80

    def entry_title(self, entry: dict) -> str:
        prod = _first(entry, "product_name", "ProductName") or "Windows"
        build = _first(entry, "current_build_number", "CurrentBuild", "build")
        return f"{prod}" + (f" (build {build})" if build else "")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["system", "build-info"]


class UacStatusPlugin(RegipyBackedPlugin):
    name = "uac_status"
    description = "User Account Control (UAC) configuration - flags weakened settings"
    hives = ["software"]
    regipy_module = "regipy.plugins.software.uac"
    regipy_class = "UACStatusPlugin"
    default_confidence = 50

    def entry_title(self, entry: dict) -> str:
        enabled = _first(entry, "EnableLUA", "enable_lua")
        return f"UAC configuration (EnableLUA={enabled})"

    def entry_description(self, entry: dict) -> str:
        return "UAC policy settings"

    def entry_tags(self, entry: dict) -> list[str]:
        tags = ["system", "uac"]
        if str(_first(entry, "EnableLUA", "enable_lua")) in ("0", "False"):
            tags.append("defense-evasion")
        return tags
