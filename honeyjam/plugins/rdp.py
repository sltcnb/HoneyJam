"""RDP client connection history (Terminal Server Client) from NTUSER."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class RdpConnectionsPlugin(RegipyBackedPlugin):
    name = "rdp_connections"
    description = "Terminal Server Client - outbound RDP connection history"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.tsclient"
    regipy_class = "TSClientPlugin"
    default_confidence = 55
    heuristic_keys = ("value", "server", "name")

    def entry_title(self, entry: dict) -> str:
        return "RDP to " + str(_first(entry, "value", "server", "name", "hostname") or "(unknown)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["lateral-movement", "rdp"]
