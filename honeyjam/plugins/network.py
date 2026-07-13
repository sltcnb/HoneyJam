"""Network artifacts: interfaces, known networks/WiFi profiles (SOFTWARE)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class NetworkListPlugin(RegipyBackedPlugin):
    name = "network_list"
    description = "NetworkList - known/previously-connected networks and WiFi profiles"
    hives = ["software"]
    regipy_module = "regipy.plugins.software.networklist"
    regipy_class = "NetworkListPlugin"
    default_confidence = 55
    timestamp_keys = ("last_write", "date_created", "date_last_connected")

    def entry_title(self, entry: dict) -> str:
        name = _first(entry, "profile_name", "description", "ssid", "name") or "(network)"
        cat = entry.get("category")
        return f"Network: {name}" + (f" [{cat}]" if cat else "")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["network", "wifi", "networklist"]


class NetworkInterfacesPlugin(RegipyBackedPlugin):
    name = "network_interfaces"
    description = "TCP/IP network interface configuration (IP, DHCP, gateways)"
    hives = ["system"]
    regipy_module = "regipy.plugins.system.network_data"
    regipy_class = "NetworkDataPlugin"
    default_confidence = 45

    def entry_title(self, entry: dict) -> str:
        iface = _first(entry, "interface", "interface_name", "key_path") or "(interface)"
        ip = _first(entry, "dhcp_ip_address", "ip_address", "ipaddress")
        return f"Interface {iface}" + (f" ip={ip}" if ip else "")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["network", "interface"]
