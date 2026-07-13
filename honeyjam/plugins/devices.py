"""Mounted devices and detailed USB device history (SYSTEM)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class MountedDevicesPlugin(RegipyBackedPlugin):
    name = "mounted_devices"
    description = "MountedDevices - drive letters / volume mount points to device IDs"
    hives = ["system"]
    regipy_module = "regipy.plugins.system.mountdev"
    regipy_class = "MountedDevicesPlugin"
    default_confidence = 40

    def entry_title(self, entry: dict) -> str:
        name = _first(entry, "name", "identifier", "key_path") or "(mount)"
        return str(name)

    def entry_tags(self, entry: dict) -> list[str]:
        return ["device", "mounted-device"]


class UsbDevicesPlugin(RegipyBackedPlugin):
    name = "usb_devices"
    description = "USB device enumeration (Enum\\USB) beyond mass-storage"
    hives = ["system"]
    regipy_module = "regipy.plugins.system.usb_devices"
    regipy_class = "USBDevicesPlugin"
    default_confidence = 55

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "device_name", "friendly_name", "key_path") or "(usb device)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["device", "usb"]
