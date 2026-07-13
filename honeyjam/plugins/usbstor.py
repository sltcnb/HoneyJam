"""USB storage device history (SYSTEM\\CurrentControlSet\\Enum\\USBSTOR)."""

from __future__ import annotations

from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin


class UsbstorPlugin(Plugin):
    name = "usbstor"
    description = "Enumerate USB storage devices ever connected to the system"
    hives = ["system"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        base = hive.control_set_path(r"\Enum\USBSTOR")
        root = hive.get_key(base)
        if root is None:
            result.errors.append(f"USBSTOR key not found at {base}")
            return result

        for device_class in root.subkeys():
            # device_class name encodes vendor/product, e.g. Disk&Ven_SanDisk&Prod_...
            for instance in device_class.subkeys():
                friendly = instance.get_value("FriendlyName")
                friendly_name = (
                    str(friendly.data) if friendly and friendly.data else device_class.name
                )
                result.add(
                    Finding(
                        title=f"USB device: {friendly_name}",
                        description=f"Device class: {device_class.name} / serial: {instance.name}",
                        severity=Severity.INFO,
                        confidence=70,
                        registry_key=instance.path,
                        value_name="FriendlyName",
                        value_data=friendly_name,
                        value_type=friendly.value_type if friendly else None,
                        timestamp=instance.last_written,
                        tags=["usb", "device", "external-media"],
                    )
                )
        return result
