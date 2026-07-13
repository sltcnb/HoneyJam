"""Basic SYSTEM hive facts: computer name, timezone, last shutdown."""

from __future__ import annotations

from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.parser.util import decode_utf16, filetime_to_dt
from honeyjam.plugins import Plugin


class SystemInfoPlugin(Plugin):
    name = "system_info"
    description = "Computer name, timezone and last shutdown time from the SYSTEM hive"
    hives = ["system"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type

        # Computer name
        cn_path = hive.control_set_path(r"\Control\ComputerName\ComputerName")
        cn = hive.get_key(cn_path)
        if cn is not None:
            val = cn.get_value("ComputerName")
            if val is not None:
                result.add(
                    Finding(
                        title=f"Computer name: {val.data}",
                        description="Registered computer name",
                        severity=Severity.INFO,
                        confidence=90,
                        registry_key=cn_path,
                        value_name="ComputerName",
                        value_data=val.data,
                        value_type=val.value_type,
                        timestamp=cn.last_written,
                        tags=["system", "hostname"],
                    )
                )

        # Timezone
        tz_path = hive.control_set_path(r"\Control\TimeZoneInformation")
        tz = hive.get_key(tz_path)
        if tz is not None:
            val = tz.get_value("TimeZoneKeyName") or tz.get_value("StandardName")
            if val is not None:
                tz_name = decode_utf16(val.data) or str(val.data)
                result.add(
                    Finding(
                        title=f"Timezone: {tz_name}",
                        description="System timezone configuration",
                        severity=Severity.INFO,
                        confidence=90,
                        registry_key=tz_path,
                        value_name=val.name,
                        value_data=tz_name,
                        value_type=val.value_type,
                        timestamp=tz.last_written,
                        tags=["system", "timezone"],
                    )
                )

        # Last shutdown time
        sd_path = hive.control_set_path(r"\Control\Windows")
        sd = hive.get_key(sd_path)
        if sd is not None:
            val = sd.get_value("ShutdownTime")
            if val is not None:
                ts = filetime_to_dt(val.data)
                result.add(
                    Finding(
                        title=f"Last shutdown: {ts.isoformat() if ts else 'unknown'}",
                        description="Last recorded system shutdown time",
                        severity=Severity.INFO,
                        confidence=90,
                        registry_key=sd_path,
                        value_name="ShutdownTime",
                        value_data=str(ts) if ts else None,
                        value_type=val.value_type,
                        timestamp=ts or sd.last_written,
                        tags=["system", "shutdown"],
                    )
                )
        return result
