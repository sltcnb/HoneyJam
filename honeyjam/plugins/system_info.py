"""Basic SYSTEM hive facts: computer name, timezone, last shutdown."""

from __future__ import annotations

import datetime as _dt
import struct

from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin


def _decode_shutdown_time(data) -> _dt.datetime | None:
    """ShutdownTime is a little-endian FILETIME stored as REG_BINARY."""
    try:
        if isinstance(data, (bytes, bytearray)) and len(data) >= 8:
            filetime = struct.unpack("<Q", bytes(data[:8]))[0]
        elif isinstance(data, int):
            filetime = data
        else:
            return None
        if filetime == 0:
            return None
        # FILETIME: 100ns intervals since 1601-01-01 UTC
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
        return epoch + _dt.timedelta(microseconds=filetime / 10)
    except Exception:
        return None


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
                result.add(
                    Finding(
                        title=f"Timezone: {val.data}",
                        description="System timezone configuration",
                        severity=Severity.INFO,
                        confidence=90,
                        registry_key=tz_path,
                        value_name=val.name,
                        value_data=val.data,
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
                ts = _decode_shutdown_time(val.data)
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
