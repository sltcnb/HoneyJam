"""UserAssist GUI program execution history (NTUSER, ROT13-encoded)."""

from __future__ import annotations

import codecs

from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin

_UA_BASE = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


class UserAssistPlugin(Plugin):
    name = "userassist"
    description = "UserAssist executed-program history (ROT13 decoded), best effort"
    hives = ["ntuser"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        base = hive.get_key(_UA_BASE)
        if base is None:
            result.errors.append("UserAssist key not present")
            return result

        for guid_key in base.subkeys():
            count_key = guid_key.get_subkey("Count")
            if count_key is None:
                continue
            for value in count_key.values():
                name = value.name or ""
                try:
                    decoded = rot13(name)
                except Exception:
                    decoded = name
                result.add(
                    Finding(
                        title=decoded,
                        description="UserAssist executed program (ROT13-decoded)",
                        severity=Severity.INFO,
                        confidence=60,
                        registry_key=count_key.path,
                        value_name=name,
                        value_data=decoded,
                        value_type=value.value_type,
                        timestamp=count_key.last_written,
                        tags=["execution", "userassist"],
                    )
                )
        return result
