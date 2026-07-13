"""Autostart / persistence locations (Run, RunOnce, ...)."""

from __future__ import annotations

from honeyjam.analysis.heuristics import analyze_command
from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin

# Common autostart key paths keyed by hive type.
_RUN_KEYS = {
    "software": [
        r"\Microsoft\Windows\CurrentVersion\Run",
        r"\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"\Microsoft\Windows\CurrentVersion\RunServices",
        r"\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ],
    "ntuser": [
        r"\Software\Microsoft\Windows\CurrentVersion\Run",
        r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"\Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ],
}


class PersistencePlugin(Plugin):
    name = "persistence"
    description = "Autostart persistence keys (Run/RunOnce) with suspicious-command heuristics"
    hives = ["software", "ntuser"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        for key_path in _RUN_KEYS.get(hive.hive_type, []):
            key = hive.get_key(key_path)
            if key is None:
                continue
            for value in key.values():
                data = value.data
                suspicion = analyze_command(str(data) if data is not None else "")
                if suspicion.suspicious:
                    severity = suspicion.severity
                    confidence = max(60, suspicion.score)
                    desc = "Suspicious autostart entry: " + ", ".join(
                        h.label for h in suspicion.hits
                    )
                    tags = ["persistence", "suspicious"]
                else:
                    severity = Severity.INFO
                    confidence = 40
                    desc = "Autostart entry"
                    tags = ["persistence"]
                result.add(
                    Finding(
                        title=f"{value.name or '(default)'} -> {data}",
                        description=desc,
                        severity=severity,
                        confidence=confidence,
                        registry_key=key_path,
                        value_name=value.name,
                        value_data=data,
                        value_type=value.value_type,
                        timestamp=key.last_written,
                        indicators=suspicion.indicators,
                        tags=tags,
                    )
                )
        return result
