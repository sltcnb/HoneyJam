"""Environment variables from the SYSTEM Session Manager environment key."""

from __future__ import annotations

from honeyjam.analysis.heuristics import analyze_command
from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin


class EnvironmentPlugin(Plugin):
    name = "environment"
    description = "System-wide environment variables (Session Manager\\Environment)"
    hives = ["system"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        key = hive.get_key(
            hive.control_set_path(r"\Control\Session Manager\Environment")
        )
        if key is None:
            result.errors.append("Environment key not found")
            return result
        for value in key.values():
            data = value.data
            suspicion = analyze_command(str(data) if data is not None else "")
            result.add(
                Finding(
                    title=f"{value.name} = {data}",
                    description="System environment variable",
                    severity=suspicion.severity if suspicion.suspicious else Severity.INFO,
                    confidence=max(50, suspicion.score) if suspicion.suspicious else 25,
                    registry_key=key.path,
                    value_name=value.name,
                    value_data=data,
                    value_type=value.value_type,
                    timestamp=key.last_written,
                    indicators=suspicion.indicators,
                    tags=["system", "environment"]
                    + (["suspicious"] if suspicion.suspicious else []),
                )
            )
        return result
