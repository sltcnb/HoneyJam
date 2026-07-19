"""Helper base class: wrap a regipy built-in plugin as a HoneyJam plugin.

regipy ships a large library of well-tested extraction plugins that each
populate a list of ``entries`` (dicts). Rather than re-implement that parsing,
HoneyJam wraps them and maps their entries into our :class:`Finding` model,
layering on heuristics, severity/confidence and timeline-ready timestamps.
"""

from __future__ import annotations

import datetime as _dt
import importlib
from typing import Optional

from honeyjam.analysis.heuristics import analyze_command
from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin


def _parse_ts(value) -> Optional[_dt.datetime]:
    if isinstance(value, _dt.datetime):
        return value
    if isinstance(value, str):
        try:
            return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _first(entry: dict, *keys):
    for k in keys:
        if k in entry and entry[k] not in (None, ""):
            return entry[k]
    return None


class RegipyBackedPlugin(Plugin):
    """Subclass and set ``regipy_module``/``regipy_class`` + a ``map_entry``."""

    regipy_module: str = ""
    regipy_class: str = ""
    default_severity: Severity = Severity.INFO
    default_confidence: int = 40
    # entry keys probed (in order) for the heuristic scan; empty = no scan
    heuristic_keys: tuple[str, ...] = ()
    # entry keys probed (in order) for a timeline timestamp
    timestamp_keys: tuple[str, ...] = ("last_write", "timestamp", "last_modified")

    def _load_regipy_plugin(self):
        mod = importlib.import_module(self.regipy_module)
        return getattr(mod, self.regipy_class)

    def _run_regipy(self, hive: Hive) -> list[dict]:
        cls = self._load_regipy_plugin()
        rp = cls(hive._hive, as_json=True)  # noqa: SLF001 - intentional adapter reach-in
        rp.run()
        return list(rp.entries or [])

    # -- subclasses override this to build the human title/description --
    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "name", "path", "full_path", "key_path") or entry)

    def entry_description(self, entry: dict) -> str:
        return self.description

    def entry_tags(self, entry: dict) -> list[str]:
        return [self.name]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        try:
            entries = self._run_regipy(hive)
        except Exception as exc:
            result.errors.append(f"{type(exc).__name__}: {exc}")
            return result

        for entry in entries:
            if not isinstance(entry, dict):
                entry = {"value": entry}
            title = self.entry_title(entry)
            severity = self.default_severity
            confidence = self.default_confidence
            indicators: list[str] = []
            tags = list(self.entry_tags(entry))

            if self.heuristic_keys:
                probe = _first(entry, *self.heuristic_keys)
                suspicion = analyze_command(str(probe) if probe else "")
                if suspicion.suspicious:
                    severity = suspicion.severity
                    confidence = max(confidence, suspicion.score)
                    indicators = suspicion.indicators
                    if "suspicious" not in tags:
                        tags.append("suspicious")

            ts = None
            for key in self.timestamp_keys:
                ts = _parse_ts(entry.get(key))
                if ts:
                    break

            result.add(
                Finding(
                    title=title,
                    description=self.entry_description(entry),
                    severity=severity,
                    confidence=confidence,
                    registry_key=_first(entry, "key_path", "registry_path", "path"),
                    value_data=_first(entry, "path", "full_path", "value", "device_name", "url"),
                    timestamp=ts,
                    indicators=indicators,
                    tags=tags,
                )
            )
        return result
