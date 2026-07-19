"""Build a chronological timeline from findings / key last-written times."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from honeyjam.models import Finding, PluginResult, Severity


@dataclass
class TimelineEvent:
    timestamp: _dt.datetime
    source: str
    description: str
    registry_key: str | None = None
    severity: Severity = Severity.INFO
    indicators: list[str] | None = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "description": self.description,
            "registry_key": self.registry_key,
            "severity": self.severity.value,
            "indicators": self.indicators or [],
        }


def _as_aware_utc(timestamp: _dt.datetime) -> _dt.datetime:
    """Normalize a datetime to timezone-aware UTC.

    Registry parsing backends are inconsistent about timezone info: some
    (e.g. regipy plugins that hand back naive ``datetime.fromisoformat``
    results) produce naive datetimes, while others always attach UTC
    tzinfo. Sorting a mix of the two raises ``TypeError``, so every
    timestamp is normalized here before it is ever compared. Naive values
    are assumed to already represent UTC (regipy/registry timestamps are
    UTC in practice) rather than the local timezone.
    """
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=_dt.timezone.utc)
    return timestamp.astimezone(_dt.timezone.utc)


def build_timeline(results: list[PluginResult]) -> list[TimelineEvent]:
    """Flatten findings that carry a timestamp into a sorted timeline."""
    events: list[TimelineEvent] = []
    for res in results:
        for finding in res.findings:
            if finding.timestamp is None:
                continue
            events.append(
                TimelineEvent(
                    timestamp=_as_aware_utc(finding.timestamp),
                    source=finding.plugin or res.plugin,
                    description=finding.title,
                    registry_key=finding.registry_key,
                    severity=finding.severity,
                    indicators=finding.indicators,
                )
            )
    events.sort(key=lambda e: e.timestamp)
    return events


def timeline_from_findings(findings: list[Finding], source: str = "honeyjam") -> list[TimelineEvent]:
    events = [
        TimelineEvent(
            timestamp=_as_aware_utc(f.timestamp),
            source=f.plugin or source,
            description=f.title,
            registry_key=f.registry_key,
            severity=f.severity,
            indicators=f.indicators,
        )
        for f in findings
        if f.timestamp is not None
    ]
    events.sort(key=lambda e: e.timestamp)
    return events
