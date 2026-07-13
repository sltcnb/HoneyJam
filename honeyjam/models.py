"""Core data models shared across HoneyJam (pydantic v2)."""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]


class Finding(BaseModel):
    """A single artifact / observation produced by a plugin."""

    plugin: str = ""
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: int = Field(default=50, ge=0, le=100)
    registry_key: Optional[str] = None
    value_name: Optional[str] = None
    value_data: Optional[Any] = None
    value_type: Optional[str] = None
    timestamp: Optional[_dt.datetime] = None
    indicators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    model_config = {"use_enum_values": False}


class PluginResult(BaseModel):
    """The return type of every plugin's ``run`` method."""

    plugin: str
    description: str = ""
    hive_type: str = ""
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def add(self, finding: Finding) -> None:
        finding.plugin = finding.plugin or self.plugin
        self.findings.append(finding)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
