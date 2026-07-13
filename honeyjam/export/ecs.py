"""Map HoneyJam findings to an ECS-ish (Elastic Common Schema) JSON shape."""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from honeyjam.models import Finding, PluginResult, Severity

# ECS registry data type names roughly mirror Windows REG_* types.
_TYPE_MAP = {
    "REG_SZ": "REG_SZ",
    "REG_EXPAND_SZ": "REG_EXPAND_SZ",
    "REG_MULTI_SZ": "REG_MULTI_SZ",
    "REG_DWORD": "REG_DWORD",
    "REG_QWORD": "REG_QWORD",
    "REG_BINARY": "REG_BINARY",
}

_SEVERITY_TO_ECS = {
    Severity.INFO: 21,
    Severity.LOW: 21,
    Severity.MEDIUM: 47,
    Severity.HIGH: 73,
    Severity.CRITICAL: 99,
}


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return value


def finding_to_ecs(finding: Finding, hive_type: str = "") -> dict:
    """Convert a single :class:`Finding` into an ECS document."""
    is_malware = "malware" in finding.tags or "suspicious" in finding.tags
    doc: dict[str, Any] = {
        "@timestamp": finding.timestamp.isoformat()
        if finding.timestamp
        else _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "event": {
            "kind": "alert" if is_malware else "event",
            "category": ["registry"] + (["malware"] if is_malware else []),
            "type": ["change" if "persistence" in finding.tags else "info"],
            "provider": "honeyjam",
            "module": finding.plugin,
            "severity": _SEVERITY_TO_ECS.get(finding.severity, 21),
            "risk_score": finding.confidence,
        },
        "message": finding.title,
        "registry": {
            "hive": hive_type,
            "key": finding.registry_key,
            "value": finding.value_name,
        },
        "honeyjam": {
            "plugin": finding.plugin,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "description": finding.description,
            "tags": finding.tags,
        },
    }
    if finding.value_data is not None:
        doc["registry"]["data"] = {
            "strings": [str(finding.value_data)],
            "type": _TYPE_MAP.get(finding.value_type or "", finding.value_type),
        }
    if finding.indicators:
        doc["threat"] = {"indicator": {"type": finding.indicators}}
        if is_malware:
            doc.setdefault("malware", {})["indicator"] = finding.indicators
    return doc


def results_to_ecs(results: list[PluginResult]) -> list[dict]:
    docs: list[dict] = []
    for res in results:
        for finding in res.findings:
            docs.append(finding_to_ecs(finding, res.hive_type))
    return docs


def to_ecs_json(results: list[PluginResult], indent: int | None = 2) -> str:
    return json.dumps(results_to_ecs(results), indent=indent, default=_jsonable)


def to_ndjson(results: list[PluginResult]) -> str:
    """Newline-delimited JSON, ready for ingestion into Elastic."""
    return "\n".join(
        json.dumps(doc, default=_jsonable) for doc in results_to_ecs(results)
    )
