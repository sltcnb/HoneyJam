"""JSON / CSV / HTML report exporters."""

from __future__ import annotations

import csv
import datetime as _dt
import io
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from honeyjam.models import PluginResult

_TEMPLATE_DIR = Path(__file__).with_name("templates")


def _jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return str(value)


def to_json(results: list[PluginResult], indent: int | None = 2) -> str:
    payload = [r.model_dump(mode="json") for r in results]
    return json.dumps(payload, indent=indent, default=_jsonable)


_CSV_FIELDS = [
    "plugin",
    "severity",
    "confidence",
    "title",
    "registry_key",
    "value_name",
    "value_data",
    "value_type",
    "timestamp",
    "indicators",
    "tags",
]


def to_csv(results: list[PluginResult]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for res in results:
        for f in res.findings:
            writer.writerow(
                {
                    "plugin": f.plugin,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "title": f.title,
                    "registry_key": f.registry_key,
                    "value_name": f.value_name,
                    "value_data": _jsonable(f.value_data)
                    if f.value_data is not None
                    else "",
                    "value_type": f.value_type or "",
                    "timestamp": f.timestamp.isoformat() if f.timestamp else "",
                    "indicators": ";".join(f.indicators),
                    "tags": ";".join(f.tags),
                }
            )
    return buf.getvalue()


def to_html(results: list[PluginResult], target: str = "") -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    total = sum(r.count for r in results)
    sev_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
    return template.render(
        results=results,
        target=target,
        total=total,
        sev_counts=sev_counts,
        generated=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
