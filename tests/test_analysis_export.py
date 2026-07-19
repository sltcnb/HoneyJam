import datetime as dt
import json

from honeyjam.analysis import malware_detector
from honeyjam.analysis.timeline import build_timeline
from honeyjam.export import ecs, report
from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.plugins import run_all


def test_malware_signature_hit():
    from honeyjam.analysis.malware_detector import scan_text

    hits = scan_text("cmd /c vssadmin delete shadows /all /quiet")
    assert any(h["id"] == "mal.ransomware.marker" for h in hits)


def test_disabled_service_defense_evasion(system_hive):
    dets = malware_detector.detect_defense_evasion(system_hive)
    assert any("defense_evasion.service_disabled" in d.indicators for d in dets)
    assert any(d.severity == Severity.HIGH for d in dets)


def test_analyze_hive_combines(system_hive):
    results = run_all(system_hive)
    dets = malware_detector.analyze_hive(system_hive, results)
    assert dets  # at least the disabled defender


def test_ecs_mapping_shape(software_hive):
    results = run_all(software_hive)
    docs = ecs.results_to_ecs(results)
    assert docs
    doc = next(d for d in docs if "Evil" in d["message"])
    assert "registry" in doc
    assert doc["registry"]["key"]
    assert "registry" in doc["event"]["category"]
    assert doc["event"]["risk_score"] >= 0
    # malware/suspicious findings get an indicator
    assert "threat" in doc


def test_ecs_json_parses(software_hive):
    results = run_all(software_hive)
    parsed = json.loads(ecs.to_ecs_json(results))
    assert isinstance(parsed, list)
    # ndjson lines each parse
    for line in ecs.to_ndjson(results).splitlines():
        json.loads(line)


def test_csv_and_json_export(software_hive):
    results = run_all(software_hive)
    csv_out = report.to_csv(results)
    assert "plugin,severity" in csv_out.splitlines()[0]
    assert "Evil" in csv_out
    parsed = json.loads(report.to_json(results))
    assert isinstance(parsed, list)


def test_html_export(software_hive):
    results = run_all(software_hive)
    html = report.to_html(results, target="test")
    assert "<html" in html.lower()
    assert "HoneyJam" in html


def test_timeline_sorted(system_hive):
    results = run_all(system_hive)
    events = build_timeline(results)
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)


def test_timeline_sorts_mixed_naive_and_aware_timestamps():
    """regipy plugins often hand back naive datetimes while other plugins
    always attach UTC tzinfo; build_timeline must not raise when the two
    are mixed and must still order events correctly (naive timestamps are
    treated as UTC).
    """
    results = [
        PluginResult(
            plugin="aware_plugin",
            findings=[
                Finding(
                    title="middle-aware",
                    timestamp=dt.datetime(2023, 6, 15, tzinfo=dt.timezone.utc),
                ),
                Finding(
                    title="latest-aware",
                    timestamp=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc),
                ),
            ],
        ),
        PluginResult(
            plugin="naive_regipy_plugin",
            findings=[
                Finding(title="earliest-naive", timestamp=dt.datetime(2020, 1, 1)),
                Finding(title="another-naive", timestamp=dt.datetime(2022, 3, 3)),
            ],
        ),
    ]

    events = build_timeline(results)  # must not raise TypeError

    assert [e.description for e in events] == [
        "earliest-naive",
        "another-naive",
        "middle-aware",
        "latest-aware",
    ]
    # every timestamp is normalized to timezone-aware UTC
    assert all(e.timestamp.tzinfo is not None for e in events)
    assert all(e.timestamp.utcoffset() == dt.timedelta(0) for e in events)
