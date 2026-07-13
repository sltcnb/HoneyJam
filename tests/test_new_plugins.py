"""Offline tests for the v0.2 plugin expansion.

The regipy-backed plugins are tested by monkeypatching their ``_run_regipy``
method so no real hive / regipy import is required. This exercises the
entry -> Finding mapping, heuristics enrichment and timeline timestamps.
"""

import datetime as _dt

import pytest

from honeyjam.parser.hive import RegValue
from honeyjam.models import Severity
from honeyjam.plugins import discover_plugins, get_plugin, get_plugins, get_plugins_for_hive
from honeyjam.plugins.amcache import AmcachePlugin
from honeyjam.plugins.bam import BamPlugin
from honeyjam.plugins.environment import EnvironmentPlugin
from honeyjam.plugins.installed_programs import InstalledProgramsPlugin
from honeyjam.plugins.mru import RunMruPlugin
from honeyjam.plugins.network import NetworkListPlugin
from honeyjam.plugins.shimcache import ShimCachePlugin
from tests.conftest import FakeHive, FakeKey, v

EXPECTED = {
    "persistence", "services", "usbstor", "system_info", "userassist",
    "shimcache", "amcache", "bam", "recentdocs", "runmru", "opensave_mru",
    "typedpaths", "typedurls", "rdp_connections", "network_list",
    "network_interfaces", "profilelist", "installed_programs",
    "shellbags_ntuser", "shellbags_usrclass", "mounted_devices",
    "usb_devices", "build_info", "uac_status", "environment",
}


def test_all_expected_plugins_discovered():
    names = {p.name for p in get_plugins()}
    missing = EXPECTED - names
    assert not missing, f"missing plugins: {missing}"
    assert len(get_plugins()) >= 25
    assert "base" not in names  # abstract intermediates excluded


def test_hive_routing_new_plugins():
    sysnames = {p.name for p in get_plugins_for_hive("system")}
    assert {"shimcache", "bam", "mounted_devices", "environment"} <= sysnames
    ntnames = {p.name for p in get_plugins_for_hive("ntuser")}
    assert {"recentdocs", "runmru", "typedurls", "rdp_connections"} <= ntnames
    swnames = {p.name for p in get_plugins_for_hive("software")}
    assert {"installed_programs", "profilelist", "network_list"} <= swnames
    assert "amcache" in {p.name for p in get_plugins_for_hive("amcache")}


def _patched(plugin, entries, monkeypatch):
    monkeypatch.setattr(plugin, "_run_regipy", lambda hive: entries)
    return plugin.run(FakeHive(plugin.hives[0], {}))


def test_regipy_backed_maps_entries_and_timeline(monkeypatch):
    entries = [
        {"path": r"C:\Windows\System32\cmd.exe", "last_mod_date": "2021-05-01T10:00:00+00:00"},
        {"path": r"C:\Users\Public\evil.exe", "last_mod_date": "2021-05-02T10:00:00+00:00"},
    ]
    res = _patched(ShimCachePlugin(), entries, monkeypatch)
    assert res.count == 2
    evil = next(f for f in res.findings if "evil" in f.title.lower())
    assert evil.severity == Severity.MEDIUM  # Users\Public heuristic
    assert "suspicious" in evil.tags
    assert all("shimcache" in f.tags for f in res.findings)
    # timestamps parsed for timeline
    assert all(isinstance(f.timestamp, _dt.datetime) for f in res.findings)


def test_regipy_backed_error_is_guarded(monkeypatch):
    def boom(hive):
        raise RuntimeError("kaboom")

    p = AmcachePlugin()
    monkeypatch.setattr(p, "_run_regipy", boom)
    res = p.run(FakeHive("amcache", {}))
    assert res.count == 0
    assert res.errors and "kaboom" in res.errors[0]


def test_runmru_heuristic(monkeypatch):
    entries = [{"value": "powershell -enc SQBFAFgA", "name": "a"}]
    res = _patched(RunMruPlugin(), entries, monkeypatch)
    assert res.findings[0].severity == Severity.HIGH
    assert "suspicious" in res.findings[0].tags


def test_installed_programs_title(monkeypatch):
    entries = [{"display_name": "7-Zip 19.00", "timestamp": "2020-01-01T00:00:00+00:00"}]
    res = _patched(InstalledProgramsPlugin(), entries, monkeypatch)
    assert "7-Zip" in res.findings[0].title


def test_network_list_title(monkeypatch):
    entries = [{"profile_name": "CorpWiFi", "category": "Private", "last_write": "2022-01-01T00:00:00+00:00"}]
    res = _patched(NetworkListPlugin(), entries, monkeypatch)
    assert "CorpWiFi" in res.findings[0].title
    assert "wifi" in res.findings[0].tags


def test_environment_plugin_flags_suspicious():
    env = FakeKey(
        "Environment",
        r"\ControlSet001\Control\Session Manager\Environment",
        values=[
            v("Path", r"C:\Windows;C:\Windows\System32"),
            v("Evil", r"powershell -enc AAAA"),
        ],
    )
    hive = FakeHive("system", {env.path: env})
    res = EnvironmentPlugin().run(hive)
    assert res.count == 2
    evil = next(f for f in res.findings if f.value_name == "Evil")
    assert evil.severity == Severity.HIGH


def test_environment_missing_key_guarded():
    res = EnvironmentPlugin().run(FakeHive("system", {}))
    assert res.count == 0
    assert res.errors
