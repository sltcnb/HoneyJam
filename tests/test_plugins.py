from honeyjam.plugins import (
    discover_plugins,
    get_plugin,
    get_plugins_for_hive,
    run_all,
)
from honeyjam.plugins.persistence import PersistencePlugin
from honeyjam.plugins.services import ServicesPlugin
from honeyjam.models import Severity


def test_discovery_finds_core_plugins():
    reg = discover_plugins(force=True)
    for name in ["persistence", "services", "usbstor", "system_info", "userassist"]:
        assert name in reg, f"{name} not discovered"


def test_get_plugins_for_hive():
    sysp = {p.name for p in get_plugins_for_hive("system")}
    assert "services" in sysp
    assert "persistence" not in sysp  # software/ntuser only

    ntp = {p.name for p in get_plugins_for_hive("ntuser")}
    assert "userassist" in ntp
    assert "persistence" in ntp


def test_persistence_plugin_flags_evil(software_hive):
    res = PersistencePlugin().run(software_hive)
    titles = {f.title: f for f in res.findings}
    assert any("Evil" in t for t in titles)
    evil = next(f for f in res.findings if "Evil" in f.title)
    assert evil.severity == Severity.HIGH
    assert "suspicious" in evil.tags
    # legit app present but marked info
    legit = next(f for f in res.findings if "LegitApp" in f.title)
    assert legit.severity == Severity.INFO


def test_services_plugin_disabled_defender(system_hive):
    res = ServicesPlugin().run(system_hive)
    defender = [f for f in res.findings if "WinDefend" in f.title and "DISABLED" in f.title]
    assert defender, "disabled defender not flagged"
    assert defender[0].severity == Severity.HIGH
    # suspicious imagepath service
    assert any("EvilSvc" in f.title and f.severity == Severity.HIGH for f in res.findings)


def test_run_all_respects_hive_type(system_hive):
    results = run_all(system_hive)
    plugins_run = {r.plugin for r in results}
    assert "services" in plugins_run
    assert "persistence" not in plugins_run
