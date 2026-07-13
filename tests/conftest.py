"""Shared fixtures: an in-memory fake hive that mimics the adapter interface.

This lets the whole plugin/analysis/export stack be exercised offline without
needing a real REGF binary hive.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from honeyjam.parser.hive import RegValue


class FakeKey:
    def __init__(self, name, path, values=None, subkeys=None, ts=None):
        self.name = name
        self.path = path
        self._values = values or []
        self._subkeys = subkeys or []
        self._ts = ts or _dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc)

    @property
    def last_written(self):
        return self._ts

    timestamp = last_written

    def values(self):
        yield from self._values

    def get_value(self, name):
        for v in self._values:
            if (v.name or "").lower() == (name or "").lower():
                return v
        return None

    def subkeys(self):
        yield from self._subkeys

    def get_subkey(self, name):
        for s in self._subkeys:
            if s.name.lower() == name.lower():
                return s
        return None

    @property
    def subkey_count(self):
        return len(self._subkeys)


class FakeHive:
    def __init__(self, hive_type, keys):
        # keys: dict[path -> FakeKey]
        self.hive_type = hive_type
        self.path = f"<fake-{hive_type}>"
        self.name = f"FAKE_{hive_type.upper()}"
        self._keys = {k.rstrip("\\").lower(): v for k, v in keys.items()}

    def get_key(self, key_path):
        return self._keys.get(key_path.rstrip("\\").lower())

    def control_set_path(self, subpath):
        return f"\\ControlSet001{subpath}"

    @property
    def root(self):
        return FakeKey("\\", "\\")

    def recurse(self, path="\\"):
        yield from self._keys.values()


def v(name, data, vtype="REG_SZ"):
    return RegValue(name=name, data=data, value_type=vtype)


@pytest.fixture
def software_hive():
    run = FakeKey(
        "Run",
        r"\Microsoft\Windows\CurrentVersion\Run",
        values=[
            v("LegitApp", r"C:\Program Files\App\app.exe"),
            v("Evil", r"powershell.exe -nop -w hidden -enc SQBFAFgA"),
            v("Dropper", r"C:\Users\Public\update.exe"),
        ],
    )
    return FakeHive("software", {run.path: run})


@pytest.fixture
def system_hive():
    good = FakeKey(
        "GoodSvc",
        r"\ControlSet001\Services\GoodSvc",
        values=[v("ImagePath", r"C:\Windows\System32\svchost.exe"), v("Start", 2, "REG_DWORD")],
    )
    evil = FakeKey(
        "EvilSvc",
        r"\ControlSet001\Services\EvilSvc",
        values=[v("ImagePath", r"C:\Windows\Temp\x.exe & powershell -enc SQBFAFgA"), v("Start", 2, "REG_DWORD")],
    )
    defender = FakeKey(
        "WinDefend",
        r"\ControlSet001\Services\WinDefend",
        values=[v("ImagePath", r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe"), v("Start", 4, "REG_DWORD")],
    )
    services = FakeKey(
        "Services",
        r"\ControlSet001\Services",
        subkeys=[good, evil, defender],
    )
    return FakeHive(
        "system",
        {services.path: services},
    )
