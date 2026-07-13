"""Thin adapter layer wrapping the ``regipy`` library.

HoneyJam plugins should only ever talk to the classes in this module so that
the parsing backend can be swapped or upgraded without touching plugin code.

The public surface intentionally mirrors classic RegRipper mental models:

* ``Hive``  -> an opened REGF file (SYSTEM, SOFTWARE, NTUSER, ...)
* ``RegKey`` -> a registry key with ``name``, ``path``, ``timestamp`` and
  helpers to iterate subkeys / values.
* ``RegValue`` -> a single value (``name``, ``data``, ``value_type``).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Iterator, Optional

from regipy.exceptions import (
    RegistryKeyNotFoundException,
    RegistryValueNotFoundException,
)
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime


@dataclass
class RegValue:
    """A single registry value."""

    name: str
    data: object
    value_type: str
    is_corrupted: bool = False

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.name or '(default)'} ({self.value_type}) = {self.data!r}"


class RegKey:
    """Wraps a regipy ``NKRecord`` giving a stable interface."""

    def __init__(self, nk, path: str):
        self._nk = nk
        self.path = path
        self.name: str = getattr(nk, "name", path.rstrip("\\").split("\\")[-1])

    # -- timestamps ------------------------------------------------------
    @property
    def last_written(self) -> Optional[_dt.datetime]:
        """Last-written timestamp of the key as a timezone-aware datetime."""
        try:
            raw = self._nk.header.last_modified
            return convert_wintime(raw)
        except Exception:  # pragma: no cover - defensive
            return None

    # alias used across the codebase / RegRipper parlance
    timestamp = last_written

    # -- values ----------------------------------------------------------
    def values(self) -> Iterator[RegValue]:
        try:
            count = self._nk.values_count
        except Exception:
            count = 0
        if not count:
            return
        try:
            for v in self._nk.iter_values():
                yield RegValue(
                    name=getattr(v, "name", "") or "",
                    data=getattr(v, "value", None),
                    value_type=getattr(v, "value_type", "") or "",
                    is_corrupted=getattr(v, "is_corrupted", False),
                )
        except Exception:
            return

    def get_value(self, name: str) -> Optional[RegValue]:
        target = (name or "").lower()
        for v in self.values():
            if (v.name or "").lower() == target:
                return v
        return None

    # -- subkeys ---------------------------------------------------------
    def subkeys(self) -> Iterator["RegKey"]:
        try:
            for sk in self._nk.iter_subkeys():
                if sk is None:
                    continue
                child_path = f"{self.path.rstrip(chr(92))}\\{sk.name}"
                yield RegKey(sk, child_path)
        except Exception:
            return

    def get_subkey(self, name: str) -> Optional["RegKey"]:
        target = (name or "").lower()
        for sk in self.subkeys():
            if sk.name.lower() == target:
                return sk
        return None

    @property
    def subkey_count(self) -> int:
        try:
            return int(self._nk.subkey_count)
        except Exception:
            return 0

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RegKey {self.path!r} subkeys={self.subkey_count}>"


class Hive:
    """An opened registry hive."""

    def __init__(self, path: str):
        self.path = str(path)
        self._hive = RegistryHive(self.path)

    @property
    def hive_type(self) -> str:
        return (self._hive.hive_type or "unknown").lower()

    @property
    def name(self) -> str:
        return getattr(self._hive, "name", "") or ""

    def get_key(self, key_path: str) -> Optional[RegKey]:
        """Return the key at ``key_path`` or ``None`` if it does not exist."""
        try:
            nk = self._hive.get_key(key_path)
        except (RegistryKeyNotFoundException, RegistryValueNotFoundException):
            return None
        except Exception:
            return None
        if nk is None:
            return None
        return RegKey(nk, key_path)

    @property
    def root(self) -> RegKey:
        return RegKey(self._hive.root, "\\")

    def control_set_path(self, subpath: str) -> str:
        """Build a path under the *current* control set (SYSTEM hives).

        ``subpath`` may be given with or without a leading backslash, e.g.
        ``"\\Services"`` or ``"Services"``.
        """
        rel = subpath.lstrip("\\")
        try:
            # regipy expects the path *without* a leading backslash and returns
            # e.g. ["\\ControlSet001\\\\Services", ...]; normalise doubles.
            csets = self._hive.get_control_sets(rel)
            if csets:
                return csets[0].replace("\\\\", "\\")
        except Exception:
            pass
        return f"\\ControlSet001\\{rel}"

    def recurse(self, path: str = "\\") -> Iterator[RegKey]:
        """Depth-first iterate every key at or below ``path``."""
        start = self.get_key(path)
        if start is None:
            return
        stack = [start]
        while stack:
            key = stack.pop()
            yield key
            stack.extend(list(key.subkeys()))


def open_hive(path: str) -> Hive:
    return Hive(path)
