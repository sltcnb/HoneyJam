"""Value-decoding helpers shared by plugins.

regipy sometimes hands values back already-normalised (ints, strings) and
sometimes as raw ``bytes`` or hex strings (for REG_BINARY). These helpers make
plugins resilient to either representation.
"""

from __future__ import annotations

import datetime as _dt
import struct

_FILETIME_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def as_bytes(data) -> bytes | None:
    """Coerce a registry value into ``bytes`` (handles hex strings)."""
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        s = data.strip()
        # regipy renders REG_BINARY as a hex string
        if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                return bytes.fromhex(s)
            except ValueError:
                return None
    return None


def decode_utf16(data) -> str | None:
    """Decode a UTF-16-LE value, trimming at the first NUL terminator."""
    raw = as_bytes(data)
    if raw is None:
        if isinstance(data, str):
            return data
        return None
    try:
        text = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return None
    # cut at first NUL (string terminator); drop trailing junk
    nul = text.find("\x00")
    if nul != -1:
        text = text[:nul]
    text = text.strip()
    return text or None


def filetime_to_dt(data) -> _dt.datetime | None:
    """Convert a Windows FILETIME (bytes/hex/int) to a UTC datetime."""
    filetime = None
    if isinstance(data, int):
        filetime = data
    else:
        raw = as_bytes(data)
        if raw is not None and len(raw) >= 8:
            filetime = struct.unpack("<Q", raw[:8])[0]
    if not filetime:
        return None
    try:
        return _FILETIME_EPOCH + _dt.timedelta(microseconds=filetime / 10)
    except Exception:
        return None


def to_text(data) -> str:
    """Best-effort human string for arbitrary value data."""
    if data is None:
        return ""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).hex()
    return str(data)
