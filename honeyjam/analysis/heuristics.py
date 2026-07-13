"""Reusable, hive-independent detection heuristics.

Everything here operates on plain strings so it can be unit-tested without a
real registry hive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from honeyjam.models import Severity

# (regex, human label, indicator id, severity weight)
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str, str, Severity]] = [
    (re.compile(r"powershell.{0,40}-enc", re.I), "Encoded PowerShell command", "powershell.encoded", Severity.HIGH),
    (re.compile(r"powershell.{0,40}(-nop|-noni|-w\s*hidden|-windowstyle\s*hidden)", re.I), "Obfuscated PowerShell flags", "powershell.hidden", Severity.HIGH),
    (re.compile(r"\bIEX\b|Invoke-Expression", re.I), "PowerShell Invoke-Expression", "powershell.iex", Severity.HIGH),
    (re.compile(r"\bmshta(\.exe)?\b", re.I), "mshta execution", "lolbin.mshta", Severity.HIGH),
    (re.compile(r"\bcertutil(\.exe)?\b.{0,60}(-urlcache|-decode|-encode)", re.I), "certutil download/decode", "lolbin.certutil", Severity.HIGH),
    (re.compile(r"\brundll32(\.exe)?\b.{0,60}javascript:", re.I), "rundll32 javascript", "lolbin.rundll32", Severity.HIGH),
    (re.compile(r"\bregsvr32(\.exe)?\b.{0,60}(scrobj|/i:http)", re.I), "regsvr32 scriptlet (Squiblydoo)", "lolbin.regsvr32", Severity.HIGH),
    (re.compile(r"\bbitsadmin(\.exe)?\b.{0,60}/transfer", re.I), "bitsadmin transfer", "lolbin.bitsadmin", Severity.MEDIUM),
    (re.compile(r"\bwscript(\.exe)?\b|\bcscript(\.exe)?\b", re.I), "Script host execution", "lolbin.scripthost", Severity.MEDIUM),
    (re.compile(r"FromBase64String", re.I), "Base64 decode in command", "encoding.base64", Severity.MEDIUM),
    (re.compile(r"\\Temp\\|\\Tmp\\|%temp%|\\AppData\\Local\\Temp", re.I), "Executable in Temp path", "path.temp", Severity.MEDIUM),
    (re.compile(r"\\AppData\\Roaming\\", re.I), "Executable in AppData\\Roaming", "path.appdata", Severity.LOW),
    (re.compile(r"\\ProgramData\\", re.I), "Executable in ProgramData", "path.programdata", Severity.LOW),
    (re.compile(r"\\Users\\Public\\", re.I), "Executable in Users\\Public", "path.public", Severity.MEDIUM),
    (re.compile(r"^\\\\[^\\]+\\", re.I), "UNC network path", "path.unc", Severity.MEDIUM),
    (re.compile(r"https?://", re.I), "Embedded URL", "network.url", Severity.MEDIUM),
    (re.compile(r"\bftp://", re.I), "Embedded FTP URL", "network.ftp", Severity.MEDIUM),
    (re.compile(r"^[A-Za-z]:\\[^\\]+\.(exe|scr|bat|cmd|vbs|js|ps1)$", re.I), "Executable at drive root", "path.driveroot", Severity.MEDIUM),
    (re.compile(r"[a-zA-Z0-9+/]{80,}={0,2}", re.I), "Long base64-like blob", "encoding.blob", Severity.MEDIUM),
]


@dataclass
class HeuristicHit:
    label: str
    indicator: str
    severity: Severity


@dataclass
class SuspicionResult:
    suspicious: bool
    hits: list[HeuristicHit] = field(default_factory=list)
    score: int = 0

    @property
    def severity(self) -> Severity:
        if not self.hits:
            return Severity.INFO
        return max((h.severity for h in self.hits), key=lambda s: s.rank)

    @property
    def indicators(self) -> list[str]:
        return [h.indicator for h in self.hits]


def analyze_command(value: str | None) -> SuspicionResult:
    """Inspect a command line / path string for suspicious indicators."""
    if not value:
        return SuspicionResult(False)
    text = str(value)
    hits: list[HeuristicHit] = []
    seen: set[str] = set()
    for pattern, label, indicator, sev in _SUSPICIOUS_PATTERNS:
        if pattern.search(text) and indicator not in seen:
            hits.append(HeuristicHit(label, indicator, sev))
            seen.add(indicator)
    score = ioc_score(hits)
    return SuspicionResult(bool(hits), hits, score)


def is_suspicious(value: str | None) -> bool:
    """Convenience boolean wrapper around :func:`analyze_command`."""
    return analyze_command(value).suspicious


def ioc_score(hits: list[HeuristicHit]) -> int:
    """Confidence score (0-100) derived from a set of heuristic hits."""
    if not hits:
        return 0
    weights = {
        Severity.LOW: 15,
        Severity.MEDIUM: 30,
        Severity.HIGH: 45,
        Severity.CRITICAL: 60,
        Severity.INFO: 5,
    }
    total = 0
    for h in hits:
        total += weights.get(h.severity, 10)
    # multiple independent indicators reinforce confidence
    if len(hits) > 1:
        total += 10 * (len(hits) - 1)
    return min(100, total)


# Security-relevant service names that, when disabled, are suspicious.
SECURITY_SERVICES = {
    "windefend": "Windows Defender Antivirus",
    "wdnissvc": "Windows Defender Network Inspection",
    "sense": "Windows Defender ATP",
    "securityhealthservice": "Windows Security Health",
    "wscsvc": "Windows Security Center",
    "mpssvc": "Windows Firewall",
    "sharedaccess": "Internet Connection Sharing / Firewall",
    "eventlog": "Windows Event Log",
    "wuauserv": "Windows Update",
}

# Service start type values (SYSTEM\...\Services\<svc>\Start)
START_TYPES = {
    0: "boot",
    1: "system",
    2: "auto",
    3: "manual",
    4: "disabled",
}
