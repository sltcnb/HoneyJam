# HoneyJam

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-alpha-orange)
![parser](https://img.shields.io/badge/parser-regipy-yellow)
![tests](https://img.shields.io/badge/tests-pytest-brightgreen)

**HoneyJam** is a Windows Registry forensics toolkit and a spiritual successor to
[RegRipper](https://github.com/keydet89/RegRipper3.0). It provides a modern
plugin architecture, malware/IOC heuristics, timeline building and
[ECS](https://www.elastic.co/guide/en/ecs/current/index.html)-style JSON export
on top of the excellent [`regipy`](https://github.com/mkorman90/regipy) pure-Python
REGF parser.

HoneyJam does **not** hand-roll the binary hive parser. It wraps `regipy` behind
a small, stable adapter (`honeyjam/parser/hive.py`) so plugins stay simple and
the parsing backend can evolve independently.

## Features

- Plugin system with auto-discovery (`honeyjam/plugins/`)
- Suspicious-command heuristics: `powershell -enc`, `mshta`, `certutil`,
  `regsvr32`/Squiblydoo, Temp/AppData/Public paths, UNC paths, embedded URLs, ...
- Malware detector: YAML signature database + defense-evasion heuristics
  (disabled Defender/firewall/event-log services, neutralized event logs)
- Confidence scoring on every finding
- Timeline builder from key last-written times and artifact timestamps
- Exports: rich terminal tables, JSON, CSV, ECS/NDJSON, standalone HTML report

## Install

```bash
pip install -e .          # from a checkout
pip install -e .[dev]     # with pytest

# or via Docker
docker build -t honeyjam .
docker run --rm -v /path/to/hives:/data honeyjam parse SYSTEM
```

Requires Python >= 3.10.

## Usage

```bash
# Run all applicable plugins against one hive
honeyjam parse SOFTWARE
honeyjam parse NTUSER.DAT --json
honeyjam parse SYSTEM --html report.html
honeyjam parse SOFTWARE --ecs        # ECS JSON to stdout
honeyjam parse SOFTWARE --csv

# Malware / IOC detection over a hive or a whole directory of hives
honeyjam detect ./triage_hives --severity high
honeyjam detect SYSTEM --json

# Chronological timeline
honeyjam timeline ./triage_hives --format table
honeyjam timeline ./triage_hives --format ecs
honeyjam timeline ./triage_hives --format csv

# Plugin management
honeyjam plugins list
honeyjam plugin run persistence --hive SOFTWARE
honeyjam plugin run services --hive SYSTEM --json

# Environment / version
honeyjam info
```

## Plugins

| Plugin        | Hives            | Purpose                                                       |
|---------------|------------------|--------------------------------------------------------------|
| `persistence` | software, ntuser | Run/RunOnce autostart keys + suspicious-command heuristics   |
| `services`    | system           | Services enumeration, suspicious ImagePath, disabled security services |
| `usbstor`     | system           | USB storage device history (USBSTOR)                         |
| `system_info` | system           | Computer name, timezone, last shutdown time                 |
| `userassist`  | ntuser           | UserAssist program-execution history (ROT13 decoded)        |

## ECS output example

Each finding maps to an ECS-ish document:

```json
{
  "@timestamp": "2024-01-01T00:00:00+00:00",
  "event": {
    "kind": "alert",
    "category": ["registry", "malware"],
    "type": ["change"],
    "module": "persistence",
    "severity": 73,
    "risk_score": 90
  },
  "message": "Evil -> powershell.exe -nop -w hidden -enc SQBFAFgA",
  "registry": {
    "hive": "software",
    "key": "\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value": "Evil",
    "data": { "strings": ["powershell.exe -nop -w hidden -enc SQBFAFgA"], "type": "REG_SZ" }
  },
  "malware": { "indicator": ["powershell.encoded", "powershell.hidden"] },
  "honeyjam": { "plugin": "persistence", "severity": "high", "confidence": 90 }
}
```

## Development

```bash
python -m pytest        # tests run fully offline (no real hive required)
```

Tests unit-check the heuristics, IOC scoring, ECS mapping, plugin discovery and
the full plugin -> analysis -> export pipeline using an in-memory fake hive.

## Roadmap

- 100+ plugins (Amcache, ShimCache, BAM/DAM, ShellBags, SAM users, network profiles, ...)
- Transaction-log (`.LOG1`/`.LOG2`) replay for dirty hives
- Live-system analysis mode
- Web UI + REST API and containerized/K8s deployment
- MITRE ATT&CK technique mapping on findings
- Diffing between two hive snapshots

## Credits

- [RegRipper](https://github.com/keydet89/RegRipper3.0) by Harlan Carvey — the
  inspiration and the standard for registry forensics tooling.
- [regipy](https://github.com/mkorman90/regipy) by Martin Korman — the REGF
  parsing backend HoneyJam builds upon.

## License

MIT © 2026 sltcnb. See [LICENSE](LICENSE).
