# Contributing to HoneyJam

Thanks for your interest in improving HoneyJam. Contributions of plugins, bug
fixes, tests and documentation are all welcome.

## Development setup

```bash
git clone https://github.com/sltcnb/HoneyJam
cd HoneyJam
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
```

## Before opening a pull request

- Run the test suite: `python -m pytest`
- Run the linter: `ruff check honeyjam tests`
- Add or update tests for any behaviour you change. Tests run fully offline
  against an in-memory fake hive (see `tests/conftest.py`), so no real registry
  hive is required.
- Keep commits focused and use [Conventional Commits](https://www.conventionalcommits.org/)
  style messages (e.g. `feat(cli): ...`, `fix(parser): ...`, `docs: ...`).

## Writing a plugin

1. Add a module under `honeyjam/plugins/`.
2. Subclass `honeyjam.plugins.Plugin` and set `name`, `description` and `hives`
   (the hive types it applies to, e.g. `["software", "ntuser"]`).
3. Implement `run(self, hive) -> PluginResult`, using the adapter in
   `honeyjam/parser/hive.py` rather than talking to `regipy` directly.
4. Emit `Finding` objects with a `severity`, `confidence` and, where relevant,
   `indicators`/`tags` so they flow into the malware detector, timeline and ECS
   exporters.

Plugins are auto-discovered at import time; modules whose name starts with `_`
are treated as internal helpers and skipped.

## Reporting bugs

Open an issue with the hive type, the command you ran and the full error
output. Please do not attach real hives that contain sensitive data.
