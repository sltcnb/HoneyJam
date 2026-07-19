"""HoneyJam command-line interface (click + rich)."""

from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from honeyjam import __version__
from honeyjam.analysis import malware_detector
from honeyjam.analysis.timeline import build_timeline
from honeyjam.export import ecs, report
from honeyjam.models import PluginResult, Severity
from honeyjam.parser.hive import open_hive
from honeyjam.plugins import (
    get_plugin,
    get_plugins,
    run_all,
)

console = Console()

_SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _sev_tag(sev: Severity) -> str:
    style = _SEV_STYLE.get(sev.value, "white")
    return f"[{style}]{sev.value.upper()}[/]"


def _open(path: str):
    try:
        return open_hive(path)
    except Exception as exc:
        console.print(f"[red]Failed to open hive:[/] {path}\n{exc}")
        raise SystemExit(2) from exc


def _collect_hives(target: str) -> list[str]:
    if os.path.isdir(target):
        files = []
        for root, _dirs, names in os.walk(target):
            for n in names:
                files.append(os.path.join(root, n))
        return files
    return [target]


def _print_results(results: list[PluginResult]) -> None:
    for res in results:
        if not res.findings and not res.errors:
            continue
        table = Table(
            title=f"{res.plugin}  ({res.hive_type})",
            title_style="bold #f5a623",
            expand=True,
            show_lines=False,
        )
        table.add_column("Sev", no_wrap=True)
        table.add_column("Conf", justify="right", no_wrap=True)
        table.add_column("Title", overflow="fold")
        table.add_column("Key", overflow="fold", style="dim")
        for f in res.findings:
            table.add_row(
                _sev_tag(f.severity),
                str(f.confidence),
                f.title,
                f.registry_key or "",
            )
        console.print(table)
        for err in res.errors:
            console.print(f"  [dim red]! {err}[/]")


@click.group()
@click.version_option(__version__, prog_name="honeyjam")
def cli() -> None:
    """HoneyJam - Windows Registry forensics toolkit (RegRipper successor)."""


# ---------------------------------------------------------------- parse
@cli.command()
@click.argument("hive", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON to stdout.")
@click.option("--ecs", "as_ecs", is_flag=True, help="Emit ECS JSON to stdout.")
@click.option("--ndjson", "as_ndjson", is_flag=True, help="Emit ECS newline-delimited JSON (NDJSON) to stdout.")
@click.option("--csv", "as_csv", is_flag=True, help="Emit CSV to stdout.")
@click.option("--html", type=click.Path(dir_okay=False), help="Write HTML report to path.")
def parse(hive, as_json, as_ecs, as_ndjson, as_csv, html):
    """Run all applicable plugins against a single HIVE."""
    h = _open(hive)
    machine = as_json or as_ecs or as_ndjson or as_csv
    if not machine:
        console.print(
            Panel.fit(
                f"[bold]{os.path.basename(hive)}[/]  type=[cyan]{h.hive_type}[/]",
                title="HoneyJam parse",
                border_style="#f5a623",
            )
        )
    results = run_all(h)

    if as_json:
        click.echo(report.to_json(results))
        return
    if as_ecs:
        click.echo(ecs.to_ecs_json(results))
        return
    if as_ndjson:
        click.echo(ecs.to_ndjson(results))
        return
    if as_csv:
        click.echo(report.to_csv(results))
        return

    _print_results(results)
    total = sum(r.count for r in results)
    console.print(f"\n[bold]{total}[/] findings across [bold]{len(results)}[/] plugins.")

    if html:
        with open(html, "w", encoding="utf-8") as fh:
            fh.write(report.to_html(results, target=hive))
        console.print(f"[green]HTML report written:[/] {html}")


# ---------------------------------------------------------------- detect
@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--severity",
    type=click.Choice(_SEV_ORDER),
    default="medium",
    help="Minimum severity to report.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def detect(target, severity, as_json):
    """Run malware/IOC detection on a HIVE or a DIRECTORY of hives."""
    min_rank = Severity(severity).rank
    all_detections = []
    for path in _collect_hives(target):
        try:
            h = open_hive(path)
        except Exception:
            continue
        results = run_all(h)
        dets = malware_detector.analyze_hive(h, results)
        for d in dets:
            if d.severity.rank >= min_rank:
                all_detections.append((path, d))

    if as_json:
        import json as _json

        click.echo(
            _json.dumps(
                [
                    {"hive": p, **d.model_dump(mode="json")}
                    for p, d in all_detections
                ],
                indent=2,
                default=str,
            )
        )
        return

    if not all_detections:
        console.print("[green]No detections at or above severity "
                      f"'{severity}'.[/]")
        return

    table = Table(title="HoneyJam detections", title_style="bold red", expand=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Conf", justify="right")
    table.add_column("Detection", overflow="fold")
    table.add_column("Hive", overflow="fold", style="dim")
    for path, d in sorted(all_detections, key=lambda x: -x[1].severity.rank):
        table.add_row(
            _sev_tag(d.severity),
            str(d.confidence),
            d.title,
            os.path.basename(path),
        )
    console.print(table)
    console.print(f"\n[bold red]{len(all_detections)}[/] detection(s).")


# ---------------------------------------------------------------- timeline
@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["ecs", "csv", "table"]),
    default="table",
)
def timeline(target, fmt):
    """Build a chronological timeline from a DIRECTORY (or single hive)."""
    results: list[PluginResult] = []
    for path in _collect_hives(target):
        try:
            h = open_hive(path)
        except Exception:
            continue
        results.extend(run_all(h))

    events = build_timeline(results)

    if fmt == "ecs":
        import json as _json

        click.echo(_json.dumps([e.to_dict() for e in events], indent=2, default=str))
        return
    if fmt == "csv":
        import csv as _csv
        import io as _io

        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["timestamp", "source", "severity", "description", "registry_key"])
        for e in events:
            w.writerow(
                [
                    e.timestamp.isoformat() if e.timestamp else "",
                    e.source,
                    e.severity.value,
                    e.description,
                    e.registry_key or "",
                ]
            )
        click.echo(buf.getvalue())
        return

    table = Table(title="HoneyJam timeline", title_style="bold #f5a623", expand=True)
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Event", overflow="fold")
    for e in events:
        table.add_row(
            e.timestamp.isoformat() if e.timestamp else "",
            e.source,
            _sev_tag(e.severity),
            e.description,
        )
    console.print(table)
    console.print(f"\n[bold]{len(events)}[/] timeline event(s).")


# ---------------------------------------------------------------- plugins
@cli.group()
def plugins():
    """Manage / list plugins."""


@plugins.command("list")
def plugins_list():
    """List all registered plugins."""
    table = Table(title="HoneyJam plugins", title_style="bold #f5a623", expand=True)
    table.add_column("Name", style="bold cyan", no_wrap=True)
    table.add_column("Hives", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for p in sorted(get_plugins(), key=lambda x: x.name):
        table.add_row(p.name, ", ".join(p.hives) or "all", p.description)
    console.print(table)
    console.print(f"\n[bold]{len(get_plugins())}[/] plugin(s) available.")


@cli.group()
def plugin():
    """Run a single plugin."""


@plugin.command("run")
@click.argument("name")
@click.option("--hive", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True)
def plugin_run(name, hive, as_json):
    """Run a single plugin by NAME against a hive."""
    p = get_plugin(name)
    if p is None:
        console.print(f"[red]Unknown plugin:[/] {name}")
        console.print("Available: " + ", ".join(sorted(x.name for x in get_plugins())))
        raise SystemExit(2)
    h = _open(hive)
    if not p.applies_to(h.hive_type):
        console.print(
            f"[yellow]Warning:[/] plugin '{name}' targets {p.hives}, "
            f"but hive is '{h.hive_type}'. Running anyway."
        )
    result = p.run(h)
    if as_json:
        click.echo(report.to_json([result]))
        return
    _print_results([result])
    console.print(f"\n[bold]{result.count}[/] finding(s).")


# ---------------------------------------------------------------- info
@cli.command()
def info():
    """Show HoneyJam version and environment info."""
    try:
        import regipy

        regipy_ver = getattr(regipy, "__version__", "installed")
    except Exception:
        regipy_ver = "not installed"

    body = (
        f"[bold #f5a623]HoneyJam[/] v{__version__}\n"
        "Windows Registry forensics toolkit\n"
        "Spiritual successor to RegRipper\n\n"
        f"[cyan]Parser backend:[/] regipy {regipy_ver}\n"
        f"[cyan]Plugins loaded:[/] {len(get_plugins())}\n"
        f"[cyan]Python:[/] {sys.version.split()[0]}\n"
        f"[cyan]Supported hive types:[/] system, software, ntuser, sam, security, amcache\n"
    )
    console.print(Panel(body, title="honeyjam info", border_style="#f5a623"))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Plugin", style="cyan")
    table.add_column("Hives")
    for p in sorted(get_plugins(), key=lambda x: x.name):
        table.add_row(p.name, ", ".join(p.hives) or "all")
    console.print(table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
