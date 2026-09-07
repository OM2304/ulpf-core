import json
import os
import sqlite3
from pathlib import Path

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
PARSERS_DIR = Path("ulpf/parsers/generated")
DB_STORAGE = "live_demo_storage.db"
DB_SPOOL = "live_demo_spool.db"


def show_parsers_table():
    table = Table(title="Generated Dynamic Parsers (Disk Registry)", header_style="bold cyan", border_style="dim")
    table.add_column("Parser ID", style="bold green")
    table.add_column("Regex Pattern", style="yellow")
    table.add_column("Mappings", style="magenta")

    if not PARSERS_DIR.exists() or not list(PARSERS_DIR.glob("*.json")):
        console.print(Panel("[dim]No dynamic parsers currently on disk.[/dim]", title="Dynamic Parsers"))
        return

    for p in PARSERS_DIR.glob("*.json"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                mappings_str = ", ".join([f"{k}→{v}" for k, v in data.get("field_mappings", {}).items()])
                table.add_row(data.get("parser_id", p.stem), data.get("regex_pattern", ""), mappings_str)
        except Exception as e:
            table.add_row(p.name, f"[red]Error: {e}[/red]", "")

    console.print(table)


def show_spool_table(limit: int = 6):
    if not os.path.exists(DB_SPOOL):
        return

    table = Table(title="Durable Spool Queue (`spool_events`)", header_style="bold blue", border_style="blue")
    table.add_column("Event ID", style="bold")
    table.add_column("SHA-256 (Forensic Hash)", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("Parser Bound", style="cyan")

    conn = sqlite3.connect(DB_SPOOL)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT event_id, raw_sha256, status, parser_id FROM spool_events ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        for r in rows:
            status_color = "green" if r["status"] == "COMMITTED" else "yellow"
            table.add_row(
                r["event_id"],
                f"{r['raw_sha256'][:16]}...",
                f"[{status_color}]{r['status']}[/{status_color}]",
                r["parser_id"] or "unassigned",
            )
        console.print(table)
    finally:
        conn.close()


def show_storage_table(limit: int = 6):
    if not os.path.exists(DB_STORAGE):
        console.print(Panel("[yellow]Storage database not found. Run demo first.[/yellow]"))
        return

    table = Table(title="OCSF Normalized Events (`normalized_events`)", header_style="bold green", border_style="green")
    table.add_column("Event ID", style="bold white")
    table.add_column("Parser", style="cyan")
    table.add_column("Source Endpoint", style="bright_yellow")
    table.add_column("Destination Endpoint", style="bright_cyan")
    table.add_column("Protocol", style="magenta")
    table.add_column("Action", style="white")
    table.add_column("Disposition", style="bold")

    conn = sqlite3.connect(DB_STORAGE)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT event_id, parser_id, src_ip, src_port, dst_ip, dst_port, protocol, action, disposition
            FROM normalized_events
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        if not rows:
            console.print(Panel("[dim]No normalized events found in database.[/dim]"))
            return

        for r in rows:
            src = f"{r['src_ip']}:{r['src_port']}" if r["src_port"] else str(r["src_ip"])
            dst = f"{r['dst_ip']}:{r['dst_port']}" if r["dst_port"] else str(r["dst_ip"])
            disp_style = "green" if r["disposition"] == "Allowed" else "red"
            table.add_row(
                r["event_id"],
                r["parser_id"],
                src,
                dst,
                r["protocol"] or "UNKNOWN",
                r["action"] or "-",
                f"[{disp_style}]{r['disposition']}[/{disp_style}]",
            )
        console.print(table)
    finally:
        conn.close()


if __name__ == "__main__":
    console.print()
    show_parsers_table()
    console.print()
    show_spool_table()
    console.print()
    show_storage_table()