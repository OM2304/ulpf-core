import hashlib
import inspect
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage
from ulpf.engine import DeterministicEngine
from ulpf.registry import DynamicParserRegistry
from ulpf.agent_worker import AgentWorker
from ulpf.models import EventEnvelope, EventStatus

console = Console()
SPOOL_PATH = "live_demo_spool.db"
STORAGE_PATH = "live_demo_storage.db"


def safe_instantiate(cls, **kwargs):
    sig = inspect.signature(cls.__init__)
    valid_args = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return cls(**valid_args)


def make_envelope(line: str) -> EventEnvelope:
    now_iso = datetime.now(timezone.utc).isoformat()
    sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
    ev_id = f"ULPF-{uuid.uuid4().hex[:12]}"
    return EventEnvelope(
        event_id=ev_id,
        received_at=now_iso,
        raw_payload=line,
        raw_sha256=sha,
        source_transport="interactive_cli",
        status=EventStatus.PENDING_AI,
    )


def verify_database_record(event_id: str):
    console.print(f"\n[bold green]▶ Direct Database Verification for ID: {event_id}[/bold green]")

    # 1. Verify Spool DB Entry
    conn_spool = sqlite3.connect(SPOOL_PATH)
    conn_spool.row_factory = sqlite3.Row
    spool_row = conn_spool.execute(
        "SELECT event_id, raw_sha256, status, parser_id, raw_payload FROM spool_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    conn_spool.close()

    if spool_row:
        t_spool = Table(title="1. Spool Verification (`spool_events`)", border_style="blue")
        t_spool.add_column("Field", style="bold cyan")
        t_spool.add_column("Value in SQLite", style="white")
        for k in ["event_id", "raw_sha256", "status", "parser_id", "raw_payload"]:
            t_spool.add_row(k, str(spool_row[k]))
        console.print(t_spool)

    # 2. Verify Normalized Storage DB Entry
    conn_storage = sqlite3.connect(STORAGE_PATH)
    conn_storage.row_factory = sqlite3.Row
    norm_row = conn_storage.execute(
        "SELECT event_id, parser_id, src_ip, src_port, dst_ip, dst_port, protocol, action, disposition FROM normalized_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    conn_storage.close()

    if norm_row:
        t_storage = Table(title="2. OCSF Analytical Storage (`normalized_events`)", border_style="green")
        t_storage.add_column("Field", style="bold green")
        t_storage.add_column("Value in SQLite", style="bright_yellow")
        for k in norm_row.keys():
            t_storage.add_row(k, str(norm_row[k]))
        console.print(t_storage)
    else:
        console.print("[red]Record not yet committed to normalized_events storage.[/red]")


def main():
    console.print(Panel.fit("[bold cyan]ULPF Interactive Single-Log Processor & DB Inspector[/bold cyan]"))

    default_sample = 'timestamp=2026-09-07T12:00:00Z device=FW-EXT src_ip=192.168.10.5 dst_ip=172.16.2.1 protocol=TCP action=DENY'
    console.print(f"[dim]Press ENTER to use default sample:[/dim] [italic]{default_sample}[/italic]\n")
    user_log = Prompt.ask("[bold yellow]Enter / Paste Log[/bold yellow]", default=default_sample).strip()

    spool = safe_instantiate(DurableSpool, db_path=SPOOL_PATH)
    storage = safe_instantiate(NormalizedStorage, db_path=STORAGE_PATH)
    registry = DynamicParserRegistry()
    engine = safe_instantiate(DeterministicEngine, registry=registry)

    # Ingest
    env = make_envelope(user_log)
    spool.enqueue(env)
    console.print(f"\n[green]✓ Ingested to Spool:[/green] ID={env.event_id} | SHA={env.raw_sha256[:12]}...")

    # Fast-Path Try
    success, processed = engine.parse_and_normalize(env)
    if success and processed.status == EventStatus.COMMITTED:
        storage.commit_event(processed)
        spool.update_status(processed.event_id, EventStatus.COMMITTED, parser_id=processed.parser_id)
        console.print(f"[green]⚡ Fast-Path Match:[/green] Parsed deterministically with [bold]{processed.parser_id}[/bold]")
    else:
        console.print("[yellow]⚠ Unrecognized Format:[/yellow] Routing to Agent Worker (Ollama Reflexion)...")
        worker = safe_instantiate(AgentWorker, spool=spool, storage=storage, registry=registry, engine=engine)
        worker.process_once()

    # Query and display the newly created DB record
    verify_database_record(env.event_id)


if __name__ == "__main__":
    main()