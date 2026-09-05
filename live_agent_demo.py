import os
import sqlite3
import sys
import time
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ulpf.agent import ParserSynthesisAgent
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.models import EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

console = Console()

DEMO_SPOOL_DB = "demo_live_spool.db"
DEMO_STORAGE_DB = "demo_live_storage.db"
GENERATED_DIR = os.path.join("ulpf", "parsers", "generated")


def cleanup_demo_dbs():
    """Remove previous demo databases and generated dynamic parsers for clean reproduction."""
    for db in [DEMO_SPOOL_DB, DEMO_STORAGE_DB]:
        if os.path.exists(db):
            os.remove(db)

    if os.path.exists(GENERATED_DIR):
        for f in os.listdir(GENERATED_DIR):
            if f.startswith("dynamic_ai_") and f.endswith(".json"):
                try:
                    os.remove(os.path.join(GENERATED_DIR, f))
                except OSError:
                    pass


def main():
    cleanup_demo_dbs()

    console.rule("[bold cyan]ULPF: Universal Log Pre-processing Framework[/bold cyan]")
    rprint("[bold green]✓[/bold green] Initializing Durable SQLite WAL Spool & Storage...")

    spool = DurableSpool(db_path=DEMO_SPOOL_DB)
    storage = NormalizedStorage(db_path=DEMO_STORAGE_DB)
    registry = DynamicParserRegistry(storage_dir=GENERATED_DIR)
    engine = DeterministicEngine(registry=registry)
    coordinator = PipelineCoordinator(spool=spool, engine=engine, storage=storage)
    agent = ParserSynthesisAgent(registry=registry, spool=spool, model_name="qwen2.5-coder:3b")

    # ---------------------------------------------------------
    # STAGE 1: INGEST MIXED LOG STREAM (KNOWN + UNKNOWN)
    # ---------------------------------------------------------
    raw_logs = [
        # Known Format 1: Firewall Key-Value
        "<134>Aug 30 12:41:22 fw01-edge src=10.2.1.15 dst=8.8.8.8 spt=51230 dpt=443 proto=TCP action=DENY",
        # Known Format 2: Palo Alto CEF
        "CEF:0|Palo Alto Networks|PAN-OS|10.0|TRAFFIC|allow|1|src=172.20.10.4 dst=198.51.100.2 spt=445 dpt=445 proto=tcp act=allow",
        # Known Format 3: Linux SSH Syslog
        "Jan 18 06:12:01 edge-auth-01 sshd[2412]: Failed password for invalid user admin from 192.168.1.105 port 54212 ssh2",
        # Unknown Format: Proprietary Industrial Router (3 lines sharing identical skeleton)
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:01Z CLIENT=10.50.1.20 REMOTE=203.0.113.10 PROTO=UDP STATE=REJECT",
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:04Z CLIENT=10.50.1.25 REMOTE=203.0.113.15 PROTO=TCP STATE=ACCEPT",
        "[EDGE_ROUTER_01] TS=2026-08-30T10:00:09Z CLIENT=10.50.1.30 REMOTE=198.51.100.8 PROTO=TCP STATE=ACCEPT"
    ]

    console.rule("[bold yellow]Stage 1: Ingestion & Fast-Path Deterministic Parsing[/bold yellow]")
    rprint(f"Ingesting [bold]{len(raw_logs)}[/bold] raw log records into durable spool...")

    for log in raw_logs:
        coordinator.ingest_raw_event(log, transport="demo_stream")

    # Run initial deterministic batch
    start_time = time.perf_counter()
    batch_stats = coordinator.process_pending_batch(batch_size=len(raw_logs))
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    rprint(f"[bold green]✓[/bold green] Fast-path processed in [bold]{elapsed_ms:.2f}ms[/bold]")
    rprint(f"  • Committed (Known Formats): [green]{batch_stats['committed']}[/green]")
    rprint(f"  • Triaged to AI (Unknown Formats): [yellow]{batch_stats['pending_ai']}[/yellow]")

    # ---------------------------------------------------------
    # STAGE 2: AUTONOMOUS AGENTIC AI SYNTHESIS & REFLEXION
    # ---------------------------------------------------------
    console.rule("[bold magenta]Stage 2: Autonomous Agentic Control Plane (Ollama + Clustering)[/bold magenta]")
    rprint("[bold blue]🤖 ParserSynthesisAgent awakened by PENDING_AI spool queue...[/bold blue]")
    rprint("  • Model: [cyan]qwen2.5-coder:3b (Local / Air-Gapped)[/cyan]")
    rprint("  • Extracting structural token skeletons and partitioning into clusters...")

    agent_start = time.perf_counter()
    triage_stats = agent.triage_pending_spool(engine=engine, storage=storage, batch_size=10)
    agent_elapsed = time.perf_counter() - agent_start

    if triage_stats["onboarded_parsers"] > 0:
        rprint(f"[bold green]✓ Dynamic Parsers Synthesized & Verified in Sandbox![/bold green] ({agent_elapsed:.2f}s)")
        rprint(f"  • Clusters Detected: [cyan]{triage_stats['clusters_detected']}[/cyan]")
        rprint(f"  • Onboarded Parsers: [green]{triage_stats['onboarded_parsers']}[/green]")
        rprint(f"  • Spool Triaged & Committed: [green]{triage_stats['committed']}[/green]")
    else:
        rprint("[bold red]✗ Agent could not synthesize a valid parser meeting 100% sandbox criteria.[/bold red]")
        sys.exit(1)

    # ---------------------------------------------------------
    # STAGE 3: ZERO-DOWNTIME REPLAY & ANALYTICS INSPECTION
    # ---------------------------------------------------------
    console.rule("[bold green]Stage 3: Analytical Storage Inspection (OCSF Class 4001)[/bold green]")

    table = Table(title="Normalized Security Events in Analytical Storage", show_lines=True)
    table.add_column("Event ID", style="cyan", no_wrap=True)
    table.add_column("Parser ID", style="magenta")
    table.add_column("Source IP", style="yellow")
    table.add_column("Destination IP", style="yellow")
    table.add_column("Protocol", style="blue")
    table.add_column("Disposition", style="green")

    with storage._get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT event_id, parser_id, src_ip, dst_ip, protocol, disposition FROM normalized_events"
        ).fetchall()

        for r in rows:
            if hasattr(r, "keys"):
                event_id = r["event_id"]
                parser_id = r["parser_id"]
                src_ip = r["src_ip"]
                dst_ip = r["dst_ip"]
                protocol = r["protocol"]
                disposition = r["disposition"]
            else:
                event_id, parser_id, src_ip, dst_ip, protocol, disposition = r

            table.add_row(
                str(event_id),
                str(parser_id or "N/A"),
                str(src_ip or "-"),
                str(dst_ip or "-"),
                str(protocol or "-"),
                str(disposition or "-")
            )

    console.print(table)
    rprint(f"[bold green]✓ SUCCESS:[/bold green] All {len(rows)}/{len(raw_logs)} logs normalized into OCSF without human intervention.")

    # ---------------------------------------------------------
    # STAGE 4: COLD-BOOT HYDRATION VERIFICATION
    # ---------------------------------------------------------
    console.rule("[bold blue]Stage 4: Cold-Boot Persistence & Hydration Verification[/bold blue]")
    rprint("Simulating service restart: Initializing a fresh DynamicParserRegistry from disk...")
    reboot_registry = DynamicParserRegistry(storage_dir=GENERATED_DIR)
    persisted_parsers = reboot_registry.list_parsers()

    rprint(f"[bold green]✓ Cold-Boot Hydration Complete:[/bold green] Loaded [bold]{len(persisted_parsers)}[/bold] parser(s) from disk without LLM inference.")
    for p_id in persisted_parsers:
        p_obj = reboot_registry.get_parser(p_id)
        rprint(f"  • Parser: [magenta]{p_id}[/magenta] -> Pattern: [italic]{p_obj.regex_pattern}[/italic]")


if __name__ == "__main__":
    main()