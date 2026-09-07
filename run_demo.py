import hashlib
import inspect
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich import print as rprint
from rich.panel import Panel

from ulpf.agent_worker import AgentWorker
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

SPOOL_PATH = "live_demo_spool.db"
STORAGE_PATH = "live_demo_storage.db"
SAMPLE_FILE = "sample_logs.txt"


def safe_instantiate(cls, **kwargs):
    """Instantiate a class passing only parameters supported by its __init__ signature."""
    sig = inspect.signature(cls.__init__)
    valid_args = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return cls(**valid_args)


def make_envelope(line: str, transport: str = "file_stream") -> EventEnvelope:
    """Safely construct an EventEnvelope instance matching model requirements."""
    try:
        return EventEnvelope(raw_payload=line, source_transport=transport)
    except Exception:
        pass

    try:
        return EventEnvelope(raw_payload=line)
    except Exception:
        pass

    now_iso = datetime.now(timezone.utc).isoformat()
    sha = hashlib.sha256(line.encode("utf-8")).hexdigest()
    ev_id = f"ULPF-{uuid.uuid4().hex[:12]}"
    status = getattr(EventStatus, "PENDING_AI", "PENDING_AI")

    try:
        return EventEnvelope(
            event_id=ev_id,
            received_at=now_iso,
            raw_payload=line,
            raw_sha256=sha,
            source_transport=transport,
            status=status,
        )
    except Exception:
        return EventEnvelope(
            event_id=ev_id,
            received_at=now_iso,
            raw_payload=line,
            source_transport=transport,
            status=status,
        )


def main():
    rprint(Panel.fit("[bold green]ULPF Autonomous Control Plane Live Demonstration[/bold green]"))

    sample_path = Path(SAMPLE_FILE)
    if not sample_path.exists():
        rprint(f"[red]Error: '{SAMPLE_FILE}' not found. Please create it first.[/red]")
        sys.exit(1)

    # 1. Initialize Core Storage, Registry, and Engine Safely
    spool = safe_instantiate(DurableSpool, db_path=SPOOL_PATH)
    storage = safe_instantiate(NormalizedStorage, db_path=STORAGE_PATH)

    registry_sig = inspect.signature(DynamicParserRegistry.__init__)
    reg_kwargs = {}
    for candidate in ["storage_dir", "persistence_dir", "persist_dir", "directory", "save_dir", "parsers_dir"]:
        if candidate in registry_sig.parameters:
            reg_kwargs[candidate] = "ulpf/parsers/generated"
            break
    registry = DynamicParserRegistry(**reg_kwargs)

    engine = safe_instantiate(DeterministicEngine, registry=registry)

    # 2. Ingest Logs into Durable Spool as EventEnvelope instances
    with open(sample_path, "r", encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    rprint(f"\n[cyan]▶ Step 1: Ingesting {len(raw_lines)} logs from '{SAMPLE_FILE}'...[/cyan]")
    spooled_events = []
    for line in raw_lines:
        env = make_envelope(line, transport="file_stream")
        ret = spool.enqueue(env)
        actual_env = ret if isinstance(ret, EventEnvelope) else env
        spooled_events.append(actual_env)
    rprint(f"  [green]✓ Spooled {len(spooled_events)} events with SHA-256 integrity hashes.[/green]")

    # 3. Fast-Path Deterministic Engine
    rprint("\n[cyan]▶ Step 2: Running Deterministic Fast-Path Engine...[/cyan]")
    fast_path_hits = 0
    pending_ai_count = 0

    for env in spooled_events:
        success, processed = engine.parse_and_normalize(env)
        if success and processed.status == EventStatus.COMMITTED:
            storage.commit_event(processed)
            spool.update_status(processed.event_id, EventStatus.COMMITTED, parser_id=processed.parser_id)
            fast_path_hits += 1
            rprint(f"  [green]⚡ Deterministic Hit:[/green] Log {processed.event_id} parsed via [bold]{processed.parser_id}[/bold]")
        else:
            spool.update_status(env.event_id, EventStatus.PENDING_AI)
            pending_ai_count += 1
            rprint(f"  [yellow]⚠ Unrecognized Format:[/yellow] Log {env.event_id} queued for AI agent triage.")

    rprint(f"  Summary: [bold]{fast_path_hits}[/bold] deterministic hit(s) | [bold]{pending_ai_count}[/bold] routed to AI triage.")

    # 4. Autonomous AI Worker Triage
    rprint("\n[cyan]▶ Step 3: Triggering Offline Agentic AI Worker...[/cyan]")
    worker = safe_instantiate(AgentWorker, spool=spool, storage=storage, registry=registry, engine=engine)
    stats = worker.process_once()

    rprint(f"\n[bold green]✓ Pipeline Execution Complete![/bold green]")
    if isinstance(stats, dict):
        rprint(f"  • Triaged Logs       : {stats.get('triaged', 0)}")
        rprint(f"  • Structural Clusters: {stats.get('clusters_detected', 0)}")
        rprint(f"  • Onboarded Parsers  : {stats.get('onboarded_parsers', 0)}")
        rprint(f"  • Committed to OCSF  : {stats.get('committed', 0)}")


if __name__ == "__main__":
    main()