import asyncio
import os
import sys
import time
from typing import Dict, Optional
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel

from ulpf.agent import ParserSynthesisAgent
from ulpf.engine import DeterministicEngine
from ulpf.registry import DEFAULT_PARSER_DIR, DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

console = Console()


class AgentWorker:
    """Autonomous background daemon that continuously monitors the durable spool
    for PENDING_AI log records, clusters them by structure, synthesizes dynamic parsers,
    and commits normalized events without operator intervention.
    """

    def __init__(
        self,
        spool: Optional[DurableSpool] = None,
        storage: Optional[NormalizedStorage] = None,
        registry: Optional[DynamicParserRegistry] = None,
        engine: Optional[DeterministicEngine] = None,
        agent: Optional[ParserSynthesisAgent] = None,
        poll_interval: float = 1.0,
        batch_size: int = 50,
        model_name: str = "qwen2.5-coder:3b"
    ):
        self.spool = spool or DurableSpool(db_path="ulpf_spool.db")
        self.storage = storage or NormalizedStorage(db_path="ulpf_storage.db")
        self.registry = registry or DynamicParserRegistry(storage_dir=DEFAULT_PARSER_DIR)
        self.engine = engine or DeterministicEngine(registry=self.registry)
        self.agent = agent or ParserSynthesisAgent(
            registry=self.registry,
            spool=self.spool,
            model_name=model_name
        )
        self.poll_interval = poll_interval
        self.batch_size = batch_size

        self.is_running = False
        self._stop_event = asyncio.Event()

        # Telemetry metrics
        self.total_triaged = 0
        self.total_clusters = 0
        self.total_parsers_onboarded = 0
        self.total_committed = 0

    def process_once(self) -> Dict[str, int]:
        """Execute a single triage cycle across pending spool events."""
        stats = self.agent.triage_pending_spool(
            engine=self.engine,
            storage=self.storage,
            batch_size=self.batch_size
        )

        triaged = stats.get("triaged", 0)
        if triaged > 0:
            clusters = stats.get("clusters_detected", 0)
            onboarded = stats.get("onboarded_parsers", 0)
            committed = stats.get("committed", 0)

            self.total_triaged += triaged
            self.total_clusters += clusters
            self.total_parsers_onboarded += onboarded
            self.total_committed += committed

            rprint(
                f"[bold green]✓ Triage Cycle Complete:[/bold green] "
                f"Triaged [bold]{triaged}[/bold] events in [cyan]{clusters}[/cyan] cluster(s) | "
                f"Onboarded [magenta]{onboarded}[/magenta] new parser(s) | "
                f"Committed [green]{committed}[/green] OCSF events."
            )

        return stats

    async def run(self):
        """Asynchronous execution loop that continuously polls the spool."""
        self.is_running = True
        self._stop_event.clear()
        rprint(f"[bold cyan]🤖 Agent Worker Daemon Active[/bold cyan] (Poll Interval: {self.poll_interval}s, Batch Size: {self.batch_size})")

        try:
            while not self._stop_event.is_set():
                self.process_once()

                # Await either stop trigger or next poll interval
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        finally:
            self.is_running = False
            rprint("[yellow]Agent Worker loop terminated cleanly.[/yellow]")

    def stop(self):
        """Signal the worker loop to stop gracefully."""
        self._stop_event.set()


def main():
    """CLI entry point for running the background daemon as a standalone process."""
    console.rule("[bold magenta]ULPF: Autonomous Agent Worker Daemon[/bold magenta]")
    rprint("Starting background worker attached to local spool and Ollama runtime...")

    worker = AgentWorker(poll_interval=2.0, batch_size=50)

    try:
        asyncio.run(worker.run())
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!] Shutdown signal received. Stopping worker daemon...[/bold yellow]")
        worker.stop()
        rprint(
            f"[bold green]Session Summary:[/bold green] "
            f"Triaged: {worker.total_triaged} | "
            f"Parsers Created: {worker.total_parsers_onboarded} | "
            f"Committed: {worker.total_committed}"
        )


if __name__ == "__main__":
    main()