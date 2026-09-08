import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ulpf.agent_worker import AgentWorker
from ulpf.clustering import cluster_unrecognized_events, extract_structural_skeleton
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DEFAULT_PARSER_DIR, DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


# ---------------------------------------------------------------------------
# Module-level shared state (used by lifespan and endpoints)
# ---------------------------------------------------------------------------

_spool = DurableSpool(db_path="ulpf_spool.db")
_storage = NormalizedStorage(db_path="ulpf_storage.db")
_registry = DynamicParserRegistry(storage_dir=DEFAULT_PARSER_DIR)
_engine = DeterministicEngine(registry=_registry)
_coordinator = PipelineCoordinator(spool=_spool, engine=_engine, storage=_storage)
_worker = AgentWorker(
    spool=_spool,
    storage=_storage,
    registry=_registry,
    engine=_engine,
    poll_interval=2.0,
    batch_size=50,
)

# Background task handle
_worker_task: Optional[asyncio.Task] = None


# ---------------------------------------------------------------------------
# Lifespan — starts AgentWorker background daemon when uvicorn boots
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    """Start AgentWorker in background on startup; cancel cleanly on shutdown."""
    global _worker_task
    _worker_task = asyncio.create_task(_worker.run())
    yield
    # Shutdown
    _worker.stop()
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class LogPayload(BaseModel):
    logs: List[str]
    source_transport: str = "http_api"


# ---------------------------------------------------------------------------
# FastAPI App Factory
# ---------------------------------------------------------------------------

def create_app(coordinator: Optional[PipelineCoordinator] = None) -> FastAPI:
    """Create and configure the FastAPI ingestion + analytics service."""
    _coord = coordinator or _coordinator

    application = FastAPI(
        title="Universal Log Pre-processing Framework (ULPF)",
        version="0.2.0",
        description="Air-Gapped Sovereign Log Ingestion, Normalization & Analytics Service",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Ingestion Endpoints
    # ------------------------------------------------------------------

    @application.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_logs(payload: LogPayload):
        """Persist raw log batch to the durable spool (WAL-backed SQLite)."""
        if not payload.logs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Log payload list cannot be empty",
            )
        envelopes = []
        for log in payload.logs:
            if log.strip():
                env = _coord.ingest_raw_event(log, transport=payload.source_transport)
                envelopes.append({"event_id": env.event_id, "sha256": env.raw_sha256})
        return {
            "status": "spooled",
            "ingested_count": len(envelopes),
            "events": envelopes,
        }

    @application.post("/api/v1/process-batch")
    async def trigger_processing(batch_size: int = 100):
        """Synchronously run a deterministic parse cycle on the pending spool batch."""
        stats = _coord.process_pending_batch(batch_size=batch_size)
        return {"status": "success", "stats": stats}

    @application.get("/api/v1/events/{event_id}")
    async def get_event(event_id: str):
        """Fetch a single committed OCSF event by its unique ID."""
        record = _storage.get_event_by_id(event_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Committed event '{event_id}' not found",
            )
        return record

    # ------------------------------------------------------------------
    # Dashboard Analytics Endpoints
    # ------------------------------------------------------------------

    @application.get("/api/v1/metrics")
    async def get_metrics():
        """Real-time pipeline metrics: spool counts, worker telemetry, storage stats."""
        spool_counts = _spool.get_status_counts()
        total_spooled = _spool.get_total_count()
        storage_stats = _storage.get_stats()

        return {
            "spool": {
                "total": total_spooled,
                "by_status": spool_counts,
                "pending_ai": spool_counts.get("PENDING_AI", 0),
                "committed": spool_counts.get("COMMITTED", 0),
                "durably_stored": spool_counts.get("DURABLY_STORED", 0),
                "received": spool_counts.get("RECEIVED", 0),
            },
            "worker": {
                "is_running": _worker.is_running,
                "total_triaged": _worker.total_triaged,
                "total_clusters": _worker.total_clusters,
                "total_parsers_onboarded": _worker.total_parsers_onboarded,
                "total_committed": _worker.total_committed,
                "poll_interval": _worker.poll_interval,
                "batch_size": _worker.batch_size,
            },
            "storage": storage_stats,
        }

    @application.get("/api/v1/parsers")
    async def get_parsers():
        """List all active parser definitions: built-in and AI-synthesized dynamic parsers."""
        builtin_parsers = [
            {
                "parser_id": "builtin_cef_panos_v1",
                "parser_version": "1.0.0",
                "type": "builtin",
                "description": "Palo Alto Networks PAN-OS CEF format parser",
                "regex_pattern": r"CEF:\d+\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|",
                "field_mappings": {"src_ip": "src", "dst_ip": "dst", "proto": "proto", "action": "act"},
            },
            {
                "parser_id": "builtin_firewall_kv_v1",
                "parser_version": "1.0.0",
                "type": "builtin",
                "description": "Perimeter Firewall key-value log parser",
                "regex_pattern": r"src=(?P<src>[^\s]+)\s+dst=(?P<dst>[^\s]+)\s+spt=(?P<spt>\d+)",
                "field_mappings": {"src_ip": "src", "dst_ip": "dst", "proto": "proto", "action": "action"},
            },
            {
                "parser_id": "builtin_linux_auth_v1",
                "parser_version": "1.0.0",
                "type": "builtin",
                "description": "Linux SSH / auth syslog parser",
                "regex_pattern": r"sshd\[\d+\]:\s+(?P<message>Failed password|Accepted password|Invalid user)",
                "field_mappings": {"action": "message"},
            },
        ]

        dynamic_parsers = []
        for pid in _registry.list_parsers():
            defn = _registry.get_parser(pid)
            if defn:
                dynamic_parsers.append({
                    "parser_id": defn.parser_id,
                    "parser_version": defn.parser_version,
                    "type": "dynamic_ai",
                    "description": defn.description,
                    "regex_pattern": defn.regex_pattern,
                    "field_mappings": defn.field_mappings,
                })

        return {
            "total": len(builtin_parsers) + len(dynamic_parsers),
            "builtin": builtin_parsers,
            "dynamic_ai": dynamic_parsers,
        }

    @application.get("/api/v1/clusters")
    async def get_clusters():
        """Extract and return structural log skeletons from current PENDING_AI spool events."""
        pending_raw = _spool.get_recent_pending_ai(limit=200)
        if not pending_raw:
            return {"clusters": [], "total_pending_ai": 0}

        envelopes = [
            EventEnvelope(
                event_id=r["event_id"],
                raw_payload=r["raw_payload"],
                received_at=r["received_at"],
                status=EventStatus.PENDING_AI,
            )
            for r in pending_raw
        ]

        clusters = cluster_unrecognized_events(envelopes)

        return {
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "skeleton": c.skeleton,
                    "sample_count": c.sample_count,
                    "sample_logs": c.sample_logs[:3],  # send up to 3 samples to UI
                }
                for c in clusters
            ],
            "total_pending_ai": len(pending_raw),
        }

    @application.get("/api/v1/events")
    async def list_events(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        search: str = Query(default=""),
        disposition: str = Query(default=""),
    ):
        """Paginated, searchable OCSF Class 4001 analytical table query."""
        events = _storage.list_events(
            limit=limit,
            offset=offset,
            search=search,
            disposition_filter=disposition,
        )
        total = _storage.get_total_event_count(search=search, disposition_filter=disposition)

        # Parse ocsf_json field back to dict for rich API response
        for ev in events:
            if ev.get("ocsf_json"):
                try:
                    ev["ocsf"] = json.loads(ev["ocsf_json"])
                except Exception:
                    ev["ocsf"] = {}

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": events,
        }

    @application.get("/api/v1/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "ok",
            "version": "0.2.0",
            "worker_active": _worker.is_running,
        }

    return application


# ---------------------------------------------------------------------------
# Module-level app instance — enables: uvicorn ulpf.listener:app
# ---------------------------------------------------------------------------

app = create_app()


# ---------------------------------------------------------------------------
# UDP Syslog Listener (unchanged)
# ---------------------------------------------------------------------------

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asynchronous UDP socket listener for RFC syslog streams."""

    def __init__(self, coordinator: PipelineCoordinator):
        self.coordinator = coordinator

    def datagram_received(self, data: bytes, addr):
        try:
            payload = data.decode("utf-8", errors="replace").strip()
            if payload:
                self.coordinator.ingest_raw_event(payload, transport="syslog_udp")
        except Exception:
            pass  # Suppress transport-level drops


async def start_udp_syslog_server(
    coordinator: PipelineCoordinator,
    host: str = "0.0.0.0",
    port: int = 1514,
):
    """Start the asynchronous UDP Syslog listener on port 1514."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(coordinator),
        local_addr=(host, port),
    )
    return transport