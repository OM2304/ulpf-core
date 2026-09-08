import asyncio
import contextlib
import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ulpf.agent_worker import AgentWorker
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


class IngestRequest(BaseModel):
    payloads: List[str] = Field(min_length=1)
    transport: Optional[str] = "http_api"


class IngestResponse(BaseModel):
    ingested: int
    fast_path_committed: int
    queued_for_ai: int
    event_ids: List[str]


class MetricsResponse(BaseModel):
    spool_counts: Dict[str, int]
    total_spooled: int
    total_ocsf_committed: int
    active_parsers_count: int


class TriggerTriageResponse(BaseModel):
    triaged: int
    clusters_detected: int
    onboarded_parsers: int
    committed: int
    quarantined: int


def _decode_packet(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Receive UDP syslog frames and durably enqueue them."""

    def __init__(self, target: Any):
        self.target = target

    def datagram_received(self, data: bytes, addr: Any) -> None:
        payload = _decode_packet(data)
        if not payload:
            return
        try:
            if isinstance(self.target, DurableSpool):
                self.target.enqueue(EventEnvelope(raw_payload=payload, source_transport="syslog_udp"))
            else:
                self.target.ingest_raw_event(payload, transport="syslog_udp")
        except Exception:
            return


async def start_udp_syslog_server(
    target: Any,
    host: str = "0.0.0.0",
    port: int = 5140,
) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(target),
        local_addr=(host, port),
    )
    return transport


@asynccontextmanager
async def lifespan(app: FastAPI):
    spool = DurableSpool("ulpf_spool.db")
    storage = NormalizedStorage("ulpf_storage.db")
    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)
    worker = AgentWorker(spool=spool, storage=storage, registry=registry, engine=engine)

    app.state.spool = spool
    app.state.storage = storage
    app.state.registry = registry
    app.state.engine = engine
    app.state.worker = worker

    udp_transport = await start_udp_syslog_server(spool, host="0.0.0.0", port=5140)
    worker_task = asyncio.create_task(worker.run(), name="ulpf-agent-worker")
    app.state.udp_transport = udp_transport
    app.state.worker_task = worker_task
    try:
        yield
    finally:
        worker.stop()
        worker_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await worker_task
        udp_transport.close()


app = FastAPI(title="ULPF Agentic Daemon", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _components(request_app: FastAPI) -> Tuple[DurableSpool, NormalizedStorage, DynamicParserRegistry, DeterministicEngine, AgentWorker]:
    try:
        return (
            request_app.state.spool,
            request_app.state.storage,
            request_app.state.registry,
            request_app.state.engine,
            request_app.state.worker,
        )
    except AttributeError as exc:
        raise HTTPException(status_code=503, detail="ULPF daemon is not initialized") from exc


@app.post("/api/v1/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_logs(payload: IngestRequest) -> IngestResponse:
    spool, storage, _, engine, _ = _components(app)
    if any(not line.strip() for line in payload.payloads):
        raise HTTPException(status_code=400, detail="payloads must contain non-empty log lines")
    event_ids: List[str] = []
    fast_path_committed = 0
    queued_for_ai = 0
    try:
        for raw_payload in payload.payloads:
            envelope = EventEnvelope(raw_payload=raw_payload, source_transport=payload.transport or "http_api")
            spool.enqueue(envelope)
            matched, parsed_event = engine.parse_and_normalize(envelope)
            if matched and parsed_event.status == EventStatus.COMMITTED:
                if not storage.commit_event(parsed_event):
                    raise RuntimeError("normalized event commit failed")
                spool.update_status(parsed_event.event_id, EventStatus.COMMITTED, parser_id=parsed_event.parser_id)
                fast_path_committed += 1
            else:
                spool.update_status(envelope.event_id, EventStatus.PENDING_AI)
                queued_for_ai += 1
            event_ids.append(envelope.event_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ingestion failed: {exc}") from exc
    return IngestResponse(
        ingested=len(event_ids),
        fast_path_committed=fast_path_committed,
        queued_for_ai=queued_for_ai,
        event_ids=event_ids,
    )


def _query_spool_counts(db_path: str) -> Dict[str, int]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT status, count(*) FROM spool_events GROUP BY status").fetchall()
    return {str(status_name): int(count) for status_name, count in rows}


def _query_storage_count(db_path: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute("SELECT count(*) FROM normalized_events").fetchone()[0])


@app.get("/api/v1/spool/metrics", response_model=MetricsResponse)
async def spool_metrics() -> MetricsResponse:
    spool, storage, registry, _, _ = _components(app)
    try:
        spool_counts = _query_spool_counts(spool.db_path)
        total_ocsf = _query_storage_count(storage.db_path)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"metrics query failed: {exc}") from exc
    return MetricsResponse(
        spool_counts=spool_counts,
        total_spooled=sum(spool_counts.values()),
        total_ocsf_committed=total_ocsf,
        active_parsers_count=len(registry.list_parsers()),
    )


@app.get("/api/v1/parsers")
async def list_parsers() -> List[Dict[str, Any]]:
    _, _, registry, _, _ = _components(app)
    parsers: List[Dict[str, Any]] = []
    for parser_id in registry.list_parsers():
        definition = registry.get_parser(parser_id)
        if definition is None:
            continue
        parsers.append({
            "parser_id": definition.parser_id,
            "regex_pattern": definition.regex_pattern,
            "field_mappings": definition.field_mappings,
            "source_format": getattr(definition, "source_format", None),
            "origin": "autonomous_agent",
        })
    return parsers


@app.get("/api/v1/events")
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    disposition: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _, storage, _, _, _ = _components(app)
    query = "SELECT ocsf_json FROM normalized_events"
    parameters: List[Any] = []
    if disposition is not None:
        query += " WHERE disposition = ?"
        parameters.append(disposition)
    query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
    parameters.extend([limit, offset])
    try:
        with sqlite3.connect(storage.db_path) as conn:
            rows = conn.execute(query, parameters).fetchall()
        return [json.loads(row[0]) for row in rows]
    except (sqlite3.Error, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"event query failed: {exc}") from exc


@app.post("/api/v1/triage/trigger", response_model=TriggerTriageResponse)
async def trigger_triage() -> TriggerTriageResponse:
    _, _, _, _, worker = _components(app)
    try:
        result = await asyncio.to_thread(worker.process_once)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"triage failed: {exc}") from exc
    return TriggerTriageResponse(
        triaged=int(result.get("triaged", 0)),
        clusters_detected=int(result.get("clusters_detected", 0)),
        onboarded_parsers=int(result.get("onboarded_parsers", 0)),
        committed=int(result.get("committed", 0)),
        quarantined=int(result.get("quarantined", 0)),
    )


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "healthy", "service": "ulpf-daemon"}


def create_app(coordinator: PipelineCoordinator) -> FastAPI:
    """Build the pre-daemon coordinator API retained for older integrations."""
    legacy = FastAPI(title="Universal Log Pre-processing Framework", version="0.1.0")

    class LogPayload(BaseModel):
        logs: List[str]
        source_transport: str = "http_api"

    @legacy.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def legacy_ingest(payload: LogPayload):
        if not payload.logs:
            raise HTTPException(status_code=400, detail="Log payload list cannot be empty")
        events = [coordinator.ingest_raw_event(log, transport=payload.source_transport) for log in payload.logs if log.strip()]
        return {
            "status": "spooled",
            "ingested_count": len(events),
            "events": [{"event_id": event.event_id, "sha256": event.raw_sha256} for event in events],
        }

    @legacy.post("/api/v1/process-batch")
    async def legacy_process(batch_size: int = 100):
        return {"status": "success", "stats": coordinator.process_pending_batch(batch_size=batch_size)}

    @legacy.get("/api/v1/events/{event_id}")
    async def legacy_event(event_id: str):
        record = coordinator.storage.get_event_by_id(event_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Committed event '{event_id}' not found")
        return record

    return legacy


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ulpf.listener:app", host="0.0.0.0", port=8000, reload=False)
