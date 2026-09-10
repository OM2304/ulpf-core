import asyncio
import contextlib
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ulpf.agent import global_agent_logs
from ulpf.agent_worker import AgentWorker
from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


logger = logging.getLogger(__name__)


class IngestRequest(BaseModel):
    payloads: List[str] = Field(min_length=1)
    transport: Optional[str] = "http_api"


class PathIngestRequest(BaseModel):
    path: str


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

    try:
        udp_transport = await start_udp_syslog_server(spool, host="0.0.0.0", port=5140)
    except OSError as exc:
        logger.warning("UDP syslog server could not bind to port 5140: %s", exc)
        udp_transport = None

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
        if udp_transport is not None:
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
        logger.exception("Ingestion failed while processing %d payload(s)", len(payload.payloads))
        raise HTTPException(status_code=500, detail=f"ingestion failed: {exc}") from exc
    return IngestResponse(
        ingested=len(event_ids),
        fast_path_committed=fast_path_committed,
        queued_for_ai=queued_for_ai,
        event_ids=event_ids,
    )


@app.post("/api/v1/ingest/path", status_code=201)
async def ingest_file_path(req: PathIngestRequest):
    spool, storage, _, engine, _ = _components(app)
    target_path = req.path.strip('"').strip("'")
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail=f"Log file not found at path: {target_path}")

    def process_file_sync():
        count = 0
        with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                payload = line.strip()
                if not payload:
                    continue
                envelope = EventEnvelope(raw_payload=payload, source_transport="web_upload")
                success, parsed = engine.parse_and_normalize(envelope)
                if success and parsed.status == EventStatus.COMMITTED:
                    storage.commit_event(parsed)
                    spool.spool(parsed)
                else:
                    parsed.status = EventStatus.PENDING_AI
                    spool.spool(parsed)
                count += 1
        return count

    ingested_count = await asyncio.to_thread(process_file_sync)
    return {"status": "success", "total_ingested": ingested_count, "path": target_path}


@app.get("/api/v1/console/logs")
async def get_console_logs() -> Dict[str, List[str]]:
    return {"logs": list(global_agent_logs)}


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


@app.get("/api/v1/spool/events")
async def spool_events(
    limit: int = Query(default=50, ge=1, le=500),
    status_filter: Optional[str] = Query(default=None, alias="status"),
) -> List[Dict[str, Any]]:
    spool, storage, _, _, _ = _components(app)
    query = """
        SELECT event_id, received_at, raw_sha256, raw_payload, status,
               parser_id, COALESCE(retry_count, 0) AS retry_count
        FROM spool_events
    """
    parameters: List[Any] = []
    if status_filter is not None:
        query += " WHERE status = ?"
        parameters.append(status_filter)
    query += " ORDER BY received_at DESC LIMIT ?"
    parameters.append(limit)
    try:
        with sqlite3.connect(spool.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, parameters).fetchall()
    except sqlite3.Error as exc:
        raise HTTPException(status_code=500, detail=f"spool query failed: {exc}") from exc

    # Normalized OCSF data is persisted in the analytical database rather than
    # the durable spool database. Fetch it for the committed spool rows so the
    # forensic spool view can display both representations of an event.
    ocsf_by_event_id: Dict[str, Any] = {}
    event_ids = [row["event_id"] for row in rows]
    if event_ids:
        placeholders = ",".join("?" for _ in event_ids)
        try:
            with sqlite3.connect(storage.db_path) as conn:
                normalized_rows = conn.execute(
                    f"SELECT event_id, ocsf_json FROM normalized_events WHERE event_id IN ({placeholders})",
                    event_ids,
                ).fetchall()
            for event_id, ocsf_json in normalized_rows:
                try:
                    ocsf_by_event_id[event_id] = json.loads(ocsf_json)
                except (TypeError, json.JSONDecodeError):
                    logger.warning("Invalid ocsf_json for event %s", event_id)
        except sqlite3.Error as exc:
            raise HTTPException(status_code=500, detail=f"normalized event query failed: {exc}") from exc

    return [
        {
            "event_id": str(row["event_id"]),
            "received_at": str(row["received_at"]),
            "raw_sha256": str(row["raw_sha256"]),
            "raw_payload": str(row["raw_payload"]),
            "status": str(row["status"]),
            "parser_id": row["parser_id"],
            "retry_count": int(row["retry_count"] or 0),
            "ocsf_json": ocsf_by_event_id.get(row["event_id"]),
        }
        for row in rows
    ]


@app.post("/api/v1/spool/retry/{event_id}")
async def retry_spool_event(event_id: str) -> Dict[str, str]:
    spool, _, _, _, _ = _components(app)
    if not spool.retry_event(event_id):
        raise HTTPException(status_code=404, detail=f"Spool event '{event_id}' not found")
    return {"event_id": event_id, "status": EventStatus.PENDING_AI.value}


@app.delete("/api/v1/spool/drop/{event_id}")
async def drop_spool_event(event_id: str) -> Dict[str, str]:
    spool, _, _, _, _ = _components(app)
    if not spool.delete_event(event_id):
        raise HTTPException(status_code=404, detail=f"Spool event '{event_id}' not found")
    return {"event_id": event_id, "status": "DROPPED"}


def _scan_parsers_dir(directory: str, parser_type: str) -> List[Dict[str, Any]]:
    parsers = []
    if not os.path.exists(directory):
        return parsers
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".json"):
            continue
        filepath = os.path.join(directory, fname)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["parser_type"] = parser_type
            data["origin"] = parser_type
            data["is_generated"] = (parser_type == "generated")
            data["deletable"] = (parser_type == "generated")
            data["read_only"] = (parser_type == "core")
            parsers.append(data)
        except Exception as exc:
            logger.warning("Failed to parse parser file %s: %s", filepath, exc)
    return parsers


@app.get("/api/v1/parsers")
async def list_parsers() -> List[Dict[str, Any]]:
    base_dir = os.path.dirname(__file__)
    core_dir = os.path.join(base_dir, "parsers", "core")
    generated_dir = os.path.join(base_dir, "parsers", "generated")

    core_parsers = _scan_parsers_dir(core_dir, "core")
    generated_parsers = _scan_parsers_dir(generated_dir, "generated")

    seen_ids = set()
    result = []
    for p in core_parsers + generated_parsers:
        pid = p.get("parser_id")
        if pid and pid not in seen_ids:
            seen_ids.add(pid)
            result.append(p)
    return result


@app.delete("/api/v1/parsers/{parser_id}")
async def delete_parser(parser_id: str):
    clean_id = parser_id.strip()
    if clean_id.endswith(".json"):
        clean_id = clean_id[:-5]

    base_dir = os.path.dirname(__file__)
    core_dir = os.path.join(base_dir, "parsers", "core")
    generated_dir = os.path.join(base_dir, "parsers", "generated")

    core_file = os.path.join(core_dir, f"{clean_id}.json")
    if os.path.exists(core_file):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Core parser '{clean_id}' is read-only and cannot be deleted."
        )

    gen_file = os.path.join(generated_dir, f"{clean_id}.json")
    if not os.path.exists(gen_file):
        matching_file = None
        if os.path.exists(generated_dir):
            for fname in os.listdir(generated_dir):
                if fname.lower() == f"{clean_id.lower()}.json" or fname.lower() == clean_id.lower():
                    matching_file = os.path.join(generated_dir, fname)
                    break
        if matching_file and os.path.exists(matching_file):
            gen_file = matching_file
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Generated parser '{clean_id}' not found."
            )

    try:
        os.remove(gen_file)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete parser file: {exc}"
        )

    try:
        _, _, registry, _, _ = _components(app)
        registry.remove_parser(clean_id, remove_from_disk=False)
    except Exception:
        pass

    return {
        "status": "success",
        "message": f"Generated parser '{clean_id}' successfully deleted.",
        "parser_id": clean_id,
    }


@app.get("/api/v1/events")
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    disposition: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _, storage, _, _, _ = _components(app)
    try:
        return storage.list_events(limit=limit, offset=offset, disposition=disposition)
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
