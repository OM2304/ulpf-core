import asyncio
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from ulpf.coordinator import PipelineCoordinator


class LogPayload(BaseModel):
    logs: List[str]
    source_transport: str = "http_api"


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asynchronous UDP socket listener for RFC syslog streams."""

    def __init__(self, coordinator: PipelineCoordinator):
        self.coordinator = coordinator

    def datagram_received(self, data: bytes, addr):
        try:
            payload = data.decode("utf-8", errors="replace").strip()
            if payload:
                # Durable ingestion: writes directly to WAL disk spool
                self.coordinator.ingest_raw_event(payload, transport="syslog_udp")
        except Exception:
            pass  # Suppress transport-level drops; corrupt frames will be handled in spool


def create_app(coordinator: PipelineCoordinator) -> FastAPI:
    """Create and configure the FastAPI ingestion service."""
    app = FastAPI(
        title="Universal Log Pre-processing Framework (ULPF)",
        version="0.1.0",
        description="Air-Gapped Sovereign Log Ingestion & Normalization Service"
    )

    @app.post("/api/v1/ingest", status_code=status.HTTP_202_ACCEPTED)
    async def ingest_logs(payload: LogPayload):
        if not payload.logs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Log payload list cannot be empty"
            )

        envelopes = []
        for log in payload.logs:
            if log.strip():
                env = coordinator.ingest_raw_event(log, transport=payload.source_transport)
                envelopes.append({"event_id": env.event_id, "sha256": env.raw_sha256})

        return {
            "status": "spooled",
            "ingested_count": len(envelopes),
            "events": envelopes
        }

    @app.post("/api/v1/process-batch")
    async def trigger_processing(batch_size: int = 100):
        stats = coordinator.process_pending_batch(batch_size=batch_size)
        return {"status": "success", "stats": stats}

    @app.get("/api/v1/events/{event_id}")
    async def get_event(event_id: str):
        record = coordinator.storage.get_event_by_id(event_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Committed event '{event_id}' not found"
            )
        return record

    return app


async def start_udp_syslog_server(
    coordinator: PipelineCoordinator,
    host: str = "0.0.0.0",
    port: int = 1514
):
    """Start the asynchronous UDP Syslog listener on port 1514 (non-root unprivileged port)."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(coordinator),
        local_addr=(host, port)
    )
    return transport