# Universal Log Parsing Framework (ULPF) System Architecture

## 1. System Overview & Hybrid Pipeline Flow

The Universal Log Parsing Framework (ULPF) is a high-throughput, crash-resilient, hybrid log ingestion and normalization platform. It ingests raw telemetry, guarantees disk durability before processing, and normalizes heterogeneous log structures into standardized Open Cybersecurity Schema Framework (OCSF) events.

The architecture strictly decouples high-speed data-plane parsing from complex agentic AI analysis by employing a two-tier **Hybrid Pipeline**:

```
                                  [ Raw Log Ingestion ]
                     (HTTP /api/v1/ingest, Path Pump, UDP Syslog 5140)
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │   Forensic Staging / Spool      │
                           │     (SQLite WAL: ulpf_spool.db) │
                           │  - Computes SHA-256 Hash        │
                           │  - Stores Lossless Envelope     │
                           └────────────────┬────────────────┘
                                            │
                                            ▼
                        ┌───────────────────────────────────────┐
                        │   Deterministic Engine (Fast-Path)    │
                        │  - 6 Core Parsers (Apache, Nginx, etc)│
                        │  - Dynamic Parser Registry            │
                        └───────┬───────────────────────┬───────┘
                                │ Match                 │ No Match
                                ▼                       ▼
                 ┌───────────────────────────┐   ┌───────────────────────────┐
                 │    Normalized Storage     │   │  Spool: Status=PENDING_AI │
                 │ (SQLite: ulpf_storage.db) │   └─────────────┬─────────────┘
                 │  - OCSF JSON (3002/4001)  │                 │
                 │  - Fast Analytical Query  │                 ▼
                 └───────────────────────────┘   ┌───────────────────────────┐
                                                 │   Agent Worker (Daemon)   │
                                                 │  - Structural Clustering  │
                                                 │  - ChromaDB RAG Context   │
                                                 │  - Ollama LLM Synthesis   │
                                                 │  - ReDoS Sandbox Gate     │
                                                 └─────────────┬─────────────┘
                                                               │
                                               ┌───────────────┴───────────────┐
                                               ▼ Verified                      ▼ Rejected
                                 ┌───────────────────────────┐   ┌───────────────────────────┐
                                 │  Dynamic Parser Registry  │   │     Quarantine Logic      │
                                 │  - Hot-Loaded to Memory   │   │  - Max Retries >= 3       │
                                 │  - Persisted to JSON disk │   │  - Isolated Poison Pills  │
                                 │  - Spool Replayed & Saved │   └───────────────────────────┘
                                 └───────────────────────────┘
```

### 1.1 Ingestion Paths
1. **HTTP Batch Ingestion (`POST /api/v1/ingest`)**: High-speed JSON batch ingestion supporting payload arrays, non-empty validation, and transport provenance tracking.
2. **Path Ingestion (`POST /api/v1/ingest/path`)**: Asynchronous, non-blocking file streaming via `asyncio.to_thread` for rapid disk log ingestion without blocking the FastAPI event loop.
3. **UDP Syslog Listener (`0.0.0.0:5140`)**: Low-overhead asynchronous datagram transport receiving native RFC 3164 / RFC 5424 syslog streams.

### 1.2 Deterministic Fast-Path vs. AI-Driven Fallback
- **Deterministic Fast-Path (Sub-millisecond latency)**: Every incoming event envelope is evaluated against compiled regular expressions registered in the `DeterministicEngine` and `DynamicParserRegistry`. If matched, the record is immediately committed to normalized storage as OCSF JSON and marked `COMMITTED` in the spool.
- **AI-Driven Fallback / RAG Agentic Synthesis (Asynchronous background control plane)**: Unrecognized logs transition to `PENDING_AI`. The `AgentWorker` clusters unrecognized logs structurally via canonical token masking, queries local ChromaDB vector embeddings for structurally similar parsers (dynamic few-shot prompting), and prompts a local LLM (`qwen2.5-coder:3b`) to synthesize candidate regular expressions. Candidate patterns must pass ReDoS and coverage validation in an isolated sandbox before being hot-loaded into memory and replayed against the spool.

---

## 2. Data Plane & Parser Registry

The data plane coordinates the evaluation and lifecycle of deterministic regular expression parsers.

### 2.1 The 6 Core Parsers
The engine pre-seeds and maintains 6 enterprise-grade core parsers configured for zero-overhead execution:

| Parser ID | Category | Target Log Format | Normalized OCSF Class |
| :--- | :--- | :--- | :--- |
| `core_apache_web_v1` | `WEB` | Standard Apache Combined / Common access logs | **Class 4002** (HTTP Activity) |
| `core_nginx_web_v1` | `WEB` | High-volume Nginx web server access logs | **Class 4002** (HTTP Activity) |
| `core_pam_auth_v1` | `AUTHENTICATION` | Linux PAM / SSH authentication sessions | **Class 3002** (Authentication) |
| `core_iptables_net_v1` | `NETWORK` | Linux Netfilter / iptables kernel network events | **Class 4001** (Network Activity) |
| `core_aws_vpc_v1` | `NETWORK` | AWS VPC Flow logs version 2 | **Class 4001** (Network Activity) |
| `core_cisco_asa_v1` | `NETWORK` | Cisco ASA Firewall connection syslogs (%ASA-*) | **Class 4001** (Network Activity) |

### 2.2 Parser Storage & Hydration Architecture
Parsers are persisted and organized across dual disk directories:
- **Core Directory (`ulpf/parsers/core/*.json`)**: Immutable, read-only baseline parsers. Protected by the API from deletion (`403 Forbidden`).
- **Generated Directory (`ulpf/parsers/generated/*.json`)**: Dynamic AI-synthesized parsers validated by the sandbox gate and hot-loaded at runtime. Deletable by operators via the frontend UI or `DELETE /api/v1/parsers/{parser_id}`.

When `DynamicParserRegistry` initializes or upon daemon restart:
1. Core parsers are pre-seeded into memory.
2. The disk storage directory is scanned for JSON definitions.
3. Named regular expressions are compiled into memory (`re.compile`) for sub-millisecond execution.

### 2.3 ReDoS & Coverage Sandbox Validation
Before any AI-generated parser is allowed into the active registry, `SandboxValidator.validate_pattern` executes:
- **ReDoS Guard**: Evaluates execution time against sample logs with a strict 50.0ms timeout cutoff.
- **Coverage Gate**: Enforces 100% sample coverage across all logs in the target structural cluster.

---

## 3. Forensic Staging & Spool Manager

The durable spool (`ulpf_spool.db`) serves as the system's crash-recovery boundary and audit staging buffer.

### 3.1 Raw Telemetry Envelope & Immutability
Every incoming log string is wrapped inside an `EventEnvelope` (`ulpf/models.py`) containing:
- `event_id`: Unique identifier formatted as `ULPF-<12-hex-uuid>`.
- `received_at`: ISO 8601 UTC arrival timestamp.
- `source_transport`: Transport method (`http_api`, `syslog_udp`, `path_ingest`, `direct`).
- `raw_payload`: Unaltered, lossless raw log text.
- `raw_sha256`: Cryptographic SHA-256 fingerprint generated upon receipt.
- `status`: Lifecycle state (`DURABLY_STORED`, `COMMITTED`, `PENDING_AI`, `QUARANTINED`).
- `retry_count`: Incremental counter tracking triage iterations.
- `last_error`: Recorded validation or synthesis failure reason.

### 3.2 WAL-Mode SQLite Concurrency
The spool database operates with:
- `PRAGMA journal_mode=WAL;` (Write-Ahead Logging allowing concurrent readers and single writer).
- `PRAGMA busy_timeout=5000;` (5-second lock queue).
- `PRAGMA synchronous=NORMAL;` (Balanced disk synchronization ensuring integrity with high throughput).

### 3.3 Poison Pill Isolation & Quarantine Governance
To prevent malformed or adversarial log lines from inducing infinite LLM hallucination loops:
- When a cluster fails LLM synthesis or sandbox validation, the `AgentWorker` calls `spool.increment_retries(event_ids)`.
- If `retry_count >= 3`, the event is automatically transitioned to `QUARANTINED` status with `last_error` populated.
- Quarantined records are bypassed during standard triage polling loops, preserving system throughput.

### 3.4 Manual Operator Interventions
The backend and frontend provide dedicated triage governance routes:
- **Retry Triage (`POST /api/v1/spool/retry/{event_id}`)**: Resets `retry_count = 0`, clears `last_error`, and transitions the event back to `PENDING_AI` for re-evaluation.
- **Drop Event (`DELETE /api/v1/spool/drop/{event_id}`)**: Permanently purges unrecoverable records from the durable spool.

---

## 4. Normalized Analytical Storage

Normalized records are persisted separately in `ulpf_storage.db` (`NormalizedStorage`) to optimize analytical querying, compliance auditing, and forensic investigations.

### 4.1 Normalized Schema & Cryptographic Linkage
Committed events retain a direct cryptographic link back to their raw spool envelope:
```sql
CREATE TABLE normalized_events (
    event_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    source_transport TEXT NOT NULL,
    raw_payload TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    parser_id TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    action TEXT,
    disposition TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    ocsf_json TEXT NOT NULL
);
CREATE INDEX idx_norm_src_ip ON normalized_events(src_ip);
CREATE INDEX idx_norm_disposition ON normalized_events(disposition);
```

### 4.2 OCSF Schema Compliance
Normalized events adhere to Open Cybersecurity Schema Framework (OCSF) standards:
- **Class 4001 (Network Activity, Category 4)**: Maps network parameters, IP 5-tuples, protocols, and standard dispositions (`Allowed`, `Blocked`, `Unknown`).
- **Class 4002 (HTTP Activity, Category 4)**: Standardizes web requests (`GET`, `POST`), URL endpoints, client IP addresses, and HTTP status codes (e.g., 200, 404, 500).
- **Class 3002 (Authentication, Category 3)**: Normalizes user identity events, session actions, and auth statuses (`opened`, `closed`, `failed`, `success`).

---

## 5. Command Center UI (`frontend/`)

The React Command Center (built with Vite, React 19, Tailwind CSS, and Lucide icons) provides full real-time operational visibility and control.

### 5.1 Telemetry Dashboard (`src/pages/TelemetryDashboard.jsx`)
- **Metric Cards with Skeleton Loading**: Real-time counters for *Total Committed*, *Pending AI Triage*, *Quarantined*, and *Total WAL Spooled*. Features pulse skeleton loaders (`animate-pulse`) during initial fetch to eliminate zero-flashing on reload.
- **Dynamic Throughput Chart**: Live line chart rendered with Recharts plotting committed, pending AI, quarantined, and spool throughput over time.
- **Path Log Streamer**: Direct ingestion form with presets (`chaos_stream.log`, `sample_logs.txt`) and non-blocking asynchronous streaming.
- **Integrated Terminal Console**: VS Code-style terminal with internal auto-scrolling (`terminalContainerRef.scrollTop`), dual view modes (Standard UI Console vs. Verbose Backend Console streaming AI triage reasoning), and fullscreen toggle.

### 5.2 OCSF Events Explorer (`src/pages/OcsfEventsView.jsx`)
- **Real-Time Client-Side Filtering**: High-performance multi-field search (`searchQuery`) filtering across event ID, parser ID, raw payload, source/destination IPs, protocols, and stringified JSON.
- **Disposition Filtering**: Dropdown filter for `Allowed`, `Blocked`, and `Quarantined` activity.
- **Forensic Detail Modal / Accordion**: Expandable row displaying the raw SHA-256 hash with one-click copy, the exact raw log payload, and formatted normalized OCSF JSON.

### 5.3 Parser Registry (`src/pages/ParserRegistry.jsx`)
- **Core vs. Generated Separation**: Visual badges distinguishing read-only core parsers from dynamic AI-generated parsers.
- **Regex & Mapping Inspector**: Expandable card view showing compiled regex patterns and field-to-schema extraction mappings.
- **Operator Deletion**: Interactive delete capability for generated parsers with real-time UI state removal and backend synchronization.

### 5.4 Durable Spool Explorer (`src/pages/DurableSpoolView.jsx`)
- Complete audit view of raw payloads, cryptographic hashes, lifecycle status badges, and manual operator actions (*Retry Triage* and *Drop Event*).

---

## 6. Future Roadmap

### 6.1 Distributed Ingestion via Apache Kafka
- Transition from local UDP/HTTP ingestion to distributed, partitioned Kafka topics (e.g., `ulpf.logs.raw` and `ulpf.logs.normalized`).
- Deploy horizontally scalable consumer groups for the deterministic fast-path engine, maintaining SQLite WAL or partitioned analytical datastores (e.g., ClickHouse) as cold storage.

### 6.2 Full Containerization & Orchestration
- Production multi-stage `Dockerfile.backend` and `Dockerfile.frontend` linked via `docker-compose.yml`.
- Kubernetes Helm charts with dedicated deployments for the API listener, the agent worker daemon, and local or remote Ollama LLM inference nodes.
