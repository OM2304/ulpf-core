# ULPF System Architecture

## 1. Architecture Scope and Evidence

- System analyzed:
  - Repository root: `C:\Users\ombat\ULPF`
  - Package: `ulpf`, version `0.1.0`
  - Runtime target: Python `>=3.10`
- Primary implementation surfaces:
  - `ulpf/listener.py`: FastAPI HTTP API and asynchronous UDP syslog listener.
  - `ulpf/coordinator.py`: synchronous pipeline orchestration.
  - `ulpf/engine.py`: deterministic parsing and normalization data plane.
  - `ulpf/registry.py`: in-memory and disk-backed dynamic parser registry.
  - `ulpf/spool.py`: durable raw-event queue implemented as SQLite.
  - `ulpf/storage.py`: normalized analytical and forensic storage implemented as SQLite.
  - `ulpf/agent.py`: local LLM parser-synthesis and reflection control plane.
  - `ulpf/agent_worker.py`: asynchronous polling daemon for `PENDING_AI` events.
  - `ulpf/clustering.py`: structural clustering of unknown log formats.
  - `ulpf/models.py`: Pydantic event and OCSF data contracts.
- Supporting surfaces:
  - `ulpf/parsers/generated/*.json`: persisted AI-generated parser definitions.
  - `live_agent_demo.py`: end-to-end demonstration of ingestion, deterministic parsing, AI synthesis, replay, and registry hydration.
  - `interactive_test.py`: terminal-driven single-event ingestion workflow.
  - `tests/*.py`: unit and integration coverage for the pipeline, listener, persistence, registry, agent, and worker.
- Architectural certainty:
  - The document distinguishes implemented behavior from deployment capabilities that are not represented in the repository.
  - No separate frontend application, API gateway, load balancer, cloud deployment manifest, Redis configuration, message-broker configuration, scheduler, webhook receiver, or remote SaaS integration was found.

## 2. High-Level System Overview

### 2.1 Logical Layers

- External log producers:
  - HTTP clients send batches of raw log strings to the ingestion API.
  - Syslog producers send UTF-8 UDP datagrams to the asynchronous syslog listener.
  - Direct Python callers and CLI/demo programs can call `PipelineCoordinator.ingest_raw_event` directly.
- Ingress and transport layer:
  - FastAPI application exposes versioned HTTP endpoints.
  - Uvicorn is the declared ASGI server dependency, but no production launch configuration is present.
  - `asyncio.DatagramProtocol` receives UDP syslog packets on port `1514` by default.
  - Transport adapters do minimal validation and immediately delegate to the coordinator.
- Durable ingestion layer:
  - `DurableSpool` creates an `EventEnvelope`, computes a SHA-256 hash, and persists raw payload plus metadata into SQLite.
  - SQLite Write-Ahead Logging is enabled for the spool database.
  - The spool is the system’s durable queue and crash-recovery boundary.
- Synchronous parsing and normalization data plane:
  - `PipelineCoordinator` fetches pending spool records in FIFO row order.
  - `DeterministicEngine` evaluates built-in parsers first and then the dynamic parser registry.
  - Successful matches produce an `OCSFNetworkActivity` object and transition the event to `COMMITTED`.
  - Unknown formats transition to `PENDING_AI`.
- Agentic control plane:
  - `AgentWorker` polls the spool for `PENDING_AI` events.
  - `clustering.py` groups unknown events by normalized structural skeleton and an eight-character SHA-256 fingerprint.
  - `ParserSynthesisAgent` sends samples to a local Ollama model, validates the returned parser, reflects on failures, and hot-loads successful definitions.
  - Newly registered parsers are persisted as JSON and then used to replay pending events.
- Normalized analytical and forensic storage layer:
  - `NormalizedStorage` stores committed raw payloads, hashes, parser provenance, selected network fields, and serialized OCSF JSON in SQLite.
  - SQLite indexes support source-IP and disposition lookups.
  - The HTTP event endpoint reads only from normalized storage.
- Local persistence and artifacts layer:
  - SQLite spool database stores raw events and lifecycle status.
  - SQLite normalized database stores committed records.
  - JSON parser files persist learned parser definitions across process restarts.
  - The in-memory registry stores compiled regular expressions for low-latency execution.
- Frontend layer:
  - No browser frontend, SPA, mobile client, server-rendered UI, or frontend source directory exists.
  - The only user-facing interfaces are the HTTP API and terminal-oriented demo/interactive programs.
- Cloud infrastructure layer:
  - No cloud provider SDKs, container manifests, Kubernetes resources, Terraform, serverless handlers, managed database configuration, load balancer configuration, or object storage configuration were found.
  - Deployment is therefore modeled as a local or on-premise process topology unless external infrastructure is added outside this repository.

### 2.2 Primary Technology Stack

- Language:
  - Python `>=3.10`.
- Data validation and domain models:
  - Pydantic `>=2.0` in `pyproject.toml`; `requirements.txt` pins a compatible `>=2.10.0` floor.
- HTTP and networking:
  - FastAPI for HTTP routing and request validation.
  - Uvicorn is the declared ASGI server.
  - `asyncio` provides UDP datagram handling and worker lifecycle control.
  - AnyIO and HTTPX are declared dependencies, but no direct application usage was found in the core package.
- Persistence:
  - Python standard-library `sqlite3`.
  - SQLite WAL journal mode with `synchronous=NORMAL` on both databases.
  - JSON files for dynamic parser definitions.
- Parsing and normalization:
  - Python `re` regular expressions.
  - Built-in patterns for Palo Alto CEF, firewall key-value logs, and Linux SSH/auth syslog.
  - OCSF Network Activity representation, class UID `4001`, category UID `4`.
- Local AI inference:
  - Optional `ollama` Python client.
  - Default model name: `qwen2.5-coder:3b`.
  - Inference is intended to target a local or air-gapped Ollama runtime.
- Terminal diagnostics:
  - Rich for demo, worker, and agent logging.
- Testing:
  - Pytest, FastAPI `TestClient`, AnyIO-compatible async tests, and temporary SQLite databases.
- Caching:
  - No Redis, Memcached, in-process result cache, or database query cache is implemented.
  - The dynamic parser registry is an in-memory compiled-regex cache with optional JSON persistence, not a general-purpose cache.
- Message queues:
  - No external message queue is used.
  - The SQLite `spool_events` table functions as a durable pull-based queue.
- Scheduling:
  - No cron or external scheduler is implemented.
  - The agent worker uses an `asyncio` polling loop with a configurable interval.

## 3. Deployment and Runtime Topology

### 3.1 Implemented Runtime Processes

- API/listener process, when assembled by an application or deployment wrapper:
  - Hosts FastAPI routes.
  - May also host the UDP syslog endpoint on the same event loop.
  - Uses a shared `PipelineCoordinator` and its injected spool, engine, and storage objects.
- Optional worker process:
  - Started through `ulpf/agent_worker.py` as a standalone Python process.
  - Owns a `DurableSpool`, `NormalizedStorage`, `DynamicParserRegistry`, `DeterministicEngine`, and `ParserSynthesisAgent` when dependencies are not injected.
  - Polls every `poll_interval` seconds; standalone default is two seconds and batch size is fifty.
- Demo/interactive process:
  - `live_agent_demo.py` runs all stages synchronously in one process with demonstration database names.
  - `interactive_test.py` runs a terminal loop and processes one event at a time.
- Test process:
  - Pytest creates isolated database files and in-memory/no-disk registries as fixtures.

### 3.2 Diagram-Ready Topology

- HTTP client -> FastAPI `POST /api/v1/ingest` -> `PipelineCoordinator` -> `DurableSpool` -> SQLite WAL spool database.
- UDP syslog producer -> `asyncio` UDP socket on `0.0.0.0:1514` -> `SyslogUDPProtocol` -> `PipelineCoordinator` -> `DurableSpool` -> SQLite WAL spool database.
- Manual processing caller -> FastAPI `POST /api/v1/process-batch` or direct coordinator call -> `DurableSpool.fetch_pending` -> `DeterministicEngine` -> `DynamicParserRegistry` -> `NormalizedStorage` and spool status update.
- Unknown event -> spool status `PENDING_AI` -> `AgentWorker` polling loop -> `ParserSynthesisAgent` -> structural clustering -> local Ollama -> sandbox validation -> parser registry and JSON artifact -> deterministic replay -> normalized SQLite storage.
- HTTP client -> FastAPI `GET /api/v1/events/{event_id}` -> `NormalizedStorage.get_event_by_id` -> normalized SQLite database -> JSON response.
- Process restart -> `DynamicParserRegistry` scans `ulpf/parsers/generated` -> parses JSON definitions -> compiles regexes -> hydrates in-memory registry.

### 3.3 Absent Infrastructure Components

- No load balancer is implemented or configured.
- No API gateway is implemented.
- No authentication or authorization middleware is implemented.
- No service discovery, container orchestration, autoscaling, health-check endpoint, metrics exporter, distributed tracing, or centralized logging backend is implemented.
- No replicated database, object store, data lake, or managed queue is implemented.
- The architecture is a modular monolith with an optional separately launched worker, not a collection of independently deployed microservices.

## 4. Component and Module Breakdown

### 4.1 Domain Contracts: `ulpf/models.py`

- `EventStatus`:
  - Enumerates `RECEIVED`, `DURABLY_STORED`, `PROCESSING`, `COMMITTED`, `PENDING_AI`, `RETRY`, and `QUARANTINED`.
  - Implemented runtime transitions use `RECEIVED` at model construction, `DURABLY_STORED` after spool persistence, `COMMITTED` after successful parsing, and `PENDING_AI` after a parser miss.
  - `PROCESSING`, `RETRY`, and `QUARANTINED` are declared contract states but are not actively driven by the current pipeline.
- `EventEnvelope`:
  - Lossless event wrapper containing generated event ID, UTC receipt timestamp, source transport, raw payload, SHA-256 hash, lifecycle status, parser identity/version, and optional normalized event.
  - Hash is computed automatically after model initialization when raw payload exists.
  - This is the correlation object carried through all pipeline stages.
- `OCSFNetworkActivity`:
  - Normalized network activity object.
  - Contains OCSF class/category identifiers, severity, action, disposition, source endpoint, destination endpoint, and connection information.
  - Endpoint and connection fields are flexible dictionaries, allowing the parser implementations to populate IPs, ports, and protocol names.

### 4.2 Ingress: `ulpf/listener.py`

- `LogPayload`:
  - Request model containing a list of raw log strings and a source transport label defaulting to `http_api`.
- `create_app(coordinator)`:
  - Builds the FastAPI application and closes over the injected coordinator.
  - Does not create its own persistence or parsing dependencies.
- `POST /api/v1/ingest`:
  - Validates that the log list is non-empty.
  - Ignores blank individual log entries.
  - Calls `coordinator.ingest_raw_event` for each nonblank log.
  - Returns HTTP `202` with spool status, ingested count, event IDs, and SHA-256 hashes.
  - Does not parse or normalize synchronously.
- `POST /api/v1/process-batch`:
  - Calls `coordinator.process_pending_batch` with a configurable batch size.
  - Runs parsing synchronously inside the request handler.
  - Returns processing counters.
- `GET /api/v1/events/{event_id}`:
  - Reads committed normalized storage by event ID.
  - Returns HTTP `404` when no normalized record exists.
  - Does not expose raw spool records or pending-event details.
- `SyslogUDPProtocol`:
  - Decodes datagrams as UTF-8 with replacement for invalid bytes.
  - Strips the payload and durably ingests nonempty frames with transport `syslog_udp`.
  - Suppresses transport-level exceptions, so malformed or failed frames are not returned to the sender.
- `start_udp_syslog_server`:
  - Creates an asyncio datagram endpoint.
  - Default bind is `0.0.0.0:1514`; tests use an ephemeral port.

### 4.3 Orchestration: `ulpf/coordinator.py`

- `PipelineCoordinator` is the central application service.
- Dependencies injected at construction:
  - `DurableSpool`.
  - `DeterministicEngine`.
  - `NormalizedStorage`.
- `ingest_raw_event`:
  - Delegates directly to `DurableSpool.persist_raw`.
  - Establishes the durable-before-parse guarantee.
- `process_pending_batch`:
  - Fetches up to `batch_size` records from the spool.
  - Calls the deterministic engine once per event.
  - Commits successful events to normalized storage, then updates spool status and parser ID.
  - Marks parser misses as `PENDING_AI`.
  - Returns `processed`, `committed`, and `pending_ai` counters.
- Internal dependencies:
  - Listener -> coordinator.
  - Coordinator -> spool.
  - Coordinator -> engine.
  - Coordinator -> normalized storage.

### 4.4 Deterministic Data Plane: `ulpf/engine.py`

- `DeterministicEngine` owns three built-in compiled regex families:
  - Palo Alto CEF logs.
  - Perimeter firewall key-value logs containing source, destination, ports, protocol, and action.
  - Linux SSH/auth syslog messages.
- Parser precedence:
  - CEF built-in parser.
  - Firewall key-value built-in parser.
  - Linux auth built-in parser.
  - Dynamic parser registry.
  - `PENDING_AI` fallback.
- Normalization behavior:
  - Extracts heterogeneous source/destination, port, protocol, and action fields.
  - Converts action terms such as deny, drop, reject, block, fail, or invalid to `Blocked`.
  - Converts allow, permit, accept, or pass terms to `Allowed`.
  - Maps all other values to `Unknown`.
  - Creates an OCSF network activity object and records parser ID/version.
- Success path:
  - Mutates envelope with `ocsf_event`, parser provenance, and `COMMITTED` status.
  - Returns `(success, envelope)`.
- Miss path:
  - Leaves the normalized event unset.
  - Sets status to `PENDING_AI`.
  - Returns `(false, envelope)`.
- Internal dependencies:
  - Engine -> domain models.
  - Engine -> dynamic parser registry.

### 4.5 Dynamic Parser Registry: `ulpf/registry.py`

- `ParserDefinition`:
  - Declarative parser ID and version.
  - Regular expression pattern.
  - Capture-group-to-semantic-field mappings for source IP, destination IP, protocol, and action.
- `SandboxValidator`:
  - Compiles candidate regular expressions.
  - Executes them against every provided sample.
  - Rejects patterns exceeding the 50 ms per-sample threshold.
  - Requires 100% sample coverage.
  - Returns validation reason and coverage.
- `DynamicParserRegistry`:
  - Stores parser definitions and compiled regex objects in `_parsers` memory.
  - Loads `.json` definitions from `ulpf/parsers/generated` at initialization.
  - Registers and hot-loads new definitions without a process restart.
  - Persists registered definitions as formatted JSON.
  - Can remove definitions from memory and disk.
  - Applies parsers in registry iteration order and stops at the first matching parser.
  - Constructs OCSF data from mapped capture groups and marks the envelope `COMMITTED`.
- Persistence behavior:
  - Default parser directory is `ulpf/parsers/generated` relative to the working directory.
  - The registry is not a database-backed shared service.
  - Multiple processes do not have an explicit cross-process registry invalidation or synchronization mechanism.
- Internal dependencies:
  - Registry -> domain models.
  - Registry -> filesystem JSON artifacts.
  - Engine -> registry.
  - Agent -> registry.

### 4.6 Unknown-Format Clustering: `ulpf/clustering.py`

- `extract_structural_skeleton`:
  - Replaces timestamps, IP/port values, MAC addresses, quoted strings, key-value values, protocols, actions, and standalone numbers with structural tokens.
  - Preserves delimiters and structural keys to distinguish log families.
- `compute_skeleton_fingerprint`:
  - Computes an eight-character SHA-256 prefix over the skeleton.
- `LogCluster`:
  - Ephemeral Pydantic grouping containing cluster ID, skeleton, sample count, up to five raw sample logs, and event envelopes.
- `cluster_unrecognized_events`:
  - Groups events by identical skeleton fingerprint.
  - Selects up to five samples per cluster for LLM synthesis.
  - Sorts clusters by descending sample count.
- Internal dependencies:
  - Clustering -> `EventEnvelope`.
  - Agent -> clustering.

### 4.7 Agentic Control Plane: `ulpf/agent.py`

- `ParserSynthesisAgent` responsibilities:
  - Build a structured prompt containing sample logs and extraction requirements.
  - Call the local LLM through an injectable callable.
  - Parse and sanitize model output into a JSON-like parser definition.
  - Retry failed candidates through a reflection prompt.
  - Validate syntax, named capture groups, regex safety, sample coverage, and IP extraction semantics.
  - Register valid parsers into the live registry.
  - Query and triage pending AI events.
- Default external boundary:
  - Imports the `ollama` client lazily.
  - Calls `ollama.generate` with the configured model, prompt, and temperature `0.0`.
  - The expected model is local `qwen2.5-coder:3b`.
- Synthesis lifecycle:
  - Cluster samples -> build initial prompt -> call model -> extract JSON -> compile regex -> verify capture groups -> run sandbox -> verify IP semantics -> register parser.
  - On failure -> build reflection prompt containing prior pattern and validation error -> repeat up to three attempts.
  - On exhaustion -> return no parser; events remain pending for later handling.
- Pending-event lifecycle:
  - Query `spool_events` where status is exactly `PENDING_AI` in FIFO row order.
  - Rehydrate envelopes from rows.
  - Cluster events.
  - Re-run the deterministic engine against each cluster event to detect whether a prior parser now handles it.
  - Synthesize one parser per still-unhandled cluster.
  - Re-run parsing for unhandled events after registration.
  - Commit successful normalized records and update spool status/parser ID.
- Internal dependencies:
  - Agent -> clustering.
  - Agent -> registry.
  - Agent -> spool.
  - Agent -> normalized storage.
  - Agent -> deterministic engine through the triage method.
  - Agent -> local Ollama runtime.

### 4.8 Background Worker: `ulpf/agent_worker.py`

- `AgentWorker` composes the spool, storage, registry, engine, and agent.
- `process_once`:
  - Executes one `triage_pending_spool` cycle.
  - Aggregates session counters for triaged events, clusters, onboarded parsers, and committed events.
- `run`:
  - Sets `is_running`.
  - Repeats `process_once` until an asyncio stop event is set.
  - Waits for either the stop event or the polling timeout.
  - Handles cancellation and marks the worker stopped in a finally block.
- `stop`:
  - Signals the event loop to exit gracefully.
- Default standalone dependencies and paths:
  - Spool database: `ulpf_spool.db`.
  - Normalized database: `ulpf_storage.db`.
  - Parser directory: `ulpf/parsers/generated`.
  - Note: `NormalizedStorage` itself defaults to `ulpf_analytics.db`; the worker explicitly uses the different `ulpf_storage.db` filename.
- The worker is an asynchronous polling daemon, not a broker consumer and not a cron job.

### 4.9 Persistence: `ulpf/spool.py`

- `DurableSpool` responsibilities:
  - Initialize the spool schema.
  - Create event envelopes and hashes.
  - Persist raw events before parsing.
  - Fetch pending events in FIFO row order.
  - Update lifecycle status and parser association.
- Database table:
  - `spool_events`.
- Queue semantics:
  - Durable pull queue backed by a single SQLite file.
  - `INSERT OR REPLACE` supports re-spooling/updating the same event ID.
  - No visibility timeout, claim token, worker lease, dead-letter table, or explicit retry counter exists.
- Compatibility aliases:
  - `enqueue`, `insert_event`, and `insert_pending` all delegate to `spool`.
- Query behavior:
  - `fetch_pending` selects `RECEIVED`, `DURABLY_STORED`, and literal `PENDING` statuses.
  - The agent’s own triage query selects `PENDING_AI` directly.
  - Therefore, the normal coordinator processes newly durable events, while the worker drains AI-designated events.

### 4.10 Normalized Storage: `ulpf/storage.py`

- `NormalizedStorage` responsibilities:
  - Initialize the normalized event table and indexes.
  - Reject envelopes that are not `COMMITTED` or lack an OCSF object.
  - Persist raw and normalized data together for forensic traceability.
  - Retrieve a committed record by event ID.
- Database table:
  - `normalized_events`.
- Stored data categories:
  - Event identity and receipt metadata.
  - Source transport.
  - Original raw payload and raw SHA-256.
  - Parser ID and parser version.
  - Denormalized action, disposition, source IP/port, destination IP/port, and protocol.
  - Complete serialized OCSF JSON.
- Query support:
  - Primary-key lookup by `event_id`.
  - Index on `src_ip`.
  - Index on `disposition`.
- Internal dependencies:
  - Storage -> SQLite.
  - Storage -> domain models.
  - Listener -> storage through coordinator-owned dependency.
  - Coordinator/agent -> storage.

### 4.11 Demonstration and Test Modules

- `live_agent_demo.py`:
  - Builds the full dependency graph manually.
  - Uses `demo_live_spool.db` and `demo_live_storage.db`.
  - Ingests known and unknown formats.
  - Runs deterministic processing, agent synthesis, analytical inspection, and cold-boot registry hydration.
  - Deletes demonstration databases and generated `dynamic_ai_*.json` files at startup.
- `interactive_test.py`:
  - Uses `live_demo_spool.db` and `live_demo_analytics.db`.
  - Reads one raw log line at a time from stdin.
  - Shows durable event ID/hash, then either normalized fields or `PENDING_AI` status.
- `tests/`:
  - Tests domain hash generation and OCSF assignment.
  - Tests all built-in parser families and unknown-format routing.
  - Tests spool persistence, status updates, and restart recovery.
  - Tests normalized storage acceptance/rejection.
  - Tests registry sandbox validation, hot reload, and disk persistence.
  - Tests HTTP batch ingestion, batch processing, event retrieval, and UDP ingestion.
  - Tests clustering, agent synthesis/reflection, and worker polling lifecycle.

## 5. Internal Dependency Map

- `listener.py` -> `coordinator.py`.
- `coordinator.py` -> `spool.py`, `engine.py`, `storage.py`, `models.py`.
- `engine.py` -> `models.py`, `registry.py`.
- `registry.py` -> `models.py`, local JSON parser artifacts.
- `agent.py` -> `clustering.py`, `models.py`, `registry.py`, `spool.py`, local Ollama client.
- `agent_worker.py` -> `agent.py`, `engine.py`, `registry.py`, `spool.py`, `storage.py`.
- `clustering.py` -> `models.py`.
- `spool.py` -> `models.py`, SQLite filesystem.
- `storage.py` -> `models.py`, SQLite filesystem.
- `live_agent_demo.py` -> agent, coordinator, engine, models, registry, spool, storage, Rich, SQLite.
- `interactive_test.py` -> coordinator, engine, spool, storage.
- Domain model direction:
  - Transport adapters depend on application orchestration.
  - Orchestration depends on domain services and persistence ports implemented by concrete SQLite classes.
  - Parsing services depend on the shared event models.
  - The agent depends on the deterministic data plane for validation/replay.

## 6. Request and Data Flow Lifecycles

### 6.1 HTTP Ingestion

- HTTP client -> `POST /api/v1/ingest`.
- FastAPI validates the request into `LogPayload`.
- For each nonblank log:
  - `LogPayload.logs[i]` -> `PipelineCoordinator.ingest_raw_event`.
  - Coordinator -> `DurableSpool.persist_raw`.
  - Spool -> `EventEnvelope` creation.
  - Envelope -> SHA-256 calculation over UTF-8 raw payload.
  - Envelope with `DURABLY_STORED` status -> SQLite `spool_events` insert/replace.
- FastAPI -> HTTP `202` response containing event IDs and hashes.
- No deterministic parsing, AI inference, or normalized-storage write occurs on this endpoint.

### 6.2 UDP Syslog Ingestion

- Syslog device -> UDP packet -> asyncio datagram endpoint.
- `SyslogUDPProtocol.datagram_received` -> UTF-8 decode with replacement -> trim.
- Nonempty payload -> `PipelineCoordinator.ingest_raw_event` with `syslog_udp` transport.
- Coordinator -> spool persistence -> SQLite WAL commit.
- The UDP handler does not parse the event or send an acknowledgment to the source.
- Decode/ingest exceptions are swallowed at the protocol boundary.

### 6.3 Synchronous Deterministic Batch Processing

- Caller -> `POST /api/v1/process-batch` or direct `PipelineCoordinator.process_pending_batch`.
- Coordinator -> `DurableSpool.fetch_pending(limit=batch_size)`.
- Spool -> select statuses `RECEIVED`, `DURABLY_STORED`, or `PENDING` -> FIFO rows -> rehydrated envelopes.
- For each envelope -> `DeterministicEngine.parse_and_normalize`.
- Parser decision chain:
  - CEF pattern match -> extract extension fields -> normalize action/disposition -> OCSF object.
  - Else firewall key-value match -> extract IPs/ports/protocol/action -> OCSF object.
  - Else Linux SSH/auth match -> infer source IP/port and local SSH destination -> OCSF object.
  - Else dynamic registry scan -> first matching compiled parser -> mapped OCSF object.
  - Else set `PENDING_AI` and return failure.
- Successful branch:
  - Parsed envelope -> `NormalizedStorage.commit_event` -> `normalized_events` SQLite insert/replace.
  - After storage call -> `DurableSpool.update_status(COMMITTED, parser_id)`.
  - Counters -> `committed += 1`.
- Unknown branch:
  - Envelope -> `DurableSpool.update_status(PENDING_AI)`.
  - Counters -> `pending_ai += 1`.
- Coordinator -> response containing processed, committed, and pending-AI counts.

### 6.4 Background AI Triage and Parser Onboarding

- `AgentWorker.run` -> periodic timeout loop -> `AgentWorker.process_once`.
- Worker -> `ParserSynthesisAgent.triage_pending_spool`.
- Agent -> direct SQLite query for `spool_events.status = 'PENDING_AI'` -> FIFO rows limited by batch size.
- Rows -> rehydrated `EventEnvelope` objects.
- Envelopes -> structural skeleton extraction:
  - Mask dynamic timestamps, network addresses, MACs, quoted strings, key-value values, protocols, action words, and numbers.
  - Hash skeleton -> cluster ID.
- Events -> `LogCluster` groups sorted by largest cluster first.
- For each cluster:
  - Cluster events -> deterministic engine replay against existing built-in and dynamic parsers.
  - Already handled events -> normalized storage commit -> spool `COMMITTED` update.
  - Still-unhandled events -> select up to five sample logs.
  - Samples -> `ParserSynthesisAgent.build_prompt`.
  - Prompt -> injected LLM caller or local `ollama.generate`.
  - LLM response -> JSON extraction and sanitization.
  - Candidate -> regex compilation check.
  - Candidate -> named-group mapping check.
  - Candidate -> 50 ms/sample sandbox and 100% coverage check.
  - Candidate -> sample extraction and source/destination IP semantic validation.
  - Failed candidate -> reflection prompt with prior pattern and failure reason -> next attempt, up to three attempts.
  - Valid candidate -> `ParserDefinition` -> registry hot-load -> JSON persistence.
  - Newly registered parser -> replay all previously unhandled cluster events.
  - Successful replays -> normalized storage commit -> spool `COMMITTED` update with parser ID.
- Worker -> accumulated telemetry counters and terminal diagnostics.
- No event emitter or external queue participates in this flow.

### 6.5 Normalized Event Query

- HTTP client -> `GET /api/v1/events/{event_id}`.
- FastAPI route -> coordinator-owned `NormalizedStorage`.
- Storage -> `SELECT * FROM normalized_events WHERE event_id = ?`.
- Found row -> dictionary -> HTTP JSON response.
- Missing row -> HTTP `404`.
- Pending, quarantined, or raw-spool-only events are not returned by this endpoint.

### 6.6 Parser Persistence and Cold-Boot Hydration

- New valid parser -> `DynamicParserRegistry.register`.
- Registry -> compile regex -> store in memory.
- Registry -> serialize `ParserDefinition` -> `ulpf/parsers/generated/<parser_id>.json`.
- New process -> registry initialization -> scan `.json` files -> parse Pydantic definitions -> compile patterns -> populate in-memory registry.
- Hydrated parser -> available to the deterministic engine without another LLM call.

## 7. Database, Storage, and Data Models

### 7.1 Spool Database: `spool_events`

- Storage technology:
  - SQLite file, default `ulpf_spool.db` in `DurableSpool`.
  - WAL journal mode.
  - `synchronous=NORMAL`.
- Fields:
  - `event_id`: primary key and logical event correlation ID.
  - `received_at`: required timestamp string.
  - `raw_sha256`: required content hash.
  - `raw_payload`: required lossless raw log text.
  - `status`: lifecycle state string.
  - `parser_id`: optional parser provenance.
  - `source_transport`: transport label, default `direct`.
- Operational role:
  - Durable ingress buffer.
  - Recovery source after process restart.
  - Work queue for deterministic processing and AI triage.
- Relationships:
  - One spool event maps conceptually to zero or one normalized event record by `event_id`.
  - The schema does not declare a SQL foreign key.
  - One parser ID can be associated with many spool events.

### 7.2 Normalized Database: `normalized_events`

- Storage technology:
  - SQLite file, default `ulpf_analytics.db` for `NormalizedStorage`.
  - `AgentWorker` explicitly defaults to `ulpf_storage.db` when it constructs storage itself.
  - WAL journal mode and `synchronous=NORMAL`.
- Fields:
  - Identity and provenance:
    - `event_id`: primary key.
    - `received_at`.
    - `source_transport`.
    - `parser_id`.
    - `parser_version`.
  - Forensic linkage:
    - `raw_payload`.
    - `raw_sha256`.
  - Denormalized network fields:
    - `action`.
    - `disposition`.
    - `src_ip`, `src_port`.
    - `dst_ip`, `dst_port`.
    - `protocol`.
  - Complete normalized object:
    - `ocsf_json` containing serialized `OCSFNetworkActivity`.
- Indexes:
  - `idx_norm_src_ip` on `src_ip`.
  - `idx_norm_disposition` on `disposition`.
- Relationships:
  - One normalized row corresponds to one committed event envelope.
  - One parser definition can produce many normalized rows through its parser ID.
  - No separate parser table or relational constraint exists.

### 7.3 In-Memory and File-Based State

- Event state:
  - Lifecycle state is authoritative in `spool_events.status` after ingestion.
  - The in-memory envelope mirrors the state during a processing call.
- Parser state:
  - Active compiled parser state is held in `DynamicParserRegistry._parsers`.
  - Durable parser state is held in generated JSON files.
- Worker state:
  - `is_running`, stop event, and cumulative counters are process-local.
- Cluster state:
  - `LogCluster` objects exist only during a triage cycle.
- No external cache sits in front of either SQLite database.

### 7.4 Entity and Cardinality Map

- `EventEnvelope` 1:0..1 `OCSFNetworkActivity`:
  - Zero normalized object while received, durable, or pending AI.
  - One normalized object after a successful parser.
- `spool_events` 1:0..1 `normalized_events`:
  - Conceptual relation through `event_id`.
  - Not enforced by a foreign key.
- `ParserDefinition` 1:N `EventEnvelope`:
  - One parser can be selected for many events.
  - Implemented as a copied `parser_id` string rather than a normalized relation.
- `LogCluster` 1:N `EventEnvelope`:
  - Ephemeral grouping for one AI triage cycle.
- `EventEnvelope` N:1 `source_transport` value:
  - Many events can share labels such as `http_api`, `syslog_udp`, `direct`, or `demo_stream`.
- There are no implemented N:M relationships, user entities, tenant entities, account entities, payment entities, or external identity entities.

## 8. External Integrations and APIs

### 8.1 Local Ollama Inference Runtime

- Integration owner:
  - `ParserSynthesisAgent._default_ollama_caller`.
- Interaction:
  - Python `ollama` client -> local Ollama generation endpoint/runtime.
  - Model defaults to `qwen2.5-coder:3b`.
  - Prompt contains up to five structurally homogeneous raw logs and parser-generation constraints.
  - Response is expected to contain a JSON parser definition.
- Failure behavior:
  - Client or inference exceptions are raised as a runtime error.
  - Invalid model output is reflected and retried up to three attempts.
- Network boundary:
  - Intended to be local/air-gapped.
  - No hosted LLM provider, API key, remote URL, webhook, or cloud AI service is configured in the repository.

### 8.2 HTTP Ingestion API

- This is a system-provided API rather than a third-party integration.
- Routes:
  - `POST /api/v1/ingest` for batch raw-log ingestion.
  - `POST /api/v1/process-batch` for synchronous processing trigger.
  - `GET /api/v1/events/{event_id}` for committed event retrieval.
- Contract:
  - JSON request validation through Pydantic.
  - Ingest returns HTTP `202`; processing and retrieval return normal success responses.
- No auth, rate limiting, signature verification, API-key middleware, or webhook verification is present.

### 8.3 UDP Syslog Interface

- This is a protocol boundary with external log-producing devices.
- Default listener:
  - UDP host `0.0.0.0`.
  - UDP port `1514`.
- Payload contract:
  - Raw UTF-8-compatible syslog text.
  - Invalid bytes are replaced during decoding.
- No response, acknowledgment, replay request, or source authentication is implemented.

### 8.4 Libraries and Runtime Services That Are Not Business Integrations

- FastAPI, Uvicorn, Pydantic, AnyIO, HTTPX, Pytest, Rich, and SQLite are implementation/runtime dependencies.
- No Stripe, payment, email, identity provider, analytics SaaS, object storage, Redis, Kafka, RabbitMQ, cloud database, or third-party webhook integration appears in the codebase.

## 9. Event State Machine and Failure Paths

- Normal lifecycle:
  - `RECEIVED` -> `DURABLY_STORED` -> `COMMITTED`.
- Unknown-format lifecycle:
  - `RECEIVED` -> `DURABLY_STORED` -> `PENDING_AI` -> `COMMITTED` after successful dynamic parser synthesis or reuse.
- In-memory processing path:
  - `DURABLY_STORED` envelope is loaded -> parser attempt -> either committed or pending AI.
  - `PROCESSING` is defined but no code currently persists or uses it as a claim state.
- Declared but unused terminal/recovery states:
  - `RETRY` is not written by the current coordinator or worker.
  - `QUARANTINED` is not written by the current coordinator or worker.
- Agent validation failures:
  - Invalid JSON -> reflection retry.
  - Regex compile failure -> reflection retry.
  - Missing named groups -> reflection retry.
  - Regex timeout or incomplete coverage -> reflection retry.
  - Invalid IP extraction -> reflection retry.
  - All attempts exhausted -> no parser registration; events remain `PENDING_AI`.
- Storage failures:
  - The coordinator does not implement an explicit transaction spanning normalized storage and spool status update.
  - The normalized storage write occurs before the spool status update.
  - A process failure between those operations can leave a committed normalized row and a stale spool status, with later processing relying on `INSERT OR REPLACE` behavior.
- Concurrency considerations:
  - No event claim/lease is used before processing.
  - Multiple coordinators or workers can potentially read the same event concurrently.
  - SQLite provides database-level durability, but the application does not implement distributed worker coordination.
- UDP failure behavior:
  - Transport exceptions are suppressed by the protocol handler.
  - There is no dead-letter or diagnostic persistence for a packet that fails before spool insertion.

## 10. Architecture Diagram Instructions

- Render the system as a modular monolith with one optional worker process:
  - Ingress process: FastAPI HTTP routes and UDP listener.
  - Application layer: `PipelineCoordinator`.
  - Data plane: `DeterministicEngine` plus `DynamicParserRegistry`.
  - Durable queue: SQLite spool database.
  - Analytical store: SQLite normalized database.
  - Control plane: `AgentWorker`, `ParserSynthesisAgent`, clustering, sandbox validation, local Ollama.
  - Parser artifact store: generated JSON files.
- Show these directed arrows:
  - HTTP client -> FastAPI ingest -> coordinator -> spool SQLite.
  - UDP syslog device -> asyncio UDP listener -> coordinator -> spool SQLite.
  - Spool SQLite -> coordinator -> deterministic engine.
  - Deterministic engine -> built-in parser chain.
  - Deterministic engine -> in-memory dynamic parser registry.
  - Successful parser -> normalized SQLite and spool status `COMMITTED`.
  - Parser miss -> spool status `PENDING_AI`.
  - `PENDING_AI` spool rows -> agent worker -> clustering -> local Ollama -> sandbox validator -> dynamic registry -> JSON parser files.
  - Newly registered parser -> deterministic replay -> normalized SQLite.
  - HTTP event query -> normalized SQLite -> HTTP response.
  - Process restart -> JSON parser files -> registry hydration.
- Label the following as absent or out of scope:
  - Frontend UI.
  - Load balancer/API gateway.
  - Redis/cache.
  - Kafka/RabbitMQ/message broker.
  - Cloud infrastructure.
  - Remote SaaS APIs and webhooks.
- Preserve these key architectural properties in any generated diagram:
  - Raw payload is persisted before parsing or AI analysis.
  - Known formats use a synchronous deterministic fast path.
  - Unknown formats use an asynchronous polling-based AI path.
  - Local LLM inference produces parser definitions, not final event records directly.
  - Normalized storage retains the original raw payload and hash alongside normalized OCSF data.
  - Dynamic parser definitions survive process restarts through JSON files.

## 11. Observed Limitations and Deployment Assumptions

- The repository contains no production bootstrap that wires FastAPI, UDP listening, and the background worker together in one managed deployment.
- A deployment must decide whether the API/listener and worker share the same SQLite files and parser directory.
- If the API and worker run as separate processes, both need filesystem access to the spool database, normalized database, and generated parser directory.
- SQLite WAL is suitable for local durability and modest concurrency, but the repository does not provide a horizontally scaled storage or queue topology.
- The dynamic registry is process-local; a parser hot-loaded in one process is not automatically loaded into another process until restart or explicit reload.
- The normalized schema is intentionally denormalized and OCSF JSON is stored as a single serialized field in addition to queryable columns.
- No retention policy, archival process, compaction process, database backup job, or parser version migration process is implemented.
- No cron jobs, scheduled maintenance tasks, event emitter abstraction, or external asynchronous message bus are present.
