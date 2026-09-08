// Typed API client for the ULPF FastAPI backend

const BASE = "/api/v1";

export interface SpoolMetrics {
  total: number;
  by_status: Record<string, number>;
  pending_ai: number;
  committed: number;
  durably_stored: number;
  received: number;
}

export interface WorkerMetrics {
  is_running: boolean;
  total_triaged: number;
  total_clusters: number;
  total_parsers_onboarded: number;
  total_committed: number;
  poll_interval: number;
  batch_size: number;
}

export interface StorageStats {
  total_committed: number;
  by_disposition: Record<string, number>;
  by_parser: Record<string, number>;
  unique_src_ips: number;
}

export interface MetricsResponse {
  spool: SpoolMetrics;
  worker: WorkerMetrics;
  storage: StorageStats;
}

export interface ParserDef {
  parser_id: string;
  parser_version: string;
  type: "builtin" | "dynamic_ai";
  description: string;
  regex_pattern: string;
  field_mappings: Record<string, string>;
}

export interface ParsersResponse {
  total: number;
  builtin: ParserDef[];
  dynamic_ai: ParserDef[];
}

export interface ClusterInfo {
  cluster_id: string;
  skeleton: string;
  sample_count: number;
  sample_logs: string[];
}

export interface ClustersResponse {
  clusters: ClusterInfo[];
  total_pending_ai: number;
}

export interface OCSFEvent {
  event_id: string;
  received_at: string;
  source_transport: string;
  raw_payload: string;
  raw_sha256: string;
  parser_id: string;
  parser_version: string;
  action: string;
  disposition: string;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  ocsf_json: string;
  ocsf?: Record<string, unknown>;
}

export interface EventsResponse {
  total: number;
  limit: number;
  offset: number;
  events: OCSFEvent[];
}

async function get<T>(path: string, params?: Record<string, string | number>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, String(v)));
  }
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`API ${path} → ${res.status}`);
  return res.json();
}

export async function fetchMetrics(): Promise<MetricsResponse> {
  return get("/metrics");
}

export async function fetchParsers(): Promise<ParsersResponse> {
  return get("/parsers");
}

export async function fetchClusters(): Promise<ClustersResponse> {
  return get("/clusters");
}

export async function fetchEvents(params: {
  limit?: number;
  offset?: number;
  search?: string;
  disposition?: string;
}): Promise<EventsResponse> {
  return get("/events", {
    limit: params.limit ?? 50,
    offset: params.offset ?? 0,
    search: params.search ?? "",
    disposition: params.disposition ?? "",
  });
}

export async function triggerIngest(logs: string[]): Promise<unknown> {
  const res = await fetch(`${BASE}/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ logs, source_transport: "dashboard_ui" }),
  });
  return res.json();
}

export async function triggerProcessBatch(): Promise<unknown> {
  const res = await fetch(`${BASE}/process-batch`, { method: "POST" });
  return res.json();
}
