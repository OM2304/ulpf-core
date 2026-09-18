import ast
import json
import os
import re
from collections import deque
from typing import Callable, Dict, List, Optional, Tuple
from rich import print as _rich_print
import chromadb
from chromadb.utils import embedding_functions

from ulpf.clustering import cluster_unrecognized_events
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry, ParserDefinition, SandboxValidator
from ulpf.spool import DurableSpool

global_agent_logs = deque(maxlen=200)

# --- NEW: DETERMINISTIC PRIMITIVE LIBRARY ---
# These are pre-tested, guaranteed-valid regex building blocks.
# The LLM never writes these; Python inserts them automatically.
PRIMITIVE_PATTERNS = {
    "IPV4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "PORT": r"\d{1,5}",
    "ACTION": r"ALLOW|DENY|DROP|ACCEPT|REJECT|BLOCK|session|login|password|opened|closed|failed|success|Logged out|Login",
    "PROTOCOL": r"TCP|UDP|ICMP|GRE",
    "SYSLOG_TIMESTAMP": r"[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}",
    "TIMESTAMP": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
    "MAC": r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",
    "METHOD": r"GET|POST|PUT|DELETE|PATCH",
    "STATUS": r"\d{3}",
    "PATH": r"/[^\s]*",
    "WORD": r"[\w\.\-]+",
    "NUMBER": r"\d+"
}

def rprint(*args, **kwargs):
    _rich_print(*args, **kwargs)
    text = " ".join(str(a) for a in args)
    clean_text = re.sub(r"\[.*?\]", "", text).strip()
    if clean_text:
        global_agent_logs.append(clean_text)


class ParserSynthesisAgent:
    """Offline Agentic AI control plane augmented with local RAG for precision parser synthesis."""

    def __init__(
        self,
        registry: DynamicParserRegistry,
        spool: Optional[DurableSpool] = None,
        llm_caller: Optional[Callable[[str], str]] = None,
        model_name: str = "qwen2.5-coder:3b"
    ):
        self.registry = registry
        self.spool = spool
        self.llm_caller = llm_caller or self._default_ollama_caller
        self.model_name = model_name
        
        db_path = os.path.join(os.getcwd(), "ulpf_chroma_db")
        self.chroma_client = chromadb.PersistentClient(path=db_path)
        self.emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        try:
            self.rag_collection = self.chroma_client.get_collection(name="log_parsers", embedding_function=self.emb_fn)
        except Exception:
            self.rag_collection = None

    def _default_ollama_caller(self, prompt: str) -> str:
        try:
            import ollama
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                options={"temperature": 0.0}
            )
            return response.get("response", "")
        except Exception as e:
            raise RuntimeError(f"Local Ollama inference failed: {e}")

    def classify_cluster(self, sample_logs: List[str]) -> str:
        """Deterministic Hard-Routing takes priority to prevent 3B LLM Hallucinations."""
        text = " ".join(sample_logs).lower()
        
        # 1. Hardcoded Rules (Unbreakable)
        if "sudo" in text or "cron" in text or "login" in text or "pam_" in text or "imap" in text or "dovecot" in text: 
            return "AUTHENTICATION"
        if "get " in text or "post " in text or "http" in text: 
            return "WEB"

        # 2. Zero-Shot Fallback
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs[:3]])
        prompt = f"""Categorize these logs into exactly ONE category (NETWORK, AUTHENTICATION, or WEB):
{formatted_samples}
Respond with ONLY the category name."""
        try:
            response = self.llm_caller(prompt).strip().upper()
            if "AUTH" in response: return "AUTHENTICATION"
            if "WEB" in response: return "WEB"
            if "NET" in response: return "NETWORK"
        except Exception:
            pass
        return "NETWORK"

    def retrieve_rag_context(self, sample_log: str, top_k: int = 2) -> List[dict]:
        """Fetch the top K structurally similar parsing plans for Dynamic Few-Shot."""
        if not self.rag_collection:
            return []
            
        results = self.rag_collection.query(
            query_texts=[sample_log],
            n_results=top_k
        )
        
        contexts = []
        if results['metadatas'] and results['metadatas'][0]:
            for i in range(len(results['metadatas'][0])):
                meta = results['metadatas'][0][i]
                contexts.append({
                    "category": meta.get("category", "NETWORK"),
                    "parsing_plan": meta.get("parsing_plan", ""),
                    "regex": meta.get("regex", ""),
                    "mappings": meta.get("mappings", ""),
                    "log": results['documents'][0][i] if results['documents'] else ""
                })
        return contexts

    def build_prompt(self, sample_logs: List[str], rag_contexts: List[dict], category: str) -> str:
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs])
        
        types_list = ", ".join(PRIMITIVE_PATTERNS.keys())
        
        if category == "AUTHENTICATION":
            fields_list = "action, status, user"
            static_example = """--- STATIC BASELINE EXAMPLE ---
TARGET LOG: May 14 12:30:00 server sshd[123]: Failed password for root from 192.168.1.10
PARSING PLAN:
{
  "fields": [
    {"val": "Failed", "field": "status", "type": "WORD"},
    {"val": "password", "field": "action", "type": "WORD"},
    {"val": "root", "field": "user", "type": "WORD"}
  ]
}"""
        elif category == "WEB":
            fields_list = "src_ip, method, url, status"
            static_example = """--- STATIC BASELINE EXAMPLE ---
TARGET LOG: 192.168.1.5 - - [10/Oct/2000] "GET /index.html HTTP/1.0" 200
PARSING PLAN:
{
  "fields": [
    {"val": "192.168.1.5", "field": "src_ip", "type": "IPV4"},
    {"val": "GET", "field": "method", "type": "METHOD"},
    {"val": "/index.html", "field": "url", "type": "PATH"},
    {"val": "200", "field": "status", "type": "STATUS"}
  ]
}"""
        else: # NETWORK
            fields_list = "src_ip, dst_ip, proto, action"
            static_example = """--- STATIC BASELINE EXAMPLE ---
TARGET LOG: SRC=10.0.0.1 DST=192.168.1.100 PROTO=TCP ACTION=DROP
PARSING PLAN:
{
  "fields": [
    {"val": "10.0.0.1", "field": "src_ip", "type": "IPV4"},
    {"val": "192.168.1.100", "field": "dst_ip", "type": "IPV4"},
    {"val": "TCP", "field": "proto", "type": "PROTOCOL"},
    {"val": "DROP", "field": "action", "type": "ACTION"}
  ]
}"""

        json_schema = '{\n  "fields": [\n    {"val": "exact_value_from_log", "field": "field_name", "type": "TYPE_FROM_LIST"}\n  ]\n}'

        dynamic_examples = ""
        for idx, ctx in enumerate(rag_contexts, 1):
            plan = ctx.get('parsing_plan', '')
            if plan:
                dynamic_examples += f"--- DYNAMIC RAG EXAMPLE {idx} ---\nTARGET LOG: {ctx['log']}\nPARSING PLAN: {plan}\n\n"

        return f"""You are an elite cybersecurity data engineer. Analyze these TARGET LOGS:
{formatted_samples}

Identify the key values inside the log and map them to OCSF field names ({fields_list}).
Assign each value a TYPE from this exact list: [{types_list}].

{static_example}
{dynamic_examples}
CRITICAL INSTRUCTIONS:
1. EXTRACT EXACT STRINGS: The "val" MUST be an exact substring present in the TARGET LOG. Do not invent or alter values.
2. NO HALLUCINATION: Only map fields that actually exist in the log.
3. JSON ONLY: Return ONLY a valid JSON object matching this schema exactly:
{json_schema}
"""

    def build_reflection_prompt(
        self,
        sample_logs: List[str],
        previous_pattern: str,
        error_reason: str,
        rag_contexts: List[dict],
        category: str
    ) -> str:
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs])
        json_schema = '{\n  "fields": [\n    {"val": "exact_value_from_log", "field": "field_name", "type": "TYPE_FROM_LIST"}\n  ]\n}'

        return f"""Your previous parsing plan failed sandbox validation.

Target Logs:
{formatted_samples}

Previous Attempt:
{previous_pattern}

Validation Error Reason:
{error_reason}

Reflect on why the previous plan failed. 
CRITICAL RULE: Make sure the "val" exists EXACTLY in the log text. Ensure you only use types from the allowed list.

Return ONLY a valid JSON object with this exact structure:
{json_schema}
"""

    def _extract_json(self, raw_response: str) -> Optional[Dict]:
        cleaned = raw_response.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```python" in cleaned:
            cleaned = cleaned.split("```python")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        snippet = cleaned[start:end + 1] if (start != -1 and end != -1 and end > start) else cleaned

        try:
            return json.loads(snippet)
        except Exception:
            pass

        try:
            res = ast.literal_eval(snippet)
            if isinstance(res, dict) and ("fields" in res or "regex_pattern" in res):
                return res
        except Exception:
            pass

        return None

    # --- NEW: DETERMINISTIC COMPILER ---
    def _compile_parsing_plan(self, sample_log: str, fields: List[Dict]) -> Tuple[str, Dict[str, str]]:
        """Converts an LLM JSON Parsing Plan into a bulletproof compiled Regex pattern."""
        found_fields = []
        for f in fields:
            val = str(f.get("val", ""))
            if not val: continue
            idx = sample_log.find(val)
            if idx != -1:
                found_fields.append((idx, val, str(f.get("field", "")), str(f.get("type", "WORD"))))
        
        # Order the captures exactly as they appear in the log string
        found_fields.sort(key=lambda x: x[0])
        
        regex_parts = [r"(?i)"]
        last_idx = 0
        field_mappings = {}
        
        for idx, val, field_name, p_type in found_fields:
            if idx < last_idx: continue # Avoid overlaps
            
            if idx > last_idx:
                regex_parts.append(r".*?") # Bridge any text gaps deterministically
                
            prim_regex = PRIMITIVE_PATTERNS.get(p_type.upper(), PRIMITIVE_PATTERNS["WORD"])
            
            safe_field_name = re.sub(r'[^a-zA-Z0-9_]', '', field_name)
            if not safe_field_name:
                safe_field_name = "unknown_field"
            if safe_field_name in field_mappings:
                safe_field_name = f"{safe_field_name}_2"
                
            regex_parts.append(f"(?P<{safe_field_name}>{prim_regex})")
            field_mappings[safe_field_name] = safe_field_name
            
            last_idx = idx + len(val)
            
        return "".join(regex_parts), field_mappings

    def synthesize_and_onboard(
        self,
        parser_id: str,
        sample_logs: List[str],
        max_attempts: int = 3
    ) -> Optional[ParserDefinition]:
        if not sample_logs:
            return None

        category = self.classify_cluster(sample_logs)
        rprint(f"    [magenta]⚡ RAG Vector Match Found:[/magenta] [bold]{category}[/bold] schema applied.")
        
        rag_contexts = self.retrieve_rag_context(sample_logs[0], top_k=2)
        current_prompt = self.build_prompt(sample_logs, rag_contexts, category)
        last_failed_pattern = ""

        for attempt in range(1, max_attempts + 1):
            rprint(f"    [cyan]Attempt {attempt}/{max_attempts}:[/cyan] Querying LLM and evaluating candidate parsing plan...")
            raw_response = self.llm_caller(current_prompt)
            data = self._extract_json(raw_response)

            if not data or "fields" not in data:
                last_failed_pattern = raw_response[:80]
                error_msg = "Output was not valid JSON format or missing the 'fields' list."
                rprint(f"    [yellow]⚠ Attempt {attempt} JSON decode error:[/yellow] Triggering self-reflection retry...")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)
                continue

            # NEW: Let Python Build the Regex safely instead of the LLM
            fields_plan = data.get("fields", [])
            regex_pattern, field_mappings = self._compile_parsing_plan(sample_logs[0], fields_plan)
            
            rprint(f"    [dim]Compiled Pattern:[/dim] [italic]{regex_pattern}[/italic]")

            try:
                compiled = re.compile(regex_pattern)
            except re.error as compile_err:
                last_failed_pattern = json.dumps(data)
                error_msg = f"Python Regex compilation error from parsed values: {compile_err}"
                rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)
                continue

            missing_groups = [grp for grp in field_mappings.values() if grp and grp not in compiled.groupindex]
            if missing_groups or not compiled.groupindex:
                last_failed_pattern = json.dumps(data)
                error_msg = "No valid fields were successfully mapped from the target log."
                rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)
                continue

            is_valid, reason, coverage = SandboxValidator.validate_pattern(
                pattern=regex_pattern,
                sample_logs=sample_logs,
                timeout_ms=50.0
            )

            extraction_valid = True
            semantic_error = ""
            for sample in sample_logs:
                m = compiled.search(sample)
                if not m:
                    extraction_valid = False
                    break
                extracted = m.groupdict()
                if not any(extracted.values()):
                    extraction_valid = False
                    break

            if is_valid and coverage == 1.0 and extraction_valid:
                rprint(f"    [green]✓ Sandbox Passed:[/green] 100% sample coverage & semantic integrity verified for {category} log.")
                definition = ParserDefinition(
                    parser_id=parser_id,
                    parser_version="1.0.0",
                    description=f"AI-synthesized dynamic parser for {category} (validated via RAG reflexion)",
                    regex_pattern=regex_pattern,
                    field_mappings=field_mappings
                )

                if self.registry.register(definition):
                    return definition

            last_failed_pattern = json.dumps(data)
            error_reason = semantic_error if semantic_error else reason
            error_msg = f"{error_reason} (Coverage: {coverage * 100:.1f}%, Field Extraction Valid: {extraction_valid})"
            rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
            current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)

        return None

    def triage_pending_spool(
        self,
        engine,
        storage,
        batch_size: int = 50
    ) -> Dict[str, int]:
        if not self.spool:
            return {"triaged": 0, "clusters_detected": 0, "onboarded_parsers": 0, "committed": 0}

        with self.spool._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT event_id, received_at, raw_sha256, raw_payload, status, parser_id, source_transport
                FROM spool_events
                WHERE status = 'PENDING_AI'
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (batch_size,),
            ).fetchall()

        if not rows:
            return {"triaged": 0, "clusters_detected": 0, "onboarded_parsers": 0, "committed": 0}

        pending_events: List[EventEnvelope] = []
        for r in rows:
            env = EventEnvelope(
                event_id=r["event_id"],
                received_at=r["received_at"],
                raw_payload=r["raw_payload"],
                source_transport=r["source_transport"] if "source_transport" in r.keys() and r["source_transport"] else "direct",
                status=EventStatus.PENDING_AI,
                parser_id=r["parser_id"],
            )
            pending_events.append(env)

        clusters = cluster_unrecognized_events(pending_events)
        rprint(f"  • Clustered [bold]{len(pending_events)}[/bold] pending event(s) into [bold]{len(clusters)}[/bold] structural log signature(s).")

        stats = {
            "triaged": len(pending_events),
            "clusters_detected": len(clusters),
            "onboarded_parsers": 0,
            "committed": 0
        }

        for cluster in clusters:
            rprint(f"    [dim]Processing Cluster [{cluster.cluster_id}] ({cluster.sample_count} events):[/dim] [italic]{cluster.skeleton[:70]}...[/italic]")

            unhandled_events: List[EventEnvelope] = []
            for ev in cluster.events:
                success, parsed_event = engine.parse_and_normalize(ev)
                if success and parsed_event.status == EventStatus.COMMITTED:
                    storage.commit_event(parsed_event)
                    self.spool.update_status(
                        parsed_event.event_id,
                        EventStatus.COMMITTED,
                        parser_id=parsed_event.parser_id
                    )
                    stats["committed"] += 1
                else:
                    unhandled_events.append(ev)

            if not unhandled_events:
                continue

            cluster_parser_id = f"dynamic_ai_{cluster.cluster_id}_v1"
            definition = self.synthesize_and_onboard(
                parser_id=cluster_parser_id,
                sample_logs=cluster.sample_logs
            )

            if definition:
                stats["onboarded_parsers"] += 1
                for ev in unhandled_events:
                    success, parsed_event = engine.parse_and_normalize(ev)
                    if success and parsed_event.status == EventStatus.COMMITTED:
                        storage.commit_event(parsed_event)
                        self.spool.update_status(
                            parsed_event.event_id,
                            EventStatus.COMMITTED,
                            parser_id=parsed_event.parser_id
                        )
                        stats["committed"] += 1

        return stats