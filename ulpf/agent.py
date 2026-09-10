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
        """Fetch the top K structurally similar parsers for Dynamic Few-Shot."""
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
                    "regex": meta.get("regex", ""),
                    "mappings": meta.get("mappings", ""),
                    "log": results['documents'][0][i] if results['documents'] else ""
                })
        return contexts

    def build_prompt(self, sample_logs: List[str], rag_contexts: List[dict], category: str) -> str:
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs])
        
        # Define base schema and static baseline example
        if category == "AUTHENTICATION":
            fields_list = "1. action (e.g., session, login, sudo, logout)\n2. status (e.g., opened, closed, failed, success)\n3. user (the username)"
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "user": "user",\n    "action": "action",\n    "status": "status"\n  }\n}'
            static_example = "--- STATIC BASELINE EXAMPLE ---\nTARGET LOG: May 14 12:30:00 server sshd[123]: Failed password for root from 192.168.1.10\nREGEX: (?i).*?(?P<action>password).*?(?P<status>Failed).*?(?:for)\\s+(?P<user>\\S+)\n"
        elif category == "WEB":
            fields_list = "1. src_ip (client IP)\n2. method (GET/POST/PUT)\n3. url (request path)\n4. status (HTTP status code)"
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "src_ip": "src_ip",\n    "method": "method",\n    "url": "url",\n    "status": "status"\n  }\n}'
            static_example = "--- STATIC BASELINE EXAMPLE ---\nTARGET LOG: 192.168.1.5 - - [10/Oct/2000] \"GET /index.html HTTP/1.0\" 200\nREGEX: (?i)^(?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+).*?(?P<method>GET|POST|PUT|DELETE)\\s+(?P<url>\\S+)\\s+HTTP.*?\"?\\s+(?P<status>\\d{3})\n"
        else: # NETWORK
            fields_list = "1. src_ip (Source IP)\n2. dst_ip (Destination IP)\n3. proto (Protocol)\n4. action (ALLOW/DENY/DROP/ACCEPT)"
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "src_ip": "src_ip",\n    "dst_ip": "dst_ip",\n    "proto": "proto",\n    "action": "action"\n  }\n}'
            static_example = "--- STATIC BASELINE EXAMPLE ---\nTARGET LOG: SRC=10.0.0.1 DST=192.168.1.100 PROTO=TCP ACTION=DROP\nREGEX: (?i).*?SRC=(?P<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+).*?DST=(?P<dst_ip>\\d+\\.\\d+\\.\\d+\\.\\d+).*?PROTO=(?P<proto>\\S+).*?(?P<action>DROP|ACCEPT|REJECT|DENY|BLOCK|ALLOW)\n"

        # Build dynamic examples from ChromaDB
        dynamic_examples = ""
        for idx, ctx in enumerate(rag_contexts, 1):
            safe_regex = ctx['regex'].replace("\\", "\\\\") if ctx.get('regex') else ""
            dynamic_examples += f"--- DYNAMIC RAG EXAMPLE {idx} ---\nTARGET LOG: {ctx['log']}\nREGEX: {safe_regex}\n\n"

        return f"""You are an elite cybersecurity log parsing engineer. Analyze these TARGET LOGS:
{formatted_samples}

Generate a Python regular expression with NAMED capture groups that extracts:
{fields_list}

{static_example}
{dynamic_examples}
CRITICAL INSTRUCTIONS:
1. ADAPT TO THE TARGET: The templates above are just examples! Look closely at the exact spacing, brackets, and punctuation in the TARGET LOGS. Change your regex to match them.
2. PUNCTUATION IS KEY: Extract values based on surrounding punctuation (like brackets [], parentheses (), or equal signs =).
3. NO HALLUCINATION: NEVER inject literal words like 'user ' or 'src=' unless they explicitly exist in the TARGET LOGS. Use .*? to skip noise.
4. UNIQUE GROUP NAMES: Never reuse the same named group (e.g., do not write (?P<user>...) more than once). Every named group must have a unique identifier.
5. CASE-INSENSITIVITY: Start your regex with the (?i) flag.
6. ESCAPING: Double-escape backslashes for valid JSON (use \\\\d, \\\\s, \\\\S).

Return ONLY a valid JSON object matching this schema exactly:
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
        
        if category == "AUTHENTICATION":
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "user": "user",\n    "action": "action",\n    "status": "status"\n  }\n}'
        elif category == "WEB":
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "src_ip": "src_ip",\n    "method": "method",\n    "url": "url",\n    "status": "status"\n  }\n}'
        else:
            json_schema = '{\n  "regex_pattern": "...",\n  "field_mappings": {\n    "src_ip": "src_ip",\n    "dst_ip": "dst_ip",\n    "proto": "proto",\n    "action": "action"\n  }\n}'

        reference = ""
        if rag_contexts:
            safe_regex = rag_contexts[0]['regex'].replace("\\", "\\\\") if rag_contexts[0].get('regex') else ""
            reference = f"--- CLOSEST KNOWN PATTERN ---\nIf stuck, look at this structure:\n{safe_regex}\n--------------------------\n"

        return f"""Your previous regular expression failed sandbox validation.

Target Logs:
{formatted_samples}

Previous Attempt:
{previous_pattern}

Validation Error Reason:
{error_reason}

{reference}

Reflect on why the previous pattern failed. 
CRITICAL RULE: You likely hardcoded literal text or duplicated a named group (such as reusing (?P<user>...)). Ensure every named group is unique and avoid hardcoded literal keys that do not exist in the logs.

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
            sanitized = re.sub(r'\\(?![\\"/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', snippet)
            return json.loads(sanitized)
        except Exception:
            pass

        try:
            res = ast.literal_eval(snippet)
            if isinstance(res, dict) and "regex_pattern" in res:
                return res
        except Exception:
            pass

        try:
            pattern_match = re.search(
                r'["\']regex_pattern["\']\s*:\s*r?["\'](.*?)["\']\s*(?:,\s*["\']field_mappings["\']|\s*\})',
                snippet,
                flags=re.DOTALL
            )
            mapping_match = re.search(r'["\']field_mappings["\']\s*:\s*\{([^}]+)\}', snippet)

            if pattern_match:
                raw_pattern = pattern_match.group(1).strip()
                mappings = {}
                if mapping_match:
                    for kv in re.finditer(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']+)["\']', mapping_match.group(1)):
                        mappings[kv.group(1)] = kv.group(2)
                return {"regex_pattern": raw_pattern, "field_mappings": mappings}
        except Exception:
            pass
        return None

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
        
        # Now fetches a list of dicts instead of a single dict
        rag_contexts = self.retrieve_rag_context(sample_logs[0], top_k=2)
        
        current_prompt = self.build_prompt(sample_logs, rag_contexts, category)
        last_failed_pattern = ""

        for attempt in range(1, max_attempts + 1):
            rprint(f"    [cyan]Attempt {attempt}/{max_attempts}:[/cyan] Querying LLM and evaluating candidate regex...")
            raw_response = self.llm_caller(current_prompt)
            data = self._extract_json(raw_response)

            if not data:
                last_failed_pattern = raw_response[:80]
                error_msg = "Output was not valid JSON format or failed regex escaping rules."
                rprint(f"    [yellow]⚠ Attempt {attempt} JSON decode error:[/yellow] Triggering self-reflection retry...")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)
                continue

            regex_pattern = data.get("regex_pattern", "")
            field_mappings = data.get("field_mappings", {})
            rprint(f"    [dim]Candidate Pattern:[/dim] [italic]{regex_pattern}[/italic]")

            try:
                compiled = re.compile(regex_pattern)
            except re.error as compile_err:
                last_failed_pattern = regex_pattern
                error_msg = f"Regex compilation error: {compile_err}"
                rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg, rag_contexts, category)
                continue

            missing_groups = [grp for grp in field_mappings.values() if grp and grp not in compiled.groupindex]
            if missing_groups or not compiled.groupindex:
                last_failed_pattern = regex_pattern
                error_msg = (
                    f"Regex lacks named capture groups (?P<name>...). Missing groups in pattern: {missing_groups}. "
                    f"You MUST format groups as (?P<group_name>pattern) instead of unnamed (pattern)."
                )
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

                src_val = extracted.get(field_mappings.get("src_ip", ""), "")
                if src_val and ("=" in src_val or not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", src_val)):
                    extraction_valid = False
                    semantic_error = f"Field 'src_ip' extracted '{src_val}', which is NOT a valid IP address. Adjust your capture group."
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

            last_failed_pattern = regex_pattern
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