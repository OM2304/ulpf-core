import json
import re
from typing import Callable, Dict, List, Optional, Tuple
from rich import print as rprint
from ulpf.clustering import cluster_unrecognized_events
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry, ParserDefinition, SandboxValidator
from ulpf.spool import DurableSpool


class ParserSynthesisAgent:
    """Offline Agentic AI control plane for synthesizing, reflecting, and validating dynamic parsers.
    
    Implements an air-gapped Reflexion loop that prompts a local LLM via Ollama,
    validates candidate regexes in a sandbox environment, and feeds runtime errors
    back into the model for autonomous self-correction.
    """

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

    def _default_ollama_caller(self, prompt: str) -> str:
        """Execute local inference against Ollama."""
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

    def build_prompt(self, sample_logs: List[str]) -> str:
        """Construct structured prompt for deterministic regex and OCSF mapping generation."""
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs])
        return f"""You are a cybersecurity log parsing expert. Analyze these perimeter log samples:
{formatted_samples}

Generate a Python regular expression with NAMED capture groups that extracts:
1. Source IP address
2. Destination IP address
3. Protocol (TCP/UDP/ICMP/etc.)
4. Action/State (ALLOW/DENY/REJECT/ACCEPT/DROP/etc.)

MANDATORY RULES:
- You MUST use Python named capture groups with (?P<group_name>pattern) syntax.
  Example: CLIENT=(?P<client_ip>\\S+)\\s+REMOTE=(?P<remote_ip>\\S+)\\s+PROTO=(?P<proto>\\w+)\\s+STATE=(?P<state>\\w+)
- DO NOT use unnamed parentheses like (\\d+). ALWAYS name them like (?P<src_ip>\\d+).
- Double-escape backslashes for valid JSON (use \\\\d, \\\\s, \\\\w, \\\\[, \\\\]).
- Return ONLY a valid JSON object matching this exact schema:

{{
  "regex_pattern": ".*CLIENT=(?P<client_ip>\\\\S+)\\\\s+REMOTE=(?P<remote_ip>\\\\S+)\\\\s+PROTO=(?P<proto>\\\\w+)\\\\s+STATE=(?P<state>\\\\w+)",
  "field_mappings": {{
    "src_ip": "client_ip",
    "dst_ip": "remote_ip",
    "proto": "proto",
    "action": "state"
  }}
}}
Do not include any explanation or Markdown outside the JSON.
"""

    def build_reflection_prompt(
        self,
        sample_logs: List[str],
        previous_pattern: str,
        error_reason: str
    ) -> str:
        """Construct a reflection prompt containing execution failure feedback from SandboxValidator."""
        formatted_samples = "\n".join([f"- {s}" for s in sample_logs])
        return f"""You are a cybersecurity log parsing expert. Your previous regular expression attempt failed sandbox validation.

Perimeter Log Samples:
{formatted_samples}

Previous Attempt:
{previous_pattern}

Validation Error Reason:
{error_reason}

Reflect on why the previous pattern failed. Fix the regular expression:
1. You MUST use Python named capture groups (?P<name>pattern).
2. Every field in field_mappings must match a (?P<name>...) group in regex_pattern.
3. Double-escape backslashes in JSON (\\\\d, \\\\s, \\\\w).
4. Ensure it matches 100% of the sample logs without catastrophic backtracking.

Return ONLY a valid JSON object with this exact structure:
{{
  "regex_pattern": "...",
  "field_mappings": {{
    "src_ip": "<capture_group_name_for_src_ip>",
    "dst_ip": "<capture_group_name_for_dst_ip>",
    "proto": "<capture_group_name_for_protocol>",
    "action": "<capture_group_name_for_action>"
  }}
}}
Do not include any explanation or Markdown outside the JSON.
"""

    def _extract_json(self, raw_response: str) -> Optional[Dict]:
        """Extract and sanitize JSON dictionary from raw LLM output."""
        cleaned = raw_response.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = cleaned[start:end + 1]
        else:
            snippet = cleaned

        # 1. Direct standard parse
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            pass

        # 2. Sanitize unescaped regex backslashes common in LLM outputs (\s, \d, \w, \.)
        try:
            sanitized = re.sub(r'\\(?![\\"/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', snippet)
            return json.loads(sanitized)
        except Exception:
            pass

        # 3. Targeted field extraction fallback via regex
        pattern_match = re.search(r'"regex_pattern"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', snippet)
        if pattern_match:
            try:
                raw_pattern = pattern_match.group(1).encode('utf-8').decode('unicode_escape')
                mappings = {}
                mapping_block = re.search(r'"field_mappings"\s*:\s*\{([^}]+)\}', snippet)
                if mapping_block:
                    for kv in re.finditer(r'"([^"]+)"\s*:\s*"([^"]+)"', mapping_block.group(1)):
                        mappings[kv.group(1)] = kv.group(2)
                return {
                    "regex_pattern": raw_pattern,
                    "field_mappings": mappings
                }
            except Exception:
                return None

        return None

    def synthesize_and_onboard(
        self,
        parser_id: str,
        sample_logs: List[str],
        max_attempts: int = 3
    ) -> Optional[ParserDefinition]:
        """Synthesize regex, test in sandbox, reflect on failures, and register into active data plane."""
        if not sample_logs:
            return None

        current_prompt = self.build_prompt(sample_logs)
        last_failed_pattern = ""

        for attempt in range(1, max_attempts + 1):
            rprint(f"    [cyan]Attempt {attempt}/{max_attempts}:[/cyan] Querying LLM and evaluating candidate regex...")
            raw_response = self.llm_caller(current_prompt)
            data = self._extract_json(raw_response)

            if not data:
                last_failed_pattern = raw_response[:80]
                error_msg = "Output was not valid JSON format or failed regex escaping rules."
                rprint(f"    [yellow]⚠ Attempt {attempt} JSON decode error:[/yellow] Triggering self-reflection retry...")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg)
                continue

            regex_pattern = data.get("regex_pattern", "")
            field_mappings = data.get("field_mappings", {})
            rprint(f"    [dim]Candidate Pattern:[/dim] [italic]{regex_pattern}[/italic]")

            # 1. Check regex compilation
            try:
                compiled = re.compile(regex_pattern)
            except re.error as compile_err:
                last_failed_pattern = regex_pattern
                error_msg = f"Regex compilation error: {compile_err}"
                rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg)
                continue

            # 2. Strict Named Group Check
            missing_groups = [
                grp for grp in field_mappings.values()
                if grp not in compiled.groupindex
            ]
            if missing_groups or not compiled.groupindex:
                last_failed_pattern = regex_pattern
                error_msg = (
                    f"Regex lacks named capture groups (?P<name>...). Missing groups in pattern: {missing_groups}. "
                    f"You MUST format groups as (?P<group_name>pattern) instead of unnamed (pattern)."
                )
                rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
                current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg)
                continue

            # 3. Hard Sandbox Security Gate (ReDoS & Coverage Check)
            is_valid, reason, coverage = SandboxValidator.validate_pattern(
                pattern=regex_pattern,
                sample_logs=sample_logs,
                timeout_ms=50.0
            )

            # 4. Verify that named groups extract values from samples
            extraction_valid = True
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
                rprint(f"    [green]✓ Sandbox Passed:[/green] 100% sample coverage & named groups verified.")
                definition = ParserDefinition(
                    parser_id=parser_id,
                    parser_version="1.0.0",
                    description="AI-synthesized dynamic parser (validated via sandbox reflexion)",
                    regex_pattern=regex_pattern,
                    field_mappings=field_mappings
                )

                # Hot-load into live registry
                if self.registry.register(definition):
                    return definition

            # Prepare reflection prompt for next iteration
            last_failed_pattern = regex_pattern
            error_msg = f"{reason} (Coverage: {coverage * 100:.1f}%, Field Extraction Valid: {extraction_valid})"
            rprint(f"    [yellow]⚠ Reflexion Loop Triggered:[/yellow] {error_msg}")
            current_prompt = self.build_reflection_prompt(sample_logs, last_failed_pattern, error_msg)

        return None

    def triage_pending_spool(
        self,
        engine,
        storage,
        batch_size: int = 50
    ) -> Dict[str, int]:
        """Fetch PENDING_AI events, partition by structural skeleton clusters, synthesize, and commit."""
        if not self.spool:
            return {"triaged": 0, "clusters_detected": 0, "onboarded_parsers": 0, "committed": 0}

        # Query events marked for AI attention
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

        # 1. Partition pending logs into homogeneous structural clusters
        clusters = cluster_unrecognized_events(pending_events)
        rprint(f"  • Clustered [bold]{len(pending_events)}[/bold] pending event(s) into [bold]{len(clusters)}[/bold] structural log signature(s).")

        stats = {
            "triaged": len(pending_events),
            "clusters_detected": len(clusters),
            "onboarded_parsers": 0,
            "committed": 0
        }

        # 2. Process each cluster independently
        for cluster in clusters:
            rprint(f"    [dim]Processing Cluster [{cluster.cluster_id}] ({cluster.sample_count} events):[/dim] [italic]{cluster.skeleton[:70]}...[/italic]")

            # Check if an existing parser in the registry already matches this cluster
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

            # Synthesize a dedicated parser tailored specifically for this structural cluster
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