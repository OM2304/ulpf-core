import json
import re
from typing import Callable, Dict, List, Optional
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry, ParserDefinition, SandboxValidator
from ulpf.spool import DurableSpool


class ParserSynthesisAgent:
    """Offline Agentic AI control plane for synthesizing and validating dynamic parsers."""

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

Generate a Python regular expression with named capture groups that extracts:
1. Source IP address
2. Destination IP address
3. Protocol (TCP/UDP/ICMP/etc.)
4. Action/State (ALLOW/DENY/REJECT/ACCEPT/DROP/etc.)

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
Do not include any Markdown formatting or explanation outside the JSON.
"""

    def synthesize_and_onboard(
        self,
        parser_id: str,
        sample_logs: List[str],
        max_attempts: int = 2
    ) -> Optional[ParserDefinition]:
        """Synthesize regex, test in sandbox, and register into active data plane."""
        if not sample_logs:
            return None

        prompt = self.build_prompt(sample_logs)

        for _ in range(max_attempts):
            raw_response = self.llm_caller(prompt)

            # Strip markdown formatting
            cleaned_json = raw_response.strip()
            if "```json" in cleaned_json:
                cleaned_json = cleaned_json.split("```json")[1].split("```")[0].strip()
            elif "```" in cleaned_json:
                cleaned_json = cleaned_json.split("```")[1].split("```")[0].strip()

            try:
                data = json.loads(cleaned_json)
                regex_pattern = data.get("regex_pattern", "")
                field_mappings = data.get("field_mappings", {})
            except json.JSONDecodeError:
                continue

            # Hard Sandbox Security Gate (ReDoS & Coverage Check)
            is_valid, reason, coverage = SandboxValidator.validate_pattern(
                pattern=regex_pattern,
                sample_logs=sample_logs,
                timeout_ms=10.0
            )

            if is_valid and coverage == 1.0:
                definition = ParserDefinition(
                    parser_id=parser_id,
                    parser_version="1.0.0",
                    description="AI-synthesized dynamic parser",
                    regex_pattern=regex_pattern,
                    field_mappings=field_mappings
                )

                # Hot-load into live registry
                if self.registry.register(definition):
                    return definition

        return None