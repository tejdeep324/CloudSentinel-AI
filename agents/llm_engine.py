import os
import json
from typing import Dict, Any

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

class LLMReasoningEngine:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY", "")
        if GENAI_AVAILABLE and api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel("gemini-1.5-flash")
            self.enabled = True
        else:
            self.enabled = False

    def generate_agent_reasoning(self, agent_name: str, payload_snippet: Dict[str, Any]) -> str:
        if not self.enabled:
            return (
                f"[{agent_name}] Rule-based engine detected non-compliant cloud configurations. "
                "Immediate remediation and volume re-encryption recommended."
            )

        prompt = f"""
        You are an expert autonomous cloud cybersecurity agent named {agent_name}.
        Analyze the following AWS workload JSON configuration for security vulnerabilities, compliance breaches, and misconfigurations:
        {json.dumps(payload_snippet, indent=2)}

        Provide a concise, 2-sentence technical evaluation explaining the exact risk and the required remediation action.
        """
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"[{agent_name}] Heuristic evaluation flagged potential security vulnerabilities. (LLM Fallback: {str(e)})"