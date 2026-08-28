import os
import sys
import json
import asyncio
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

GENAI_AVAILABLE = False
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except Exception:
    GENAI_AVAILABLE = False


# ==========================================
# PYDANTIC STRUCTURED SCHEMAS
# ==========================================

class FindingItem(BaseModel):
    title: str = Field(description="Concise description of the security finding")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    description: str = Field(description="Detailed technical reasoning and risk context")
    action: str = Field(description="Target remediation action command")
    confidence: float = Field(default=0.98, description="Model confidence score between 0.0 and 1.0")

class AgentAuditResponse(BaseModel):
    verdict: str = Field(description="FLAGGED or CLEARED")
    findings: List[FindingItem] = Field(default_factory=list)
    reasoning: str = Field(description="Cognitive reasoning trace synthesizing the findings")


# ==========================================
# HIGH-PERFORMANCE GOOGLE AGENT ENGINE
# ==========================================

class GoogleAgentEngine:
    """Enterprise-grade interface for dispatching autonomous Gemini agents."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.client = None
        if GENAI_AVAILABLE and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    def is_live(self) -> bool:
        return self.client is not None

    def analyze_domain_sync(
        self,
        domain_name: str,
        system_instruction: str,
        domain_payload: Dict[str, Any]
    ) -> Optional[AgentAuditResponse]:
        """Executes domain assessment via chat session with strict JSON structure."""
        if not self.is_live():
            return None

        prompt = f"""
        You are an autonomous cloud security sub-agent specializing in {domain_name}.
        Analyze the scoped workload telemetry below and identify all critical security and compliance vulnerabilities.

        SCOPED WORKLOAD TELEMETRY:
        {json.dumps(domain_payload, indent=2)}

        Return your evaluation strictly in JSON format matching this schema:
        {{
            "verdict": "FLAGGED" or "CLEARED",
            "findings": [
                {{
                    "title": "Short finding title",
                    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
                    "description": "Detailed reasoning",
                    "action": "Remediation action string",
                    "confidence": 0.98
                }}
            ],
            "reasoning": "Summary of agent cognitive reasoning"
        }}
        """

        try:
            chat = self.client.chats.create(
                model="gemini-2.5-flash",
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    temperature=0.1
                )
            )
            response = chat.send_message(prompt)
            if response and response.text:
                parsed = json.loads(response.text)
                return AgentAuditResponse(**parsed)
        except Exception:
            return None
        return None

    async def analyze_domain_async(
        self,
        domain_name: str,
        system_instruction: str,
        domain_payload: Dict[str, Any]
    ) -> Optional[AgentAuditResponse]:
        """Asynchronously dispatches domain evaluations in a non-blocking thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.analyze_domain_sync,
            domain_name,
            system_instruction,
            domain_payload
        )