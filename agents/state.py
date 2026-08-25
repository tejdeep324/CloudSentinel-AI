from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import time

@dataclass
class AgentFinding:
    agent_name: str
    domain: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    remediation_action: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

@dataclass
class RemediationPlan:
    plan_id: str
    name: str
    description: str
    target_risk_score: int
    actions: List[str]
    trade_off_notes: str
    estimated_duration: str

@dataclass
class AgentBlackboard:
    """Shared state container passed between agents in the collaborative pipeline."""
    workload_payload: Dict[str, Any]
    target_compliance: str = "PCI-DSS (Payment Card Security)"
    pre_scan_score: int = 100
    post_scan_score: int = 100
    supervisor_verdict: str = "PENDING"
    supervisor_reasoning: str = ""
    findings: List[AgentFinding] = field(default_factory=list)
    remediation_plans: Dict[str, RemediationPlan] = field(default_factory=dict)
    execution_trace: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def log_trace(self, agent_name: str, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.execution_trace.append(f"[{timestamp}] [{agent_name}] {message}")

    def add_finding(self, finding: AgentFinding):
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_compliance": self.target_compliance,
            "pre_scan_score": self.pre_scan_score,
            "post_scan_score": self.post_scan_score,
            "supervisor_verdict": self.supervisor_verdict,
            "supervisor_reasoning": self.supervisor_reasoning,
            "findings": [
                {
                    "agent": f.agent_name,
                    "domain": f.domain,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "action": f.remediation_action,
                    "evidence": f.evidence,
                    "confidence": f.confidence
                }
                for f in self.findings
            ],
            "remediation_plans": {
                k: {
                    "name": v.name,
                    "description": v.description,
                    "target_score": v.target_risk_score,
                    "actions": v.actions,
                    "trade_offs": v.trade_off_notes,
                    "estimated_duration": v.estimated_duration
                }
                for k, v in self.remediation_plans.items()
            },
            "execution_trace": self.execution_trace
        }