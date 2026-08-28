import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any

# Guarantee root path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base_agent import BaseAgent
from agents.state import AgentBlackboard, RemediationPlan
from agents.specialized_agents import SecurityAgent, NetworkAgent, IAMAgent, ComplianceAgent
from core.scoring import calculate_risk_score

class SupervisorAgent(BaseAgent):
    """Lead orchestrator: coordinates domain agents concurrently, aggregates state, and structures remediation strategies."""

    def __init__(self):
        super().__init__(
            name="SupervisorAgent",
            domain="Multi-Agent Orchestration & Consensus",
            system_prompt=(
                "You are the Supervisor AI for CloudSentinel AI. Coordinate domain agents, "
                "synthesize security posture verdicts, and formulate trade-off remediation plans."
            )
        )
        self.security_agent = SecurityAgent()
        self.network_agent = NetworkAgent()
        self.iam_agent = IAMAgent()
        self.compliance_agent = ComplianceAgent()

    def coordinate_assessment(
        self,
        workload_payload: Dict[str, Any],
        target_compliance: str = "PCI-DSS (Payment Card Security)"
    ) -> AgentBlackboard:
        """Executes concurrent multi-agent evaluation pipeline."""
        blackboard = AgentBlackboard(
            workload_payload=workload_payload,
            target_compliance=target_compliance
        )
        
        blackboard.log_trace(self.name, "Initialized parallel multi-agent evaluation pipeline.")

        # 1. Baseline Pre-Scan Quantitative Score
        pre_eval = calculate_risk_score(workload_payload)
        blackboard.pre_scan_score = pre_eval["total_score"]
        blackboard.log_trace(self.name, f"Baseline Pre-Scan Score: {blackboard.pre_scan_score}/100")

        # 2. Parallel Dispatch of Infrastructure Domain Agents
        infrastructure_agents = [self.security_agent, self.network_agent, self.iam_agent]
        with ThreadPoolExecutor(max_workers=len(infrastructure_agents)) as executor:
            futures = [executor.submit(agent.evaluate, blackboard) for agent in infrastructure_agents]
            for future in futures:
                future.result()

        # 3. Compliance Framework Mapping
        self.compliance_agent.evaluate(blackboard)

        # 4. Consensus Decision Engine
        critical_count = sum(1 for f in blackboard.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in blackboard.findings if f.severity == "HIGH")

        if critical_count > 0 or high_count > 0:
            blackboard.supervisor_verdict = "REMEDIATION_REQUIRED"
            blackboard.supervisor_reasoning = (
                f"Consensus reached: Quarantine isolation active due to {critical_count} critical "
                f"and {high_count} high-severity findings across storage, network, and IAM domains."
            )
        else:
            blackboard.supervisor_verdict = "APPROVED_FOR_MIGRATION"
            blackboard.supervisor_reasoning = (
                "Consensus reached: All domain security, network, and IAM parameters satisfy baseline policy."
            )

        # 5. Formulate Trade-Off Remediation Strategies
        blackboard.remediation_plans = {
            "Plan A (Maximum Security - Recommended)": RemediationPlan(
                plan_id="PLAN_A",
                name="Maximum Security & Zero-Trust",
                description="Complete remediation: AWS KMS CMK encryption, 0.0.0.0/0 ingress revocation, CIS Level 1 OS scripts, and least-privilege IAM profile binding.",
                target_risk_score=95,
                actions=["ENABLE_KMS_CMK_ENCRYPTION", "LOCK_SECURITY_GROUP_INGRESS", "APPLY_CIS_LEVEL1_OS_HARDENING", "REPLACE_WITH_LEAST_PRIVILEGE_ROLE"],
                trade_off_notes="Takes ~2 minutes to bake a fresh Golden AMI, delivering 100% Zero-Trust compliance.",
                estimated_duration="2 mins (Golden AMI Bake)"
            ),
            "Plan B (Fast Network Quarantine Lockdown)": RemediationPlan(
                plan_id="PLAN_B",
                name="Fast Network Quarantine Lockdown",
                description="Revokes public ingress rules without re-encrypting underlying storage volumes.",
                target_risk_score=75,
                actions=["LOCK_SECURITY_GROUP_INGRESS"],
                trade_off_notes="Executes in <30 seconds, but unencrypted storage remains exposed to physical or hypervisor risks.",
                estimated_duration="< 30 seconds"
            ),
            "Plan C (Regulatory Baseline Hardening)": RemediationPlan(
                plan_id="PLAN_C",
                name="CIS & KMS Compliance Baseline",
                description="Enforces KMS storage encryption and CIS SSH hardening for compliance audits.",
                target_risk_score=85,
                actions=["ENABLE_KMS_CMK_ENCRYPTION", "APPLY_CIS_LEVEL1_OS_HARDENING"],
                trade_off_notes="Satisfies regulatory compliance checks while leaving existing security groups intact.",
                estimated_duration="1.5 mins"
            )
        }

        blackboard.log_trace(self.name, f"Assessment finalized with verdict: {blackboard.supervisor_verdict}")
        return blackboard