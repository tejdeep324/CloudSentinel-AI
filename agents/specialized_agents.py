import os
import sys
from typing import Dict, Any

# Guarantee root path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base_agent import BaseAgent
from agents.state import AgentBlackboard, AgentFinding
from agents.llm_engine import GoogleAgentEngine
from tools.inspector_tool import WorkloadInspectorTool
from tools.cis_benchmark_tool import CISBenchmarkTool

llm_engine = GoogleAgentEngine()

# ==========================================
# 1. SECURITY AGENT (Storage & OS)
# ==========================================

class SecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="SecurityAgent",
            domain="Storage Encryption & OS Baselines",
            system_prompt=(
                "You are the Security Agent for CloudSentinel AI. Evaluate storage volume encryption (AWS KMS CMK) "
                "and OS CIS Level 1 hardening baselines (SSH root access, password authentication). "
                "Flag critical vulnerabilities immediately."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Starting storage and OS baseline inspection.")

        # Prune context: pass only storage and OS parameters
        scoped_data = {
            "instance_id": payload.get("instance_id"),
            "storage": payload.get("storage", {}),
            "os_security": payload.get("os_security", {})
        }

        # 1. Try Gemini GenAI Agent First
        llm_response = llm_engine.analyze_domain_sync(self.domain, self.system_prompt, scoped_data)
        if llm_response and llm_response.findings:
            blackboard.log_trace(self.name, f"[Gemini 2.5 Flash] Analysis complete: {llm_response.reasoning}")
            for item in llm_response.findings:
                blackboard.add_finding(AgentFinding(
                    agent_name=self.name,
                    domain=self.domain,
                    severity=item.severity,
                    title=item.title,
                    description=item.description,
                    remediation_action=item.action,
                    confidence=item.confidence
                ))
            return

        # 2. Deterministic Tool Fallback
        blackboard.log_trace(self.name, "[Deterministic Tool] Running local security inspector.")
        storage_check = WorkloadInspectorTool.inspect_storage_encryption(payload.get("storage"))
        if not storage_check.get("is_encrypted"):
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity="CRITICAL",
                title="Unencrypted EBS Volume",
                description="Storage volumes are unencrypted plaintext. High risk of data exposure.",
                remediation_action="ENABLE_KMS_CMK_ENCRYPTION",
                evidence=storage_check
            ))

        cis_check = CISBenchmarkTool.evaluate_os_baseline(payload.get("os_security"))
        if not cis_check.get("compliant"):
            for violation in cis_check.get("violations", []):
                blackboard.add_finding(AgentFinding(
                    agent_name=self.name,
                    domain=self.domain,
                    severity="HIGH",
                    title="CIS OS Baseline Breach",
                    description=violation,
                    remediation_action="APPLY_CIS_LEVEL1_OS_HARDENING",
                    evidence=cis_check
                ))


# ==========================================
# 2. NETWORK AGENT (Perimeter & Ingress)
# ==========================================

class NetworkAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="NetworkAgent",
            domain="VPC Perimeter & Ingress Governance",
            system_prompt=(
                "You are the Network Security Agent for CloudSentinel AI. Inspect Security Group inbound rules. "
                "Flag open management ports (22, 3389) or open database ports (3306, 5432, 27017) exposed to 0.0.0.0/0."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Auditing VPC security groups and ingress vectors.")

        scoped_data = {
            "instance_id": payload.get("instance_id"),
            "network": payload.get("network", {})
        }

        # 1. Try Gemini GenAI Agent First
        llm_response = llm_engine.analyze_domain_sync(self.domain, self.system_prompt, scoped_data)
        if llm_response and llm_response.findings:
            blackboard.log_trace(self.name, f"[Gemini 2.5 Flash] Analysis complete: {llm_response.reasoning}")
            for item in llm_response.findings:
                blackboard.add_finding(AgentFinding(
                    agent_name=self.name,
                    domain=self.domain,
                    severity=item.severity,
                    title=item.title,
                    description=item.description,
                    remediation_action=item.action,
                    confidence=item.confidence
                ))
            return

        # 2. Deterministic Tool Fallback
        blackboard.log_trace(self.name, "[Deterministic Tool] Running local network inspector.")
        exposed_ports = WorkloadInspectorTool.inspect_exposed_ports(payload.get("network"))
        for item in exposed_ports:
            port = item.get("port")
            severity = item.get("severity", "HIGH")
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity=severity,
                title=f"Unrestricted Ingress on Port {port}",
                description=f"Port {port} is open to 0.0.0.0/0, allowing public access.",
                remediation_action="LOCK_SECURITY_GROUP_INGRESS",
                evidence=item
            ))


# ==========================================
# 3. IAM AGENT (Least Privilege)
# ==========================================

class IAMAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="IAMAgent",
            domain="Identity & Access Governance",
            system_prompt=(
                "You are the IAM Agent for CloudSentinel AI. Detect over-privileged administrative roles "
                "(AdministratorAccess or wildcard '*' actions) and enforce Principle of Least Privilege."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Auditing IAM instance profiles and permission policies.")

        scoped_data = {
            "instance_id": payload.get("instance_id"),
            "iam": payload.get("iam", {})
        }

        # 1. Try Gemini GenAI Agent First
        llm_response = llm_engine.analyze_domain_sync(self.domain, self.system_prompt, scoped_data)
        if llm_response and llm_response.findings:
            blackboard.log_trace(self.name, f"[Gemini 2.5 Flash] Analysis complete: {llm_response.reasoning}")
            for item in llm_response.findings:
                blackboard.add_finding(AgentFinding(
                    agent_name=self.name,
                    domain=self.domain,
                    severity=item.severity,
                    title=item.title,
                    description=item.description,
                    remediation_action=item.action,
                    confidence=item.confidence
                ))
            return

        # 2. Deterministic Tool Fallback
        blackboard.log_trace(self.name, "[Deterministic Tool] Running local IAM inspector.")
        iam_check = WorkloadInspectorTool.inspect_iam_privileges(payload.get("iam"))
        if iam_check.get("is_admin_wildcard"):
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity="CRITICAL",
                title="Over-Privileged Administrative IAM Role",
                description=f"Role '{iam_check.get('attached_role')}' contains wildcard administrator privileges.",
                remediation_action="REPLACE_WITH_LEAST_PRIVILEGE_ROLE",
                evidence=iam_check
            ))


# ==========================================
# 4. COMPLIANCE AGENT (Framework Mapping)
# ==========================================

class ComplianceAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ComplianceAgent",
            domain="Regulatory Audit & Governance Mapping",
            system_prompt=(
                "You are the Compliance Agent for CloudSentinel AI. Map workload vulnerabilities "
                "to PCI-DSS, HIPAA, and SOC 2 frameworks."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        blackboard.log_trace(self.name, f"Mapping findings against framework: {blackboard.target_compliance}")
        
        has_critical = any(f.severity == "CRITICAL" for f in blackboard.findings)
        if has_critical:
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity="HIGH",
                title=f"Non-Compliant with {blackboard.target_compliance}",
                description="Workload violates mandatory regulatory storage encryption and perimeter isolation controls.",
                remediation_action="TRIGGER_REMEDIATION_PIPELINE",
                evidence={"framework": blackboard.target_compliance}
            ))
            blackboard.log_trace(self.name, f"VERDICT: Workload fails {blackboard.target_compliance} validation.")