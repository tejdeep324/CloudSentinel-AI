import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.base_agent import BaseAgent
from agents.state import AgentBlackboard, AgentFinding
from tools.inspector_tool import WorkloadInspectorTool
from tools.cis_benchmark_tool import CISBenchmarkTool

class SecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="SecurityAgent",
            domain="Storage Encryption & OS Baselines",
            system_prompt=(
                "You are the Security Agent for CloudSentinel AI. Inspect storage volumes, "
                "AWS KMS CMK encryption, and OS-level CIS hardening parameters."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Starting storage and OS baseline inspection.")

        # 1. Storage Inspection
        storage_check = WorkloadInspectorTool.inspect_storage_encryption(payload.get("storage"))
        if not storage_check.get("is_encrypted"):
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity="CRITICAL",
                title="Unencrypted EBS Volume",
                description="Storage volumes are completely unencrypted. Risk of data exfiltration.",
                remediation_action="ENABLE_KMS_CMK_ENCRYPTION",
                evidence=storage_check
            ))
            blackboard.log_trace(self.name, "FLAGGED: Unencrypted storage volumes detected.")

        # 2. CIS OS Baseline Check
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
            blackboard.log_trace(self.name, f"FLAGGED: {len(cis_check.get('violations', []))} CIS benchmark breaches.")


class NetworkAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="NetworkAgent",
            domain="VPC Perimeter & Ingress Governance",
            system_prompt=(
                "You are the Network Security Agent for CloudSentinel AI. Evaluate security groups, "
                "open management ports (22/3389), database ports, and internet exposure."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Auditing VPC security groups and ingress vectors.")

        exposed_ports = WorkloadInspectorTool.inspect_exposed_ports(payload.get("network"))
        for item in exposed_ports:
            port = item.get("port")
            severity = item.get("severity", "HIGH")
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity=severity,
                title=f"Unrestricted Ingress on Port {port}",
                description=f"Port {port} is open to 0.0.0.0/0, allowing unrestricted internet ingress.",
                remediation_action="LOCK_SECURITY_GROUP_INGRESS",
                evidence=item
            ))
            blackboard.log_trace(self.name, f"FLAGGED: Port {port} exposed to 0.0.0.0/0 ({severity}).")


class IAMAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="IAMAgent",
            domain="Identity & Access Governance",
            system_prompt=(
                "You are the IAM Agent for CloudSentinel AI. Enforce Principle of Least Privilege "
                "and detect over-privileged or administrative wildcard roles."
            )
        )

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        payload = blackboard.workload_payload
        blackboard.log_trace(self.name, "Auditing IAM instance profiles and permission policies.")

        iam_check = WorkloadInspectorTool.inspect_iam_privileges(payload.get("iam"))
        if iam_check.get("is_admin_wildcard"):
            blackboard.add_finding(AgentFinding(
                agent_name=self.name,
                domain=self.domain,
                severity="CRITICAL",
                title="Over-Privileged Administrative IAM Role",
                description=f"Attached role '{iam_check.get('attached_role')}' contains administrator wildcard permissions.",
                remediation_action="REPLACE_WITH_LEAST_PRIVILEGE_ROLE",
                evidence=iam_check
            ))
            blackboard.log_trace(self.name, "FLAGGED: Administrator-level IAM role detected.")


class ComplianceAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ComplianceAgent",
            domain="Regulatory Audit & Governance Mapping",
            system_prompt=(
                "You are the Compliance Agent for CloudSentinel AI. Map workload vulnerabilities "
                "to industry frameworks such as PCI-DSS, HIPAA, and SOC2."
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
                description="Workload fails mandatory regulatory encryption and isolation controls.",
                remediation_action="TRIGGER_REMEDIATION_PIPELINE",
                evidence={"framework": blackboard.target_compliance}
            ))
            blackboard.log_trace(self.name, f"VERDICT: Workload fails {blackboard.target_compliance} validation.")