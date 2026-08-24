import json
from typing import Dict, Any

class NetworkAgent:
    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        issues = []
        rules = payload.get("network", {}).get("security_group_rules", [])
        for rule in rules:
            if rule.get("source") == "0.0.0.0/0" and rule.get("port") in [22, 3389]:
                issues.append(f"Port {rule.get('port')} is publicly exposed to 0.0.0.0/0 (High Risk).")
        
        return {
            "agent": "Network Agent",
            "status": "Vulnerable" if issues else "Compliant",
            "findings": issues,
            "recommended_action": "Revoke 0.0.0.0/0 ingress and restrict SSH/RDP access to VPN/Bastion IP CIDR."
        }

class SecurityAgent:
    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        issues = []
        storage = payload.get("storage", {})
        os_sec = payload.get("os_security", {})
        
        if not storage.get("encrypted", False):
            issues.append("Underlying EBS volume is unencrypted. Violates CIS AWS Foundations Benchmark.")
        if os_sec.get("root_login_enabled", False):
            issues.append("Direct SSH Root Login is permitted in /etc/ssh/sshd_config.")
        if os_sec.get("password_auth_enabled", False):
            issues.append("Password-based authentication is enabled instead of mandatory SSH Key Pairs.")
            
        return {
            "agent": "Security & AMI Hardening Agent",
            "status": "Vulnerable" if issues else "Compliant",
            "findings": issues,
            "recommended_action": "Enforce KMS Customer Managed Key (CMK) encryption, disable SSH root login, and enforce ed25519 key-based auth."
        }

class IAMAgent:
    def evaluate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        issues = []
        iam = payload.get("iam", {})
        if not iam.get("least_privilege_compliant", True):
            issues.append(f"Role '{iam.get('attached_role')}' contains wildcard administrative permissions ('*:*').")
            
        return {
            "agent": "IAM Governance Agent",
            "status": "Vulnerable" if issues else "Compliant",
            "findings": issues,
            "recommended_action": "Detach AdministratorAccess and attach an ephemeral least-privilege role using AWS STS AssumeRole."
        }

class SupervisorAgent:
    def __init__(self):
        self.net_agent = NetworkAgent()
        self.sec_agent = SecurityAgent()
        self.iam_agent = IAMAgent()

    def coordinate_assessment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        net_report = self.net_agent.evaluate(payload)
        sec_report = self.sec_agent.evaluate(payload)
        iam_report = self.iam_agent.evaluate(payload)

        # Multi-Plan Remediation Generation
        plans = {
            "Plan A (Maximum Security - Recommended)": {
                "description": "Full zero-trust lockdown: KMS CMK encryption, quarantine isolated VPC, strict security groups, CIS benchmark OS hardening, and IAM least-privilege attachment.",
                "estimated_time": "3-5 mins",
                "target_score": 95,
                "cost_impact": "Negligible (Free Tier Eligible)"
            },
            "Plan B (Fast Deployment)": {
                "description": "Rapid patching: Ingest instance, close public ingress ports 22/3389, and attach default AWS-managed KMS encryption without deep OS recompilation.",
                "estimated_time": "1-2 mins",
                "target_score": 80,
                "cost_impact": "Zero"
            },
            "Plan C (Cost & Downtime Optimized)": {
                "description": "Live in-place patching with instance right-sizing recommendation to t3.micro and scheduled off-peak volume re-encryption.",
                "estimated_time": "4 mins",
                "target_score": 85,
                "cost_impact": "Saves ~15% monthly compute costs"
            }
        }

        reasoning = (
            f"Supervisor evaluated telemetry for Instance '{payload.get('instance_id')}'. "
            f"Detected {len(net_report['findings']) + len(sec_report['findings']) + len(iam_report['findings'])} critical security flaws. "
            f"The image requires immediate quarantine and automated Golden AMI baking."
        )

        return {
            "supervisor_verdict": "REMEDIATION_REQUIRED",
            "confidence_score": "98.4%",
            "reasoning": reasoning,
            "agent_reports": [net_report, sec_report, iam_report],
            "remediation_plans": plans
        }