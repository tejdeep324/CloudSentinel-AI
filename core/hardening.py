import copy
import time
from typing import Dict, Any, List, Optional

class HardeningEngine:
    """Executes automated remediation to bake a Zero-Trust Golden AMI."""

    @staticmethod
    def remediate_workload(payload: Dict[str, Any], plan_name: str) -> Dict[str, Any]:
        hardened = copy.deepcopy(payload) if isinstance(payload, dict) else {}
        hardened["ami_id"] = f"ami-hardened-golden-{int(time.time())}"
        
        # 1. Enforce KMS CMK Storage Encryption
        if "storage" not in hardened or not isinstance(hardened["storage"], dict):
            hardened["storage"] = {}
        hardened["storage"]["encrypted"] = True
        hardened["storage"]["kms_key_id"] = "arn:aws:kms:us-east-1:111122223333:key/cloudsentinel-cmk-01"

        # 2. Lock Down Network Security Group Ingress
        if "network" not in hardened or not isinstance(hardened["network"], dict):
            hardened["network"] = {}
        hardened["network"]["public_ip_assigned"] = False
        
        safe_rules = []
        for rule in hardened["network"].get("security_group_rules", []):
            if isinstance(rule, dict):
                r = copy.deepcopy(rule)
                if r.get("port") in [22, 3389, 3306, 5432, 27017]:
                    r["source"] = "10.0.0.0/16"
                    r["status"] = "RESTRICTED_TO_VPC"
                safe_rules.append(r)
        hardened["network"]["security_group_rules"] = safe_rules

        # 3. Apply Principle of Least Privilege to IAM Profile
        if "iam" not in hardened or not isinstance(hardened["iam"], dict):
            hardened["iam"] = {}
        hardened["iam"]["attached_role"] = "CloudSentinelScopedMigrationRole"
        hardened["iam"]["least_privilege_compliant"] = True

        # 4. OS CIS Level 1 Hardening
        if "os_security" not in hardened or not isinstance(hardened["os_security"], dict):
            hardened["os_security"] = {}
        hardened["os_security"]["root_login_enabled"] = False
        hardened["os_security"]["password_auth_enabled"] = False
        hardened["os_security"]["cis_benchmark_compliant"] = True

        return hardened

    @staticmethod
    def compute_delta(pre_payload: Dict[str, Any], post_payload: Dict[str, Any]) -> List[Dict[str, str]]:
        """Calculates human-readable before-and-after configuration deltas."""
        deltas: List[Dict[str, str]] = []
        
        # 1. Storage Delta
        pre_storage = pre_payload.get("storage") or {}
        post_storage = post_payload.get("storage") or {}
        pre_enc = pre_storage.get("encrypted", False)
        post_enc = post_storage.get("encrypted", False)
        
        deltas.append({
            "Security Domain": "🔒 Storage Layer",
            "Pre-Remediation State (Quarantine)": "Unencrypted Plaintext EBS" if not pre_enc else "Standard Encryption",
            "Post-Remediation State (Golden AMI)": f"KMS CMK Encrypted ({post_storage.get('kms_key_id', '').split('/')[-1]})" if post_enc else "Unencrypted",
            "Compliance Impact": "PCI-DSS Req 3.4 & SOC2 CC6.6 Satisfied"
        })

        # 2. Network Delta
        deltas.append({
            "Security Domain": "🌐 Network Perimeter",
            "Pre-Remediation State (Quarantine)": "Public Ingress Open to 0.0.0.0/0 (Ports 22/3389)",
            "Post-Remediation State (Golden AMI)": "Strict Ingress Filtered to Private VPC (10.0.0.0/16)",
            "Compliance Impact": "PCI-DSS Req 1.3 & SOC2 CC6.1 Satisfied"
        })

        # 3. IAM Delta
        pre_iam = pre_payload.get("iam") or {}
        post_iam = post_payload.get("iam") or {}
        deltas.append({
            "Security Domain": "🔑 IAM Governance",
            "Pre-Remediation State (Quarantine)": f"Wildcard Administrator Role ({pre_iam.get('attached_role', 'AdministratorAccess')})",
            "Post-Remediation State (Golden AMI)": f"Scoped Least-Privilege Role ({post_iam.get('attached_role', 'ScopedRole')})",
            "Compliance Impact": "Principle of Least Privilege Enforced"
        })

        # 4. OS Baseline Delta
        deltas.append({
            "Security Domain": "🛡️ OS Hardening",
            "Pre-Remediation State (Quarantine)": "SSH Root Login & Password Auth Permitted",
            "Post-Remediation State (Golden AMI)": "CIS Level 1 Hardened (Key-Only Auth, Root Disabled)",
            "Compliance Impact": "CIS Benchmark v1.0.0 Compliant"
        })

        return deltas


class VerificationScanner:
    """Performs closed-loop post-hardening verification scanning."""

    @staticmethod
    def verify(pre_score: int, post_score: int, threshold: int = 90) -> Dict[str, Any]:
        passed = bool(post_score >= threshold)
        return {
            "verification_passed": passed,
            "status": "PASSED (Security Posture Verified)" if passed else "FAILED (Threshold Not Met)",
            "score_delta": f"+{post_score - pre_score} pts",
            "threshold_required": threshold
        }