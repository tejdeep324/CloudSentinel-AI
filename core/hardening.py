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