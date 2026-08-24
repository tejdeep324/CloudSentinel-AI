import copy
from typing import Dict, Any

class HardeningEngine:
    @staticmethod
    def execute_remediation(payload: Dict[str, Any], plan_selected: str) -> Dict[str, Any]:
        hardened_payload = copy.deepcopy(payload)
        
        # 1. Network Hardening (VPC & Security Groups)
        hardened_payload["network"]["security_group_rules"] = [
            {"port": 443, "source": "0.0.0.0/0", "protocol": "tcp", "status": "SECURE_HTTPS"},
            {"port": 22, "source": "10.0.0.0/16", "protocol": "tcp", "status": "RESTRICTED_INTERNAL_VPC"}
        ]
        hardened_payload["network"]["open_ports"] = [443, 22]
        
        # 2. Storage Hardening (AWS KMS Encryption & Golden AMI)
        hardened_payload["storage"]["encrypted"] = True
        hardened_payload["storage"]["kms_key_id"] = "arn:aws:kms:us-east-1:123456789012:key/cmk-golden-ami-01"
        hardened_payload["ami_id"] = "ami-golden-cis-hardened-v1"

        # 3. IAM Least-Privilege Role Attachment
        hardened_payload["iam"]["attached_role"] = "CloudSentinelLeastPrivilegeExecutionRole"
        hardened_payload["iam"]["least_privilege_compliant"] = True

        # 4. OS Hardening (CIS Benchmark)
        hardened_payload["os_security"]["root_login_enabled"] = False
        hardened_payload["os_security"]["password_auth_enabled"] = False
        hardened_payload["os_security"]["cis_benchmark_compliant"] = True

        return hardened_payload

class VerificationScanner:
    @staticmethod
    def verify(pre_score: int, post_score: int) -> Dict[str, Any]:
        passed = post_score >= 90
        return {
            "verification_passed": passed,
            "status": "VERIFIED_SECURE_GOLDEN_AMI" if passed else "VERIFICATION_FAILED_TRIGGER_ROLLBACK",
            "score_delta": f"+{post_score - pre_score} points improvement",
            "production_ready": passed
        }