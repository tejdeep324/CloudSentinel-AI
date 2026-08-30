import copy
import time
from typing import Dict, Any, List, Union
from core.scoring import calculate_risk_score

class HardeningEngine:
    """Applies Zero-Trust security transformations to quarantined cloud workload payloads."""

    @classmethod
    def apply_hardening(cls, quarantined_payload: Dict[str, Any], plan_name: str = "Plan A") -> Dict[str, Any]:
        """Produces an immutable, CIS/PCI-DSS compliant hardened payload."""
        hardened = copy.deepcopy(quarantined_payload)
        timestamp = int(time.time())

        # 1. AMI Baking & Identification
        hardened["ami_id"] = f"ami-cloudsentinel-golden-{timestamp}"
        hardened["hardened_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        hardened["applied_plan"] = plan_name

        # 2. Storage Domain: KMS CMK AES-256 Volume Encryption
        if "storage" not in hardened:
            hardened["storage"] = {}
        hardened["storage"]["encrypted"] = True
        if not hardened["storage"].get("kms_key_id"):
            hardened["storage"]["kms_key_id"] = "arn:aws:kms:us-east-1:123456789012:key/cloudsentinel-cmk-golden"

        # 3. Network Domain: Revoke Public Ingress & Strip Public IP
        if "network" not in hardened:
            hardened["network"] = {}
        
        # Enforce Private VPC Subnet Placement (No Public IP)
        hardened["network"]["public_ip_assigned"] = False

        # Restrict Ingress to internal management CIDRs (10.0.0.0/16)
        hardened_rules = []
        original_rules = hardened["network"].get("security_group_rules", [])
        for rule in original_rules:
            port = rule.get("port")
            proto = rule.get("protocol", "tcp")
            
            # Restrict SSH (22), RDP (3389), MySQL (3306), Postgres (5432), MongoDB (27017)
            if port in [22, 3389, 3306, 5432, 27017]:
                hardened_rules.append({
                    "port": port,
                    "protocol": proto,
                    "source": "10.0.0.0/16"
                })
            else:
                hardened_rules.append(rule)

        if not hardened_rules:
            hardened_rules = [
                {"port": 22, "protocol": "tcp", "source": "10.0.0.0/16"},
                {"port": 443, "protocol": "tcp", "source": "0.0.0.0/0"}
            ]
        hardened["network"]["security_group_rules"] = hardened_rules

        # 4. IAM Domain: Attach Scoped Least-Privilege Role
        if "iam" not in hardened:
            hardened["iam"] = {}
        hardened["iam"]["attached_role"] = "CloudSentinelScopedMigrationRole"
        hardened["iam"]["least_privilege_compliant"] = True

        # 5. OS Domain: Enforce CIS Level 1 Benchmark
        if "os_security" not in hardened:
            hardened["os_security"] = {}
        hardened["os_security"]["root_login_enabled"] = False
        hardened["os_security"]["password_auth_enabled"] = False
        hardened["os_security"]["cis_benchmark_compliant"] = True

        # 6. Package CVEs: Apply Virtual Patching
        if "packages" in hardened:
            for pkg in hardened["packages"]:
                pkg["status"] = "PATCHED_TO_LATEST_SECURE_VERSION"

        return hardened

    @classmethod
    def remediate_workload(cls, quarantined_payload: Dict[str, Any], plan_name: str = "Plan A") -> Dict[str, Any]:
        return cls.apply_hardening(quarantined_payload, plan_name)

    @staticmethod
    def compute_delta(pre_payload: Dict[str, Any], post_payload: Dict[str, Any]) -> List[Dict[str, str]]:
        """Computes structural before/after delta for UI display."""
        pre_storage = "Encrypted (KMS)" if pre_payload.get("storage", {}).get("encrypted") else "Plaintext (UNENCRYPTED)"
        post_storage = "Encrypted (KMS AES-256)" if post_payload.get("storage", {}).get("encrypted") else "Plaintext"

        pre_net = "Public IP + Open 0.0.0.0/0" if pre_payload.get("network", {}).get("public_ip_assigned") else "Private CIDR"
        post_net = "Private Isolated VPC (10.0.0.0/16)" if not post_payload.get("network", {}).get("public_ip_assigned") else "Public"

        pre_iam = pre_payload.get("iam", {}).get("attached_role", "AdministratorAccess (Overprivileged)")
        post_iam = post_payload.get("iam", {}).get("attached_role", "CloudSentinelScopedMigrationRole (Least Privilege)")

        pre_os = "Root SSH Allowed" if pre_payload.get("os_security", {}).get("root_login_enabled") else "CIS Compliant"
        post_os = "CIS Level 1 Hardened (Root SSH Disabled)"

        return [
            {"Security Domain": "Storage (EBS/KMS)", "Quarantined State": str(pre_storage), "Hardened Golden State": str(post_storage)},
            {"Security Domain": "Network Perimeter", "Quarantined State": str(pre_net), "Hardened Golden State": str(post_net)},
            {"Security Domain": "IAM Governance", "Quarantined State": str(pre_iam), "Hardened Golden State": str(post_iam)},
            {"Security Domain": "OS CIS Baseline", "Quarantined State": str(pre_os), "Hardened Golden State": str(post_os)},
        ]


class VerificationScanner:
    """Verifies hardened workloads against Zero-Trust policy thresholds."""

    @staticmethod
    def verify(
        pre_input: Union[Dict[str, Any], int, float] = None,
        post_input: Union[Dict[str, Any], int, float] = None,
        threshold: int = 90,
        pre_score: int = None,
        post_score: int = None
    ) -> Dict[str, Any]:
        """
        Accepts either (pre_payload, post_payload) or direct numeric scores (pre_score, post_score).
        """
        if pre_score is not None and post_score is not None:
            final_pre = pre_score
            final_post = post_score
            deductions_remaining = []
        elif isinstance(pre_input, (int, float)) and isinstance(post_input, (int, float)):
            final_pre = int(pre_input)
            final_post = int(post_input)
            deductions_remaining = []
        else:
            pre_eval = calculate_risk_score(pre_input if isinstance(pre_input, dict) else {})
            post_eval = calculate_risk_score(post_input if isinstance(post_input, dict) else {})
            final_pre = pre_eval["total_score"]
            final_post = post_eval["total_score"]
            deductions_remaining = post_eval.get("deductions", [])

        delta = final_post - final_pre
        passed = final_post >= threshold

        return {
            "verified": passed,
            "passed": passed,
            "verification_passed": passed,
            "pre_score": final_pre,
            "post_score": final_post,
            "score_delta": f"+{delta}" if delta >= 0 else str(delta),
            "status": "APPROVED_FOR_PRODUCTION" if passed else "RE_QUARANTINED",
            "deductions_remaining": deductions_remaining
        }