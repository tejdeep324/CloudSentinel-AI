import copy
import time
from typing import Dict, Any, List, Union
from core.scoring import calculate_risk_score

class HardeningEngine:
    """Applies Zero-Trust security transformations to quarantined cloud workload payloads."""

    @classmethod
    def apply_hardening(cls, quarantined_payload: Dict[str, Any], plan_name: str = "Plan A") -> Dict[str, Any]:
        """Produces an immutable, CIS/PCI-DSS compliant hardened payload."""
        hardened = copy.deepcopy(quarantined_payload) if isinstance(quarantined_payload, dict) else {}
        timestamp = int(time.time())

        # 1. AMI Baking & Identification
        hardened["ami_id"] = f"ami-cloudsentinel-golden-{timestamp}"
        hardened["hardened_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        hardened["applied_plan"] = plan_name

        plan_lower = str(plan_name).lower()
        is_plan_b = "plan b" in plan_lower or "fast network" in plan_lower
        is_plan_c = "plan c" in plan_lower or "regulatory" in plan_lower or "cis & kms" in plan_lower

        # Determine which actions apply based on the plan
        apply_storage = not is_plan_b
        apply_network = not is_plan_c
        apply_iam = not (is_plan_b or is_plan_c)
        apply_os = not is_plan_b

        # 2. Storage Domain: KMS CMK AES-256 Volume Encryption
        if apply_storage:
            if "storage" not in hardened or not isinstance(hardened["storage"], dict):
                hardened["storage"] = {}
            hardened["storage"]["encrypted"] = True
            hardened["storage"]["kms_key_id"] = "arn:aws:kms:us-east-1:123456789012:key/cloudsentinel-cmk-golden"

        # 3. Network Domain: Revoke Public Ingress & Strip Public IP
        if apply_network:
            if "network" not in hardened or not isinstance(hardened["network"], dict):
                hardened["network"] = {}
            hardened["network"]["public_ip_assigned"] = False

            hardened_rules = []
            original_rules = hardened["network"].get("security_group_rules", [])
            for rule in original_rules:
                if isinstance(rule, dict):
                    r = copy.deepcopy(rule)
                    port = r.get("port")
                    # Restrict SSH (22), RDP (3389), MySQL (3306), Postgres (5432), MongoDB (27017)
                    if port in [22, 3389, 3306, 5432, 27017]:
                        r["source"] = "10.0.0.0/16"
                        r["status"] = "RESTRICTED_TO_VPC"
                    hardened_rules.append(r)

            if not hardened_rules:
                hardened_rules = [
                    {"port": 22, "protocol": "tcp", "source": "10.0.0.0/16", "status": "RESTRICTED_TO_VPC"},
                    {"port": 443, "protocol": "tcp", "source": "0.0.0.0/0", "status": "SECURE_HTTPS"}
                ]
            hardened["network"]["security_group_rules"] = hardened_rules

        # 4. IAM Domain: Attach Scoped Least-Privilege Role
        if apply_iam:
            if "iam" not in hardened or not isinstance(hardened["iam"], dict):
                hardened["iam"] = {}
            hardened["iam"]["attached_role"] = "CloudSentinelScopedMigrationRole"
            hardened["iam"]["least_privilege_compliant"] = True

        # 5. OS Domain: Enforce CIS Level 1 Benchmark
        if apply_os:
            if "os_security" not in hardened or not isinstance(hardened["os_security"], dict):
                hardened["os_security"] = {}
            hardened["os_security"]["root_login_enabled"] = False
            hardened["os_security"]["password_auth_enabled"] = False
            hardened["os_security"]["cis_benchmark_compliant"] = True

        # 6. Package CVEs: Apply Virtual Patching
        if "packages" in hardened and isinstance(hardened["packages"], list):
            for pkg in hardened["packages"]:
                if isinstance(pkg, dict):
                    pkg["status"] = "PATCHED_TO_LATEST_SECURE_VERSION"

        return hardened

    @classmethod
    def remediate_workload(cls, quarantined_payload: Dict[str, Any], plan_name: str = "Plan A") -> Dict[str, Any]:
        return cls.apply_hardening(quarantined_payload, plan_name)

    @staticmethod
    def compute_delta(pre_payload: Dict[str, Any], post_payload: Dict[str, Any]) -> List[Dict[str, str]]:
        """Calculates human-readable before-and-after configuration deltas."""
        if not isinstance(pre_payload, dict):
            pre_payload = {}
        if not isinstance(post_payload, dict):
            post_payload = {}

        deltas: List[Dict[str, str]] = []
        
        # 1. Storage Delta
        pre_storage = pre_payload.get("storage") or {}
        post_storage = post_payload.get("storage") or {}
        pre_enc = pre_storage.get("encrypted", False)
        post_enc = post_storage.get("encrypted", False)
        kms_id = str(post_storage.get("kms_key_id", "")).split("/")[-1] if post_storage.get("kms_key_id") else "CMK"
        
        deltas.append({
            "Security Domain": "🔒 Storage Layer",
            "Pre-Remediation State (Quarantine)": "Unencrypted Plaintext EBS" if not pre_enc else "Standard Encrypted EBS",
            "Post-Remediation State (Golden AMI)": f"KMS CMK Encrypted ({kms_id})" if post_enc else "Unencrypted Plaintext EBS",
            "Compliance Impact": "PCI-DSS Req 3.4 & SOC2 CC6.6 Satisfied (REMEDIATED)" if post_enc else "Storage Encryption Deferred"
        })

        # 2. Network Delta
        pre_net = pre_payload.get("network") or {}
        post_net = post_payload.get("network") or {}
        post_rules = post_net.get("security_group_rules") or []
        has_post_open = any(
            isinstance(r, dict) and r.get("source") in ["0.0.0.0/0", "::/0"] and r.get("port") in [22, 3389, 3306, 5432, 27017]
            for r in post_rules
        )

        deltas.append({
            "Security Domain": "🌐 Network Perimeter",
            "Pre-Remediation State (Quarantine)": "Public Ingress Open to 0.0.0.0/0 (Ports 22/3389)",
            "Post-Remediation State (Golden AMI)": "Strict Ingress Filtered to Private VPC (10.0.0.0/16)" if not has_post_open else "Public Ingress Maintained",
            "Compliance Impact": "PCI-DSS Req 1.3 & SOC2 CC6.1 Satisfied (REMEDIATED)" if not has_post_open else "Perimeter Lockdown Deferred"
        })

        # 3. IAM Delta
        pre_iam = pre_payload.get("iam") or {}
        post_iam = post_payload.get("iam") or {}
        post_is_least = post_iam.get("least_privilege_compliant", False)
        post_role = post_iam.get("attached_role", "ScopedRole")

        deltas.append({
            "Security Domain": "🔑 IAM Governance",
            "Pre-Remediation State (Quarantine)": f"Wildcard Administrator Role ({pre_iam.get('attached_role', 'AdministratorAccess')})",
            "Post-Remediation State (Golden AMI)": f"Scoped Least-Privilege Role ({post_role})" if post_is_least else f"Original Role ({post_role})",
            "Compliance Impact": "Principle of Least Privilege Enforced (REMEDIATED)" if post_is_least else "IAM Scope Modification Deferred"
        })

        # 4. OS Baseline Delta
        post_os = post_payload.get("os_security") or {}
        post_cis = post_os.get("cis_benchmark_compliant", False)

        deltas.append({
            "Security Domain": "🛡️ OS Hardening",
            "Pre-Remediation State (Quarantine)": "SSH Root Login & Password Auth Permitted",
            "Post-Remediation State (Golden AMI)": "CIS Level 1 Hardened (Key-Only Auth, Root Disabled)" if post_cis else "Unhardened OS Baseline",
            "Compliance Impact": "CIS Benchmark v1.0.0 Compliant (REMEDIATED)" if post_cis else "OS Hardening Deferred"
        })

        return deltas


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