import os
import sys
from typing import Dict, Any, List

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def unwrap_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Unwraps payload if it is nested inside an audit manifest or report wrapper."""
    if not isinstance(payload, dict):
        return {}
    if "golden_ami_manifest" in payload and isinstance(payload["golden_ami_manifest"], dict):
        return payload["golden_ami_manifest"]
    if "hardened_payload" in payload and isinstance(payload["hardened_payload"], dict):
        return payload["hardened_payload"]
    if "workload_payload" in payload and isinstance(payload["workload_payload"], dict):
        return payload["workload_payload"]
    if "manifest" in payload and isinstance(payload["manifest"], dict) and "storage" in payload["manifest"]:
        return payload["manifest"]
    if "workload" in payload and isinstance(payload["workload"], dict) and "storage" in payload["workload"]:
        return payload["workload"]
    return payload

def calculate_risk_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates cloud workload telemetry across 4 security domains (Max: 100 points).
    - Storage Encryption: 25 pts (CMK: 25 pts, AWS Default: 15 pts, Plaintext: 0 pts)
    - Network Perimeter: 30 pts (Granular per-port penalties: SSH -10, RDP -15, DB -20, Public IP -5)
    - IAM Least Privilege: 25 pts (Scoped: 25 pts, Over-privileged: 15 pts, Wildcard Admin: 5 pts)
    - OS CIS Baseline: 20 pts (Additively penalizes Root login, Password auth, and CIS non-compliance)
    """
    if not isinstance(payload, dict) or not payload:
        return {
            "total_score": 100,
            "breakdown": {"storage": 25, "network": 30, "iam": 25, "os_security": 20},
            "category_breakdown": {"storage": 25, "network": 30, "iam": 25, "os_security": 20},
            "deductions": [],
            "status": "APPROVED"
        }

    payload = unwrap_payload(payload)
    breakdown = {}
    deductions: List[str] = []

    # 1. Storage Domain (Max 25 pts)
    storage_data = payload.get("storage") or {}
    if storage_data.get("encrypted", False) is True:
        kms_key = str(storage_data.get("kms_key_id") or "")
        if kms_key and not kms_key.startswith("alias/aws/ebs") and "aws-managed" not in kms_key.lower():
            storage_score = 25
        else:
            storage_score = 15
            deductions.append("Default AWS-managed key used instead of Customer-Managed Key (CMK): -10 pts")
    else:
        storage_score = 0
        deductions.append("EBS root volume is unencrypted (Plaintext data at rest risk: -25 pts)")
    breakdown["storage"] = storage_score
    breakdown["storage_score"] = storage_score

    # 2. Network Domain (Max 30 pts)
    network_data = payload.get("network") or {}
    sg_rules = network_data.get("security_group_rules") or []
    net_deductions = 0

    seen_ports = set()
    for rule in sg_rules:
        if isinstance(rule, dict):
            src = str(rule.get("source", ""))
            port = rule.get("port")
            if src in ["0.0.0.0/0", "::/0", "0.0.0.0/0;"] and port not in seen_ports:
                seen_ports.add(port)
                if port == 22:
                    net_deductions += 10
                    deductions.append("Unrestricted SSH ingress (0.0.0.0/0 on Port 22): -10 pts")
                elif port == 3389:
                    net_deductions += 15
                    deductions.append("Unrestricted RDP ingress (0.0.0.0/0 on Port 3389): -15 pts")
                elif port in [3306, 5432, 27017]:
                    net_deductions += 20
                    deductions.append(f"Unrestricted database ingress (0.0.0.0/0 on Port {port}): -20 pts")
                elif port not in [80, 443]:
                    net_deductions += 5
                    deductions.append(f"Unrestricted ingress on Port {port}: -5 pts")

    if network_data.get("public_ip_assigned", False):
        net_deductions += 5
        deductions.append("Direct public IPv4 assignment in DMZ: -5 pts")

    network_score = max(0, 30 - net_deductions)
    breakdown["network"] = network_score
    breakdown["network_score"] = network_score

    # 3. IAM Domain (Max 25 pts)
    iam_data = payload.get("iam") or {}
    attached = str(iam_data.get("attached_role", ""))
    attached_lower = attached.lower()
    is_admin = any(wildcard in attached_lower for wildcard in ["fullaccess", "admin", "administrator", "root", "*"])
    
    if is_admin:
        iam_score = 5
        deductions.append(f"Wildcard Administrator credentials attached ({attached}): -20 pts")
    elif not iam_data.get("least_privilege_compliant", True) or "poweruser" in attached_lower:
        iam_score = 15
        deductions.append(f"Over-privileged IAM role ({attached}): -10 pts")
    else:
        iam_score = 25
    breakdown["iam"] = iam_score
    breakdown["iam_score"] = iam_score

    # 4. OS CIS Security Domain (Max 20 pts)
    os_sec = payload.get("os_security") or {}
    os_deductions = 0
    if os_sec.get("root_login_enabled", False):
        os_deductions += 5
        deductions.append("OS direct root login enabled: -5 pts")
    if os_sec.get("password_auth_enabled", False):
        os_deductions += 5
        deductions.append("OS password authentication enabled (violates CIS 5.2.11): -5 pts")
    if not os_sec.get("cis_benchmark_compliant", True):
        os_deductions += 5
        deductions.append("OS CIS Level 1 baseline unhardened: -5 pts")

    os_score = max(0, 20 - os_deductions)
    breakdown["os_security"] = os_score
    breakdown["os_security_score"] = os_score

    total_score = max(0, min(100, storage_score + network_score + iam_score + os_score))

    return {
        "total_score": total_score,
        "breakdown": breakdown,
        "category_breakdown": breakdown,
        "deductions": deductions,
        "status": "APPROVED" if total_score >= 90 else "QUARANTINED"
    }