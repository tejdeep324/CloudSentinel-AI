import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def calculate_risk_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates a quantitative security score (0-100) for a cloud workload.
    
    Category Allocation:
      - Storage Encryption: 25 pts (25 if encrypted, 0 if unencrypted)
      - Network Ingress:    30 pts (30 if restricted, 10 if ports 22/3389/3306 exposed to 0.0.0.0/0)
      - IAM Least Privilege: 25 pts (25 if scoped role, 15 if admin/wildcard)
      - OS CIS Hardening:   20 pts (20 if compliant, 15 if root login enabled/unhardened)
    """
    if not payload:
        return {
            "total_score": 100,
            "category_breakdown": {
                "storage": 25,
                "network": 30,
                "iam": 25,
                "os_security": 20
            },
            "deductions": []
        }

    deductions = []

    # 1. Storage Domain (Max 25 pts)
    storage_data = payload.get("storage", {})
    if storage_data.get("encrypted", False):
        storage_score = 25
    else:
        storage_score = 0
        deductions.append("Unencrypted EBS volume: -25 pts")

    # 2. Network Domain (Max 30 pts)
    network_data = payload.get("network", {})
    sg_rules = network_data.get("security_group_rules", [])
    has_open_mgmt_ports = any(
        rule.get("source") == "0.0.0.0/0" and rule.get("port") in [22, 3389, 3306, 5432, 27017]
        for rule in sg_rules
    )
    if has_open_mgmt_ports or network_data.get("public_ip_assigned", False):
        network_score = 10
        deductions.append("Unrestricted management/database ingress or public IP: -20 pts")
    else:
        network_score = 30

    # 3. IAM Domain (Max 25 pts)
    iam_data = payload.get("iam", {})
    if iam_data.get("least_privilege_compliant", False):
        iam_score = 25
    else:
        attached = iam_data.get("attached_role", "")
        if "admin" in attached.lower() or not iam_data.get("least_privilege_compliant", True):
            iam_score = 15
            deductions.append(f"Over-privileged IAM role ({attached}): -10 pts")
        else:
            iam_score = 25

    # 4. OS CIS Security Domain (Max 20 pts)
    os_sec = payload.get("os_security", {})
    if os_sec.get("root_login_enabled", False) or not os_sec.get("cis_benchmark_compliant", True):
        os_score = 15
        deductions.append("OS root login enabled / CIS baseline unhardened: -5 pts")
    else:
        os_score = 20

    total_score = storage_score + network_score + iam_score + os_score
    total_score = max(0, min(100, total_score))

    return {
        "total_score": total_score,
        "category_breakdown": {
            "storage": storage_score,
            "network": network_score,
            "iam": iam_score,
            "os_security": os_score
        },
        "deductions": deductions
    }