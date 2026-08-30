from typing import Dict, Any, List

def calculate_risk_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates cloud workload telemetry across 4 security domains (Max: 100 points).
    - Storage Encryption: 25 pts
    - Network Perimeter: 30 pts
    - IAM Least Privilege: 25 pts
    - OS CIS Baseline: 20 pts
    """
    breakdown = {}
    deductions: List[str] = []

    # 1. Storage Domain (Max 25 pts)
    storage = payload.get("storage", {})
    if storage.get("encrypted") is True:
        storage_score = 25
    else:
        storage_score = 0
        deductions.append("EBS root volume is unencrypted (Plaintext data at rest risk: -25 pts)")
    breakdown["storage"] = storage_score
    breakdown["storage_score"] = storage_score

    # 2. Network Domain (Max 30 pts)
    network = payload.get("network", {})
    sg_rules = network.get("security_group_rules", [])
    has_public_ip = network.get("public_ip_assigned", False)

    sensitive_ports = [22, 3389, 3306, 5432, 27017]
    open_sensitive_ports = []

    for rule in sg_rules:
        port = rule.get("port")
        source = rule.get("source", "")
        if port in sensitive_ports and source in ["0.0.0.0/0", "::/0", "0.0.0.0/0;"]:
            open_sensitive_ports.append(port)

    if not open_sensitive_ports and not has_public_ip:
        network_score = 30
    elif not open_sensitive_ports and has_public_ip:
        network_score = 20
        deductions.append("Public IP is assigned to workload instance (-10 pts)")
    else:
        network_score = 10
        deductions.append(f"Unrestricted public ingress (0.0.0.0/0) detected on ports {open_sensitive_ports} (-20 pts)")
    breakdown["network"] = network_score
    breakdown["network_score"] = network_score

    # 3. IAM Domain (Max 25 pts)
    iam = payload.get("iam", {})
    role = iam.get("attached_role", "")
    is_least_priv = iam.get("least_privilege_compliant", False)

    if is_least_priv or (role and "admin" not in role.lower() and role != "None" and role != "PowerUserAccess"):
        iam_score = 25
    else:
        iam_score = 15
        deductions.append(f"Over-privileged IAM role '{role}' attached to compute profile (-10 pts)")
    breakdown["iam"] = iam_score
    breakdown["iam_score"] = iam_score

    # 4. OS Security & CIS Baseline (Max 20 pts)
    os_sec = payload.get("os_security", {})
    root_login = os_sec.get("root_login_enabled", True)
    cis_compliant = os_sec.get("cis_benchmark_compliant", False)

    if cis_compliant and not root_login:
        os_score = 20
    elif not root_login:
        os_score = 18
    else:
        os_score = 15
        deductions.append("SSH Root Login is enabled in OS sshd configuration (-5 pts)")
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