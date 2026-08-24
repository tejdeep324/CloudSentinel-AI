def calculate_risk_score(payload: dict) -> dict:
    score = 100
    breakdown = {}

    # 1. Network checks (30 points)
    net_penalty = 0
    for rule in payload.get("network", {}).get("security_group_rules", []):
        if rule.get("source") == "0.0.0.0/0" and rule.get("port") in [22, 3389]:
            net_penalty += 15
    score -= net_penalty
    breakdown["Network Security"] = max(0, 30 - net_penalty)

    # 2. Storage & Encryption checks (25 points)
    storage_penalty = 0
    if not payload.get("storage", {}).get("encrypted", False):
        storage_penalty += 25
    score -= storage_penalty
    breakdown["Storage Encryption"] = max(0, 25 - storage_penalty)

    # 3. IAM Permissions checks (25 points)
    iam_penalty = 0
    if not payload.get("iam", {}).get("least_privilege_compliant", True):
        iam_penalty += 25
    score -= iam_penalty
    breakdown["IAM Governance"] = max(0, 25 - iam_penalty)

    # 4. OS Hardening checks (20 points)
    os_penalty = 0
    os_sec = payload.get("os_security", {})
    if os_sec.get("root_login_enabled", False):
        os_penalty += 10
    if os_sec.get("password_auth_enabled", False):
        os_penalty += 10
    score -= os_penalty
    breakdown["OS Hardening"] = max(0, 20 - os_penalty)

    return {
        "total_score": max(0, score),
        "breakdown": breakdown
    }