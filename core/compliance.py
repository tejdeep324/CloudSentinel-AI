import os
import sys
from typing import Dict, Any, List

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

COMPLIANCE_STANDARDS = {
    "PCI-DSS (Payment Card Security)": {
        "description": "Payment Card Industry Data Security Standard v4.0",
        "rules": [
            "Encrypted EBS Storage (Req 3.4)",
            "Restricted Administrative Ingress (Req 1.3)",
            "Non-Root OS Access Control (Req 8.2)"
        ]
    },
    "HIPAA (Healthcare Data Privacy)": {
        "description": "Health Insurance Portability and Accountability Act Security Rule",
        "rules": [
            "Data At Rest Encryption (45 CFR § 164.312(a)(2)(iv))",
            "Unique User Identification & Least Privilege (45 CFR § 164.312(a)(1))",
            "Audit Controls & Transmission Security (45 CFR § 164.312(e)(1))"
        ]
    },
    "SOC2 (Trust & Availability)": {
        "description": "AICPA SOC 2 Type II Security & Confidentiality Criteria",
        "rules": [
            "CC6.1: Boundary Protection & Perimeter Filtering",
            "CC6.6: Customer Managed KMS Key Protection",
            "CC6.3: Role-Based Access Control and Principle of Least Privilege"
        ]
    }
}

def evaluate_compliance(payload: Dict[str, Any], standard_name: str) -> Dict[str, Any]:
    """Audits telemetry against standard regulatory compliance frameworks."""
    if not isinstance(payload, dict):
        payload = {}

    passed: List[str] = []
    failed: List[str] = []
    
    std_lower = standard_name.lower()
    if "pci" in std_lower:
        storage_cite = "PCI-DSS Req 3.4"
        network_cite = "PCI-DSS Req 1.3"
        iam_cite = "PCI-DSS Req 8.2"
    elif "hipaa" in std_lower:
        storage_cite = "HIPAA 45 CFR § 164.312(a)(2)(iv)"
        network_cite = "HIPAA 45 CFR § 164.312(e)(1)"
        iam_cite = "HIPAA 45 CFR § 164.312(a)(1)"
    else:  # SOC 2 default
        storage_cite = "SOC2 CC6.6 (KMS Protection)"
        network_cite = "SOC2 CC6.1 (Perimeter Boundary)"
        iam_cite = "SOC2 CC6.3 (RBAC & Least Privilege)"

    # 1. Storage Encryption Audit
    storage = payload.get("storage") or {}
    if storage.get("encrypted", False) and storage.get("kms_key_id"):
        passed.append(f"Storage Encryption ({storage_cite}): Compliant with KMS CMK encryption policy.")
    else:
        failed.append(f"Storage Encryption ({storage_cite}): Non-compliant (Missing disk encryption or KMS CMK key).")

    # 2. Network Perimeter Audit
    net = payload.get("network") or {}
    rules = net.get("security_group_rules") or []
    open_public = any(
        isinstance(r, dict) and r.get("source") in ["0.0.0.0/0", "::/0"] and r.get("port") in [22, 3389, 3306, 5432, 27017]
        for r in rules
    )
    
    if not open_public:
        passed.append(f"Network Ingress ({network_cite}): Compliant (No administrative ports exposed to 0.0.0.0/0).")
    else:
        failed.append(f"Network Ingress ({network_cite}): Non-compliant (Management/DB ports exposed to public internet).")

    # 3. Access Governance Audit
    iam = payload.get("iam") or {}
    role = str(iam.get("attached_role", "")).lower()
    is_admin = any(wildcard in role for wildcard in ["fullaccess", "admin", "administrator", "root", "*"])

    if iam.get("least_privilege_compliant", True) and not is_admin:
        passed.append(f"Access Governance ({iam_cite}): Compliant with Principle of Least Privilege.")
    else:
        failed.append(f"Access Governance ({iam_cite}): Non-compliant (Over-privileged instance profile assigned).")

    return {
        "standard": standard_name,
        "status": "NON_COMPLIANT" if len(failed) > 0 else "COMPLIANT",
        "passed": passed,
        "failed": failed
    }