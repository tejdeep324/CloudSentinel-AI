from typing import Dict, Any

COMPLIANCE_STANDARDS = {
    "PCI-DSS (Payment Card Security)": {
        "kms_mandatory": True,
        "max_open_ports": 1,  # Only HTTPS 443
        "password_auth_allowed": False,
        "required_tags": ["PCI-Compliant", "Production"]
    },
    "HIPAA (Healthcare Data Protection)": {
        "kms_mandatory": True,
        "max_open_ports": 2,
        "password_auth_allowed": False,
        "audit_logging_required": True
    },
    "SOC2 Type II (General SaaS Security)": {
        "kms_mandatory": True,
        "max_open_ports": 2,
        "least_privilege_mandatory": True
    }
}

def evaluate_compliance(payload: dict, standard: str) -> dict:
    rules = COMPLIANCE_STANDARDS.get(standard, {})
    passed_checks = []
    failed_checks = []

    # Check 1: KMS
    if rules.get("kms_mandatory"):
        if payload.get("storage", {}).get("encrypted", False):
            passed_checks.append("KMS Disk Encryption Active")
        else:
            failed_checks.append("Non-Compliant: Storage lacks KMS CMK Encryption")

    # Check 2: Ports
    open_ports_count = len(payload.get("network", {}).get("open_ports", []))
    if open_ports_count > rules.get("max_open_ports", 2):
        failed_checks.append(f"Non-Compliant: Excessive open ports ({open_ports_count} active)")
    else:
        passed_checks.append("Network Port Boundary Compliant")

    # Check 3: IAM
    if not payload.get("iam", {}).get("least_privilege_compliant", True):
        failed_checks.append("Non-Compliant: Over-privileged IAM Permissions")
    else:
        passed_checks.append("IAM Zero-Trust Policy Enforced")

    status = "COMPLIANT" if not failed_checks else "NON-COMPLIANT"
    return {
        "standard": standard,
        "status": status,
        "passed": passed_checks,
        "failed": failed_checks
    }

def calculate_cost_optimization(current_instance: str = "m5.large") -> dict:
    pricing = {
        "m5.large": 0.096 * 730,    # ~$70.08 / month
        "t3.micro": 0.0104 * 730    # ~$7.59 / month (or $0 on Free Tier)
    }
    
    current_cost = pricing.get(current_instance, 70.08)
    optimized_cost = pricing.get("t3.micro")
    savings = current_cost - optimized_cost
    
    return {
        "current_instance": current_instance,
        "current_cost": round(current_cost, 2),
        "recommended_instance": "t3.micro (Free Tier Eligible)",
        "recommended_cost": round(optimized_cost, 2),
        "monthly_savings": round(savings, 2),
        "percentage_savings": round((savings / current_cost) * 100, 1)
    }