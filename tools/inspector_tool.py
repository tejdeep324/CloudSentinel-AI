import os
import sys
from typing import Dict, Any, List, Optional

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class WorkloadInspectorTool:
    """Deterministic inspection tool used by AI agents to audit cloud configurations."""

    @staticmethod
    def inspect_storage_encryption(storage_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Audits EBS volume encryption status and customer-managed KMS key association."""
        if not storage_data or not isinstance(storage_data, dict):
            return {
                "is_encrypted": False,
                "kms_key": None,
                "has_customer_key": False,
                "issue": "Missing storage configuration block"
            }
        
        is_encrypted = storage_data.get("encrypted", False)
        kms_key = storage_data.get("kms_key_id")
        has_cmk = bool(kms_key and not str(kms_key).startswith("alias/aws/ebs"))

        return {
            "is_encrypted": bool(is_encrypted),
            "kms_key": kms_key,
            "has_customer_key": has_cmk
        }

    @staticmethod
    def inspect_exposed_ports(network_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifies any security group ingress rule allowing unrestricted public internet exposure."""
        if not network_data or not isinstance(network_data, dict):
            return []
        
        exposed: List[Dict[str, Any]] = []
        rules = network_data.get("security_group_rules", [])
        
        if not isinstance(rules, list):
            return exposed

        for rule in rules:
            if isinstance(rule, dict):
                src = str(rule.get("source", ""))
                port = rule.get("port")
                if src in ["0.0.0.0/0", "::/0"]:
                    # Legitimate web ports (HTTP/HTTPS) are standard ingress for web tier
                    if port in [80, 443]:
                        continue
                    # Flag administrative and critical database ports with CRITICAL severity
                    severity = "CRITICAL" if port in [22, 3389, 3306, 5432, 27017] else "MEDIUM"
                    exposed.append({
                        "port": port,
                        "protocol": rule.get("protocol", "tcp"),
                        "source": src,
                        "severity": severity
                    })
        return exposed

    @staticmethod
    def inspect_iam_privileges(iam_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluates IAM instance profiles for wildcard administrative privileges."""
        if not iam_data or not isinstance(iam_data, dict):
            return {
                "attached_role": "NONE",
                "is_least_privilege": False,
                "is_admin_wildcard": True,
                "risk": "CRITICAL"
            }
        
        role = str(iam_data.get("attached_role", ""))
        least_privilege = iam_data.get("least_privilege_compliant", True)
        
        # Detect admin, root, or full-access wildcard indicators
        role_lower = role.lower()
        is_admin = any(wildcard in role_lower for wildcard in ["fullaccess", "admin", "administrator", "root", "*"])
        
        return {
            "attached_role": role,
            "is_least_privilege": bool(least_privilege and not is_admin),
            "is_admin_wildcard": is_admin
        }