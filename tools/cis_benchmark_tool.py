import os
import sys
from typing import Dict, Any, List, Optional

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class CISBenchmarkTool:
    """Evaluates OS configurations against Center for Internet Security (CIS) Level 1 Benchmark."""

    @staticmethod
    def evaluate_os_baseline(os_security: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Audits SSH configuration parameters and authentication policies against CIS baseline."""
        if not os_security or not isinstance(os_security, dict):
            return {
                "compliant": False,
                "violations": ["No OS security configuration metadata found in workload"],
                "recommendations": ["Apply standard CIS Level 1 OS baseline profile"]
            }

        violations: List[str] = []
        if os_security.get("root_login_enabled", False):
            violations.append("CIS 5.2.10: SSH Direct Root Login is enabled (PermitRootLogin yes)")
        
        if os_security.get("password_auth_enabled", False):
            violations.append("CIS 5.2.11: Password-based authentication is enabled (Require SSH keys)")

        if os_security.get("cis_benchmark_compliant") is False and not violations:
            violations.append("CIS Baseline Breach: Workload OS has not completed CIS Level 1 hardening")

        return {
            "compliant": len(violations) == 0,
            "violations": violations,
            "recommendations": [
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
                "Enforce SSH Ed25519 or RSA-4096 key-based authentication"
            ]
        }