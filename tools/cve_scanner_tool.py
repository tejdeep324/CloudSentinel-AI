import os
import sys
from typing import Dict, Any, List

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class CVEScannerTool:
    """Simulates CVE database lookups (NVD / OSV) for installed packages on quarantined workloads."""

    VULNERABILITY_DATABASE = {
        "openssl": {
            "cve_id": "CVE-2023-0286",
            "severity": "HIGH",
            "cvss_score": 7.4,
            "description": "OpenSSL X.400 address type confusion vulnerability.",
            "fixed_version": "openssl-3.0.8"
        },
        "log4j": {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "Log4Shell remote code execution vulnerability.",
            "fixed_version": "log4j-core-2.17.1"
        },
        "linux_kernel": {
            "cve_id": "CVE-2024-1086",
            "severity": "HIGH",
            "cvss_score": 7.8,
            "description": "Netfilter privilege escalation vulnerability in Linux kernel.",
            "fixed_version": "kernel-6.8.0"
        }
    }

    @classmethod
    def scan_workload_packages(cls, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scans workload OS and installed packages for active CVEs."""
        if not isinstance(payload, dict):
            payload = {}
        findings = []
        os_sec = payload.get("os_security", {}) or {}
        
        # If OS is not hardened, simulate presence of legacy vulnerable libraries
        if not os_sec.get("cis_benchmark_compliant", False):
            for pkg, data in cls.VULNERABILITY_DATABASE.items():
                findings.append({
                    "package": pkg,
                    "cve_id": data["cve_id"],
                    "severity": data["severity"],
                    "cvss_score": data["cvss_score"],
                    "description": data["description"],
                    "remediation": f"Upgrade to {data['fixed_version']} during Golden AMI build."
                })
        return findings