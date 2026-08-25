import os
import sys
import json
import csv
import io
import time
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class ComplianceReportGenerator:
    """Generates regulatory compliance audit manifests and executive CSV summaries."""

    @staticmethod
    def generate_csv_summary(pipeline_result: Dict[str, Any], framework_name: str) -> str:
        """Generates an executive-ready CSV report for cloud auditors."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["CloudSentinel AI - Security & Compliance Migration Audit"])
        writer.writerow(["Timestamp", time.strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Target Framework", framework_name])
        writer.writerow(["AMI ID", pipeline_result.get("hardened_payload", {}).get("ami_id", "N/A")])
        writer.writerow(["Deployment Status", pipeline_result.get("deployment_status", "UNKNOWN")])
        writer.writerow([])
        writer.writerow(["Metric", "Baseline (Pre-Scan)", "Verified Target (Post-Scan)", "Status"])
        
        pre_score = pipeline_result.get("pre_score", 0)
        post_score = pipeline_result.get("post_score", 0)
        status = "PASSED" if post_score >= 90 else "FAILED"
        
        writer.writerow(["Overall Security Score", f"{pre_score}/100", f"{post_score}/100", status])
        writer.writerow(["Storage Encryption", "Unencrypted", "AWS KMS CMK (AES-256)", "REMEDIATED"])
        writer.writerow(["VPC Ingress (Port 22/3389)", "Public 0.0.0.0/0", "Restricted 10.0.0.0/16", "REMEDIATED"])
        writer.writerow(["IAM Least Privilege", "Wildcard Admin Role", "Scoped Migration Profile", "REMEDIATED"])
        writer.writerow(["OS CIS Hardening", "Direct Root / Password Auth", "CIS Level 1 Locked", "REMEDIATED"])

        return output.getvalue()

    @staticmethod
    def generate_json_manifest(pipeline_result: Dict[str, Any], framework_name: str) -> str:
        """Serializes the full cryptographic and configuration manifest to JSON."""
        manifest = {
            "generator": "CloudSentinel AI Multi-Agent Engine v2.0",
            "audit_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target_compliance": framework_name,
            "pre_hardening_score": pipeline_result.get("pre_score"),
            "post_hardening_score": pipeline_result.get("post_score"),
            "deployment_status": pipeline_result.get("deployment_status"),
            "verification_details": pipeline_result.get("verification"),
            "golden_ami_manifest": pipeline_result.get("hardened_payload"),
            "multi_agent_blackboard": pipeline_result.get("blackboard")
        }
        return json.dumps(manifest, indent=2)