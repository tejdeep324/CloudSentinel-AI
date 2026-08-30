import os
import sys
import json
import argparse
import time

# Guarantee project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure UTF-8 output across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from agents.supervisor import SupervisorAgent
from core.pipeline_orchestrator import PipelineOrchestrator
from core.database_service import AuditDatabaseService
from core.report_generator import ComplianceReportGenerator

def main():
    parser = argparse.ArgumentParser(description="CloudSentinel AI - Autonomous Migration Security CLI")
    parser.add_argument("--payload", type=str, default="data/sample_payload.json", help="Path to telemetry JSON")
    parser.add_argument("--plan", type=str, default="Plan A (Maximum Security - Recommended)", help="Remediation plan to execute")
    parser.add_argument("--compliance", type=str, default="PCI-DSS (Payment Card Security)", help="Target compliance framework")
    parser.add_argument("--force-failure", action="store_true", help="Simulate a verification scan failure to test rollback")
    parser.add_argument("--export-report", action="store_true", help="Generate and save CSV & JSON audit artifacts locally")

    args = parser.parse_args()

    print("=" * 70)
    print("🛡️  CLOUDSENTINEL AI: AUTONOMOUS WORKLOAD GOVERNANCE & AMI HARDENING")
    print("=" * 70)

    # 1. Ingest Telemetry Payload
    if not os.path.exists(args.payload):
        print(f"[-] Error: Telemetry payload file '{args.payload}' not found.")
        sys.exit(1)

    with open(args.payload, "r") as f:
        payload = json.load(f)

    if isinstance(payload, dict) and "golden_ami_manifest" in payload:
        print("[*] Detected CloudSentinel Audit Manifest — extracted Golden AMI workload telemetry.")
        payload = payload["golden_ami_manifest"]
    elif isinstance(payload, dict) and "hardened_payload" in payload:
        payload = payload["hardened_payload"]

    print(f"[*] Ingested Workload Payload : {args.payload}")
    print(f"[*] Instance ID              : {payload.get('instance_id', 'UNKNOWN')}")
    print(f"[*] Target Compliance        : {args.compliance}")
    print(f"[*] Selected Remediation Plan: {args.plan}\n")

    # 2. Run Supervisor & Multi-Agent Assessment
    print("[*] Dispatching Multi-Agent Evaluation Team (Security, Network, IAM, Compliance)...")
    supervisor = SupervisorAgent()
    blackboard = supervisor.coordinate_assessment(payload, target_compliance=args.compliance)

    print(f"\n[+] Multi-Agent Verdict      : {blackboard.supervisor_verdict}")
    print(f"[+] Pre-Scan Baseline Score  : {blackboard.pre_scan_score}/100")
    print(f"[+] Total Vulnerabilities   : {len(blackboard.findings)}")
    print(f"[+] Consensus Rationale      : {blackboard.supervisor_reasoning}\n")

    # 3. Execute Automated Hardening Pipeline
    print("[*] Executing Automated Remediation & Golden AMI Baking Engine...")
    orchestrator = PipelineOrchestrator()
    result = orchestrator.run_full_pipeline(
        payload,
        selected_plan=args.plan,
        target_compliance=args.compliance,
        force_failure=args.force_failure
    )

    print("\n" + "=" * 70)
    print(f"[+] Hardened Golden AMI ID   : {result['hardened_payload'].get('ami_id')}")
    print(f"[+] Post-Remediation Score   : {result['post_score']}/100 ({result['verification']['score_delta']})")
    print(f"[+] Verification Status      : {result['verification']['status']}")
    print(f"[+] Final Deployment State   : {result['deployment_status']}")
    print("=" * 70)

    # 4. Persist to SQLite Database
    db = AuditDatabaseService()
    db.record_migration_event(
        instance_id=payload.get("instance_id", "i-workload-node"),
        pre_score=result["pre_score"],
        post_score=result["post_score"],
        compliance=args.compliance,
        status=result["deployment_status"],
        manifest=result["hardened_payload"]
    )
    print("[+] Audit event successfully persisted to local governance database.")

    # 5. Export Reports if requested
    if args.export_report:
        ami_id = result["hardened_payload"].get("ami_id", f"ami-{int(time.time())}")
        csv_filename = f"CloudSentinel_Audit_{ami_id}.csv"
        json_filename = f"CloudSentinel_Manifest_{ami_id}.json"
        pdf_filename = f"CloudSentinel_Report_{ami_id}.pdf"

        csv_content = ComplianceReportGenerator.generate_csv_summary(result, args.compliance)
        json_content = ComplianceReportGenerator.generate_json_manifest(result, args.compliance)
        pdf_content = ComplianceReportGenerator.generate_pdf_report(result, args.compliance)

        with open(csv_filename, "w", encoding="utf-8") as f:
            f.write(csv_content)
        with open(json_filename, "w", encoding="utf-8") as f:
            f.write(json_content)
        with open(pdf_filename, "wb") as f:
            f.write(pdf_content)

        print(f"[+] Exported CSV Audit Summary     : {csv_filename}")
        print(f"[+] Exported JSON Golden Manifest : {json_filename}")
        print(f"[+] Exported PDF Compliance Report: {pdf_filename}")

    print("\n[✓] CloudSentinel AI Pipeline Run Complete.\n")

if __name__ == "__main__":
    main()