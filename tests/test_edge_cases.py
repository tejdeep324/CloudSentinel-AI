import os
import sys
import unittest
import json

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.supervisor import SupervisorAgent
from agents.state import AgentBlackboard, AgentFinding
from core.scoring import calculate_risk_score
from core.pipeline_orchestrator import PipelineOrchestrator
from core.database_service import AuditDatabaseService
from tools.inspector_tool import WorkloadInspectorTool
from tools.cis_benchmark_tool import CISBenchmarkTool

class TestCloudSentinelResilience(unittest.TestCase):

    def setUp(self):
        self.supervisor = SupervisorAgent()
        self.orchestrator = PipelineOrchestrator()

    def test_empty_payload_resilience(self):
        """Pipeline must handle empty payload dictionaries without crashing."""
        empty_payload = {}
        score_res = calculate_risk_score(empty_payload)
        self.assertIsInstance(score_res["total_score"], int)
        
        blackboard = self.supervisor.coordinate_assessment(empty_payload)
        self.assertIn(blackboard.supervisor_verdict, ["REMEDIATION_REQUIRED", "APPROVED_FOR_MIGRATION"])

    def test_corrupt_types_handling(self):
        """Tool inspect methods must gracefully handle None and invalid types."""
        storage_res = WorkloadInspectorTool.inspect_storage_encryption(None)
        self.assertFalse(storage_res["is_encrypted"])
        
        net_res = WorkloadInspectorTool.inspect_exposed_ports(None)
        self.assertEqual(len(net_res), 0)

        cis_res = CISBenchmarkTool.evaluate_os_baseline(None)
        self.assertFalse(cis_res["compliant"])

    def test_remediation_and_hardening_pipeline(self):
        """A sample legacy workload must achieve score >= 90 and deploy successfully."""
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        result = self.orchestrator.run_full_pipeline(
            sample_payload, 
            "Plan A (Maximum Security - Recommended)"
        )
        self.assertTrue(result["verification"]["verification_passed"])
        self.assertEqual(result["deployment_status"], "DEPLOYED_TO_PRODUCTION")
        self.assertGreaterEqual(result["post_score"], 90)

    def test_chaos_rollback_trigger(self):
        """Forced failure simulation must trigger quarantine rollback."""
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        result = self.orchestrator.run_full_pipeline(
            sample_payload, 
            "Plan A (Maximum Security - Recommended)",
            force_failure=True
        )
        self.assertFalse(result["verification"]["verification_passed"])
        self.assertEqual(result["deployment_status"], "ROLLED_BACK_TO_QUARANTINE")

    def test_plan_b_and_c_selective_hardening(self):
        """Plan B and Plan C must selectively remediate designated domains only."""
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        # Plan B: Fast Network Lockdown only
        plan_b_res = self.orchestrator.run_full_pipeline(
            sample_payload,
            "Plan B (Fast Network Quarantine Lockdown)"
        )
        hardened_b = plan_b_res["hardened_payload"]
        self.assertFalse(hardened_b["storage"]["encrypted"])
        self.assertFalse(hardened_b["network"]["public_ip_assigned"])
        for rule in hardened_b["network"]["security_group_rules"]:
            self.assertEqual(rule["source"], "10.0.0.0/16")

        # Plan C: Regulatory Baseline (Storage + CIS OS only, SG left open)
        plan_c_res = self.orchestrator.run_full_pipeline(
            sample_payload,
            "Plan C (Regulatory Baseline Hardening)"
        )
        hardened_c = plan_c_res["hardened_payload"]
        self.assertTrue(hardened_c["storage"]["encrypted"])
        self.assertFalse(hardened_c["os_security"]["root_login_enabled"])

    def test_ipv6_scoring_deduction(self):
        """Scoring engine must deduct points when management ports are exposed to IPv6 (::/0)."""
        ipv6_payload = {
            "network": {
                "security_group_rules": [
                    {"port": 22, "protocol": "tcp", "source": "::/0"}
                ]
            }
        }
        res = calculate_risk_score(ipv6_payload)
        self.assertEqual(res["category_breakdown"]["network"], 20)
        self.assertTrue(any("Port 22" in d for d in res["deductions"]))

    def test_dynamic_report_generation(self):
        """Report generator must dynamically serialize findings, CSVs, and PDFs without crashing."""
        from core.report_generator import ComplianceReportGenerator
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        result = self.orchestrator.run_full_pipeline(
            sample_payload,
            "Plan A (Maximum Security - Recommended)"
        )
        csv_out = ComplianceReportGenerator.generate_csv_summary(result, "PCI-DSS (Payment Card Security)")
        self.assertIn("REMEDIATED", csv_out)
        self.assertIn("PCI-DSS", csv_out)

        pdf_bytes = ComplianceReportGenerator.generate_pdf_report(result, "PCI-DSS (Payment Card Security)")
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 1000)

    def test_reuploading_downloaded_manifest_preserves_100_score(self):
        """Re-uploading an exported Golden AMI audit manifest must evaluate to 100/100 and APPROVED."""
        from core.report_generator import ComplianceReportGenerator
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        # 1. First run: Workload is hardened to 100/100
        res = self.orchestrator.run_full_pipeline(
            sample_payload,
            "Plan A (Maximum Security - Recommended)"
        )
        self.assertEqual(res["post_score"], 100)

        # 2. User downloads the full JSON manifest
        manifest_json_str = ComplianceReportGenerator.generate_json_manifest(res, "PCI-DSS (Payment Card Security)")
        downloaded_manifest_obj = json.loads(manifest_json_str)

        # 3. User re-uploads that exact downloaded JSON file freshly
        reuploaded_score = calculate_risk_score(downloaded_manifest_obj)
        self.assertEqual(reuploaded_score["total_score"], 100)
        self.assertEqual(len(reuploaded_score["deductions"]), 0)

        blackboard = self.supervisor.coordinate_assessment(downloaded_manifest_obj)
        self.assertEqual(blackboard.pre_scan_score, 100)
        self.assertEqual(blackboard.supervisor_verdict, "APPROVED_FOR_MIGRATION")

    def test_cis_benchmark_explicit_non_compliance(self):
        """CISBenchmarkTool must report non-compliance when cis_benchmark_compliant is False."""
        os_sec = {"cis_benchmark_compliant": False}
        res = CISBenchmarkTool.evaluate_os_baseline(os_sec)
        self.assertFalse(res["compliant"])
        self.assertGreater(len(res["violations"]), 0)

    def test_null_payload_resilience_in_tools(self):
        """Tool utilities must not crash when None is passed."""
        from tools.cve_scanner_tool import CVEScannerTool
        from core.ansible_generator import AnsiblePlaybookGenerator

        cve_findings = CVEScannerTool.scan_workload_packages(None)
        self.assertIsInstance(cve_findings, list)

        playbook = AnsiblePlaybookGenerator.generate_playbook(None, "PCI-DSS")
        self.assertIn("ami-cloudsentinel-golden", playbook)

    def test_plan_specific_orchestrator_logs(self):
        """Orchestrator logs must reflect specific actions for Plan B vs Plan A."""
        with open("data/sample_payload.json", "r") as f:
            sample_payload = json.load(f)

        plan_b_res = self.orchestrator.run_full_pipeline(
            sample_payload,
            "Plan B (Fast Network Quarantine Lockdown)"
        )
        logs_text = " ".join(plan_b_res["logs"])
        self.assertIn("Plan B isolation strategy", logs_text)

    def test_web_ports_legitimate_ingress(self):
        """Standard web ports 80 and 443 must not trigger critical administrative vulnerability alerts."""
        web_payload = {
            "network": {
                "security_group_rules": [
                    {"port": 80, "protocol": "tcp", "source": "0.0.0.0/0"},
                    {"port": 443, "protocol": "tcp", "source": "0.0.0.0/0"}
                ]
            }
        }
        exposed = WorkloadInspectorTool.inspect_exposed_ports(web_payload.get("network"))
        self.assertEqual(len(exposed), 0)

    def test_dr_recovery_runbook_commands(self):
        """DR recovery manager must generate an end-to-end executable rollback script."""
        from core.recovery_manager import RecoverySnapshotManager
        sample = {"instance_id": "i-test-123", "storage": {"volume_id": "vol-test-456"}}
        dr_info = RecoverySnapshotManager.generate_dr_runbook(sample)
        script = dr_info["rollback_script"]
        self.assertIn("attach-volume", script)
        self.assertIn("start-instances", script)

    def test_iam_wildcard_admin_spoofed_flag_penalized(self):
        """Spoofing least_privilege_compliant=True on an admin role must not bypass the IAM deduction."""
        spoofed_payload = {
            "iam": {
                "attached_role": "AdministratorAccess",
                "least_privilege_compliant": True
            }
        }
        res = calculate_risk_score(spoofed_payload)
        self.assertEqual(res["category_breakdown"]["iam"], 5)
        self.assertTrue(any("Wildcard Administrator" in d for d in res["deductions"]))

    def test_os_password_auth_deduction(self):
        """Insecure OS password authentication enabled must trigger an OS security deduction."""
        os_payload = {
            "os_security": {
                "root_login_enabled": False,
                "password_auth_enabled": True,
                "cis_benchmark_compliant": True
            }
        }
        res = calculate_risk_score(os_payload)
        self.assertEqual(res["category_breakdown"]["os_security"], 15)

    def test_target_compliance_propagation_in_orchestrator(self):
        """Orchestrator must forward target_compliance to supervisor blackboard."""
        with open("data/sample_payload.json", "r") as f:
            sample = json.load(f)

        res = self.orchestrator.run_full_pipeline(
            sample,
            "Plan A (Maximum Security - Recommended)",
            target_compliance="HIPAA (Healthcare Data Privacy)"
        )
        self.assertEqual(res["blackboard"]["target_compliance"], "HIPAA (Healthcare Data Privacy)")

    def test_concurrent_blackboard_writes(self):
        """Concurrent threads writing to AgentBlackboard must not deadlock or corrupt state."""
        import concurrent.futures
        blackboard = AgentBlackboard(workload_payload={})

        def worker(idx):
            blackboard.log_trace(f"Worker_{idx}", f"Trace message {idx}")
            blackboard.add_finding(AgentFinding(
                agent_name=f"Agent_{idx}",
                domain="TestDomain",
                severity="HIGH",
                title=f"Finding {idx}",
                description=f"Description {idx}",
                remediation_action=f"ACTION_{idx}"
            ))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(worker, i) for i in range(50)]
            for f in futures:
                f.result(timeout=5.0)

        self.assertEqual(len(blackboard.findings), 50)
        self.assertEqual(len(blackboard.execution_trace), 50)

    def test_concurrent_database_reads_and_writes(self):
        """Concurrent SQLite writes and reads must not deadlock or raise table lock errors."""
        import concurrent.futures
        db = AuditDatabaseService("test_concurrent_audit.db")

        def db_worker(idx):
            db.record_migration_event(
                instance_id=f"i-concurrent-{idx}",
                pre_score=50,
                post_score=100,
                compliance="PCI-DSS",
                status="DEPLOYED_TO_PRODUCTION",
                manifest={"ami_id": f"ami-conc-{idx}"}
            )
            _ = db.get_historical_logs()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(db_worker, i) for i in range(20)]
                for f in futures:
                    f.result(timeout=10.0)

            logs = db.get_historical_logs()
            self.assertGreaterEqual(len(logs), 20)
        finally:
            if os.path.exists("test_concurrent_audit.db"):
                try:
                    os.remove("test_concurrent_audit.db")
                except Exception:
                    pass

    def test_granular_scoring_port_differentiation(self):
        """Different open ports must produce distinct network scores based on risk severity."""
        ssh_only = {"network": {"security_group_rules": [{"port": 22, "source": "0.0.0.0/0"}]}}
        rdp_only = {"network": {"security_group_rules": [{"port": 3389, "source": "0.0.0.0/0"}]}}
        db_only = {"network": {"security_group_rules": [{"port": 3306, "source": "0.0.0.0/0"}]}}

        self.assertEqual(calculate_risk_score(ssh_only)["category_breakdown"]["network"], 20)
        self.assertEqual(calculate_risk_score(rdp_only)["category_breakdown"]["network"], 15)
        self.assertEqual(calculate_risk_score(db_only)["category_breakdown"]["network"], 10)

    def test_granular_storage_cmk_vs_aws_default(self):
        """Customer-Managed Key (CMK) must score 25 while AWS-managed default key scores 15."""
        cmk_storage = {"storage": {"encrypted": True, "kms_key_id": "arn:aws:kms:us-east-1:1111:key/cmk-01"}}
        default_storage = {"storage": {"encrypted": True, "kms_key_id": "alias/aws/ebs"}}

        self.assertEqual(calculate_risk_score(cmk_storage)["category_breakdown"]["storage"], 25)
        self.assertEqual(calculate_risk_score(default_storage)["category_breakdown"]["storage"], 15)


if __name__ == "__main__":
    unittest.main()