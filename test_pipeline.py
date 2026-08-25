import os
import sys
import unittest
import json

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.scoring import calculate_risk_score
from core.hardening import HardeningEngine, VerificationScanner
from core.compliance import evaluate_compliance
from core.database_service import AuditDatabaseService
from core.pipeline_orchestrator import PipelineOrchestrator
from agents.supervisor import SupervisorAgent

class TestCloudSentinelPipeline(unittest.TestCase):

    def setUp(self):
        self.sample_payload_path = os.path.join("data", "sample_payload.json")
        with open(self.sample_payload_path, "r") as f:
            self.payload = json.load(f)
        self.orchestrator = PipelineOrchestrator()
        self.supervisor = SupervisorAgent()

    def test_pre_remediation_risk_score(self):
        """Pre-scan posture score of vulnerable payload should be < 50."""
        result = calculate_risk_score(self.payload)
        self.assertLess(result["total_score"], 50)
        self.assertIn("Network Security", result["breakdown"])
        self.assertIn("Storage Encryption", result["breakdown"])

    def test_multi_agent_assessment(self):
        """Supervisor and sub-agents should flag critical vulnerabilities."""
        blackboard = self.supervisor.coordinate_assessment(self.payload)
        self.assertEqual(blackboard.supervisor_verdict, "REMEDIATION_REQUIRED")
        self.assertGreater(len(blackboard.findings), 0)
        self.assertIn("Plan A (Maximum Security - Recommended)", blackboard.remediation_plans)

    def test_hardening_engine_remediation(self):
        """Hardening engine must produce encrypted storage and restrict network access."""
        hardened = HardeningEngine.remediate_workload(self.payload, "Plan A (Maximum Security - Recommended)")
        self.assertTrue(hardened["storage"]["encrypted"])
        self.assertTrue(bool(hardened["storage"]["kms_key_id"]))
        self.assertFalse(hardened["network"]["public_ip_assigned"])
        self.assertTrue(hardened["iam"]["least_privilege_compliant"])

    def test_verification_scanner(self):
        """Verification scanner must approve scores >= 90 and reject scores < 90."""
        pass_res = VerificationScanner.verify(pre_score=40, post_score=95, threshold=90)
        self.assertTrue(pass_res["verification_passed"])

        fail_res = VerificationScanner.verify(pre_score=40, post_score=75, threshold=90)
        self.assertFalse(fail_res["verification_passed"])

    def test_compliance_evaluation(self):
        """Unremediated workload must fail PCI-DSS compliance checks."""
        comp_res = evaluate_compliance(self.payload, "PCI-DSS (Payment Card Security)")
        self.assertEqual(comp_res["status"], "NON_COMPLIANT")
        self.assertGreater(len(comp_res["failed"]), 0)

    def test_full_pipeline_orchestration(self):
        """End-to-end pipeline execution must yield verified Golden AMI and production deployment."""
        res = self.orchestrator.run_full_pipeline(self.payload, "Plan A (Maximum Security - Recommended)")
        self.assertGreaterEqual(res["post_score"], 90)
        self.assertEqual(res["deployment_status"], "DEPLOYED_TO_PRODUCTION")
        self.assertTrue(res["hardened_payload"]["ami_id"].startswith("ami-hardened-golden-"))

    def test_database_logging(self):
        """Audit log must persist migration events in an in-memory SQLite instance."""
        db = AuditDatabaseService(db_path=":memory:")
        db.record_migration_event(
            instance_id="i-test-01",
            pre_score=40,
            post_score=95,
            compliance="PCI-DSS (Payment Card Security)",
            status="DEPLOYED_TO_PRODUCTION",
            manifest={"ami_id": "ami-test"}
        )
        logs = db.get_historical_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["instance_id"], "i-test-01")

if __name__ == "__main__":
    unittest.main()