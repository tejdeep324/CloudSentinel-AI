import unittest
import json
import os
import sys

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.compliance import evaluate_compliance
from core.hardening import HardeningEngine, VerificationScanner
from core.pipeline_orchestrator import PipelineOrchestrator
from core.database_service import AuditDatabaseService

class TestCloudSentinelPipeline(unittest.TestCase):

    def setUp(self):
        payload_path = os.path.join(os.path.dirname(__file__), "data", "sample_payload.json")
        with open(payload_path, "r") as f:
            self.payload = json.load(f)
        self.supervisor = SupervisorAgent()
        self.orchestrator = PipelineOrchestrator()

    def test_scoring_engine(self):
        """Quantitative pre-scan scoring engine must calculate deductions accurately."""
        res = calculate_risk_score(self.payload)
        self.assertIn("total_score", res)
        self.assertEqual(res["total_score"], 10)
        self.assertIn("category_breakdown", res)
        self.assertEqual(res["category_breakdown"]["storage"], 0)

    def test_compliance_mapping(self):
        """Compliance mapping engine must identify regulatory framework breaches."""
        eval_pci = evaluate_compliance(self.payload, "PCI-DSS (Payment Card Security)")
        self.assertEqual(eval_pci["status"], "NON_COMPLIANT")
        self.assertTrue(len(eval_pci["failed"]) > 0)

    def test_multi_agent_blackboard_consensus(self):
        """Supervisor AI must aggregate domain sub-agent findings onto the shared blackboard."""
        blackboard = self.supervisor.coordinate_assessment(self.payload)
        self.assertEqual(blackboard.supervisor_verdict, "REMEDIATION_REQUIRED")
        self.assertTrue(len(blackboard.findings) >= 3)
        self.assertIn("Plan A (Maximum Security - Recommended)", blackboard.remediation_plans)

    def test_hardening_remediation(self):
        """Hardening engine must enforce KMS CMK encryption and lock exposed ingress ports."""
        hardened = HardeningEngine.remediate_workload(self.payload, "Plan A (Maximum Security - Recommended)")
        self.assertTrue(hardened["storage"]["encrypted"])
        self.assertIn("kms_key_id", hardened["storage"])
        self.assertFalse(hardened["network"]["public_ip_assigned"])
        for rule in hardened["network"]["security_group_rules"]:
            self.assertEqual(rule["source"], "10.0.0.0/16")

    def test_verification_scanner(self):
        """Verification scanner must enforce security policy score threshold >= 90."""
        passed_verif = VerificationScanner.verify(pre_score=40, post_score=95, threshold=90)
        self.assertTrue(passed_verif["verification_passed"])
        
        failed_verif = VerificationScanner.verify(pre_score=40, post_score=85, threshold=90)
        self.assertFalse(failed_verif["verification_passed"])

    def test_end_to_end_pipeline(self):
        """Closed-loop pipeline orchestrator must execute full remediation and report production release."""
        result = self.orchestrator.run_full_pipeline(self.payload, "Plan A (Maximum Security - Recommended)")
        self.assertEqual(result["deployment_status"], "DEPLOYED_TO_PRODUCTION")
        self.assertGreaterEqual(result["post_score"], 90)
        self.assertTrue(result["verification"]["verification_passed"])

    def test_database_logging(self):
        """Audit database service must persist migration events and cleanly close connections."""
        with AuditDatabaseService(db_path=":memory:") as db:
            event_id = db.record_migration_event(
                instance_id="i-test-01",
                pre_score=40,
                post_score=95,
                compliance="PCI-DSS",
                status="DEPLOYED_TO_PRODUCTION",
                manifest={"ami_id": "ami-test-golden"}
            )
            self.assertEqual(event_id, 1)
            history = db.get_historical_logs()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["instance_id"], "i-test-01")


if __name__ == "__main__":
    unittest.main()