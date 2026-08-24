import json
import unittest
from core.scoring import calculate_risk_score
from core.hardening import HardeningEngine, VerificationScanner
from core.compliance import evaluate_compliance, calculate_cost_optimization
from core.pipeline_orchestrator import PipelineOrchestrator
from agents.supervisor import SupervisorAgent

class TestCloudSentinelPipeline(unittest.TestCase):
    def setUp(self):
        with open("data/sample_payload.json", "r") as f:
            self.payload = json.load(f)

    def test_pre_scoring(self):
        result = calculate_risk_score(self.payload)
        self.assertLessEqual(result["total_score"], 60, "Pre-score should reflect critical vulnerabilities")

    def test_supervisor_evaluation(self):
        supervisor = SupervisorAgent()
        assessment = supervisor.coordinate_assessment(self.payload)
        self.assertEqual(assessment["supervisor_verdict"], "REMEDIATION_REQUIRED")
        self.assertEqual(len(assessment["agent_reports"]), 3)

    def test_hardening_execution(self):
        plan = "Plan A (Maximum Security - Recommended)"
        hardened = HardeningEngine.execute_remediation(self.payload, plan)
        post_eval = calculate_risk_score(hardened)
        self.assertGreaterEqual(post_eval["total_score"], 90, "Post-score must be >= 90")
        self.assertTrue(hardened["storage"]["encrypted"])

    def test_verification_scanner(self):
        verification = VerificationScanner.verify(42, 95)
        self.assertTrue(verification["verification_passed"])
        self.assertEqual(verification["status"], "VERIFIED_SECURE_GOLDEN_AMI")

    def test_compliance_and_cost(self):
        comp = evaluate_compliance(self.payload, "PCI-DSS (Payment Card Security)")
        self.assertIn(comp["status"], ["COMPLIANT", "NON-COMPLIANT"])
        cost = calculate_cost_optimization("m5.large")
        self.assertGreater(cost["monthly_savings"], 0)

    def test_orchestrator_success_and_rollback(self):
        orchestrator = PipelineOrchestrator()
        plan = "Plan A (Maximum Security - Recommended)"
        
        # Test Success Route
        success_res = orchestrator.run_full_pipeline(self.payload, plan, force_failure=False)
        self.assertEqual(success_res["deployment_status"], "DEPLOYED_TO_PRODUCTION")
        
        # Test Rollback Route
        fail_res = orchestrator.run_full_pipeline(self.payload, plan, force_failure=True)
        self.assertEqual(fail_res["deployment_status"], "ROLLED_BACK_TO_SNAPSHOT")

if __name__ == "__main__":
    unittest.main()