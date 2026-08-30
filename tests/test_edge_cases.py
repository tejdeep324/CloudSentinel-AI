import os
import sys
import unittest
import json

# Ensure project root is available in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.pipeline_orchestrator import PipelineOrchestrator
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

if __name__ == "__main__":
    unittest.main()