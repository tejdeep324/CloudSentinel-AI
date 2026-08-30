import unittest
import json
import os
import sys

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.orchestration_service import AWSOrchestrationService
from core.packer_generator import PackerImageBuilderGenerator
from core.iac_generator import IaCGenerator

class TestOrchestrationAndPacker(unittest.TestCase):

    def setUp(self):
        self.sample_payload = {
            "instance_id": "i-orch-test-01",
            "instance_type": "t3.medium",
            "ami_id": "ami-cloudsentinel-golden-test",
            "storage": {
                "volume_id": "vol-orch-01",
                "encrypted": True,
                "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/cmk-test"
            },
            "network": {
                "public_ip_assigned": False,
                "security_group_rules": [{"port": 22, "protocol": "tcp", "source": "10.0.0.0/16"}]
            }
        }

    def test_step_functions_asl_generation(self):
        """Step Functions ASL definition must be valid JSON and contain multi-agent state branches."""
        asl_json_str = AWSOrchestrationService.generate_step_functions_asl()
        asl_data = json.loads(asl_json_str)
        self.assertIn("States", asl_data)
        self.assertIn("ParallelMultiAgentAudit", asl_data["States"])
        self.assertIn("BakeGoldenAMIAndRemediate", asl_data["States"])

    def test_dms_manifest_generation(self):
        """AWS DMS manifest must contain replication task rules and table mappings."""
        dms_json_str = AWSOrchestrationService.generate_dms_migration_task()
        dms_data = json.loads(dms_json_str)
        self.assertEqual(dms_data["ReplicationTaskIdentifier"], "cloudsentinel-encrypted-db-migration")
        self.assertEqual(dms_data["MigrationType"], "full-load-and-cdc")

    def test_packer_hcl_generation(self):
        """Packer template must include Amazon EBS builder and CIS shell provisioners."""
        packer_hcl = PackerImageBuilderGenerator.generate_packer_hcl(self.sample_payload, "PCI-DSS")
        self.assertIn("source \"amazon-ebs\" \"cloudsentinel_golden_ami\"", packer_hcl)
        self.assertIn("PermitRootLogin no", packer_hcl)
        self.assertIn("encrypt_boot = true", packer_hcl)

    def test_full_iac_terraform_contains_all_services(self):
        """Terraform output must contain definitions for SQS, SNS, Step Functions, and DMS."""
        tf_code = IaCGenerator.generate_terraform(self.sample_payload, "PCI-DSS")
        self.assertIn("aws_sqs_queue", tf_code)
        self.assertIn("aws_sns_topic", tf_code)
        self.assertIn("aws_sfn_state_machine", tf_code)
        self.assertIn("aws_dms_replication_instance", tf_code)


if __name__ == "__main__":
    unittest.main()