import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class IaCGenerator:
    """Generates production-ready Terraform and CloudFormation code for hardened Golden AMIs."""

    @staticmethod
    def generate_terraform(hardened_payload: Dict[str, Any], framework_name: str) -> str:
        ami_id = hardened_payload.get("ami_id", "ami-cloudsentinel-golden")
        kms_key = hardened_payload.get("storage", {}).get("kms_key_id", "arn:aws:kms:us-east-1:111122223333:key/cmk-01")
        role_name = hardened_payload.get("iam", {}).get("attached_role", "CloudSentinelScopedMigrationRole")

        tf_template = f"""# ==============================================================================
# CloudSentinel AI - Automated Infrastructure as Code (Terraform)
# Compliance Target: {framework_name}
# Baked Golden AMI: {ami_id}
# ==============================================================================

terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "us-east-1"
}}

# 1. Zero-Trust Hardened Security Group
resource "aws_security_group" "hardened_sg" {{
  name        = "cloudsentinel-hardened-sg"
  description = "Managed by CloudSentinel AI - Filtered VPC Ingress"
  vpc_id      = "vpc-0a1b2c3d4e5f"

  ingress {{
    description = "Restricted Internal SSH / RDP Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }}

  egress {{
    description = "Allow Outbound HTTPS for Scoped Packages"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  tags = {{
    Environment = "Production"
    Governance  = "CloudSentinel-AI"
  }}
}}

# 2. Production EC2 Deployment with Baked Golden AMI
resource "aws_instance" "production_workload" {{
  ami                  = "{ami_id}"
  instance_type        = "t3.medium"
  iam_instance_profile = "{role_name}"
  vpc_security_group_ids = [aws_security_group.hardened_sg.id]

  root_block_device {{
    volume_type           = "gp3"
    volume_size           = 50
    encrypted             = true
    kms_key_id            = "{kms_key}"
    delete_on_termination = true
  }}

  metadata_options {{
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 Enforced
    http_put_response_hop_limit = 1
  }}

  tags = {{
    Name        = "Hardened-Production-Node"
    Compliance  = "{framework_name}"
    ManagedBy   = "CloudSentinel-AI"
  }}
}}
"""
        return tf_template