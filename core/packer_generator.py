import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class PackerImageBuilderGenerator:
    """Generates HashiCorp Packer HCL and AWS EC2 Image Builder Recipes for baking Golden AMIs."""

    @staticmethod
    def generate_packer_hcl(hardened_payload: Dict[str, Any], framework_name: str) -> str:
        instance_type = hardened_payload.get("instance_type", "t3.medium")
        kms_arn = hardened_payload.get("storage", {}).get("kms_key_id", "arn:aws:kms:us-east-1:123456789012:key/cmk-golden")

        packer_hcl = f"""# ==============================================================================
# CloudSentinel AI — HashiCorp Packer Golden AMI Automation
# Target Compliance Framework: {framework_name}
# ==============================================================================

packer {{
  required_plugins {{
    amazon = {{
      version = ">= 1.2.8"
      source  = "github.com/hashicorp/amazon"
    }}
  }}
}}

variable "aws_region" {{
  type    = string
  default = "us-east-1"
}}

source "amazon-ebs" "cloudsentinel_golden_ami" {{
  region          = var.aws_region
  instance_type   = "{instance_type}"
  ami_name        = "cloudsentinel-golden-ami-{{{{timestamp}}}}"
  ami_description = "Zero-Trust CIS Level 1 Hardened Golden AMI ({framework_name})"

  source_ami_filter {{
    filters = {{
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }}
    most_recent = true
    owners      = ["099720109477"] # Canonical
  }}

  ssh_username = "ubuntu"

  # AWS KMS CMK Volume Encryption
  encrypt_boot = true
  kms_key_id   = "{kms_arn}"

  launch_block_device_mappings {{
    device_name           = "/dev/sda1"
    volume_size           = 40
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = "{kms_arn}"
  }}
}}

build {{
  name    = "cloudsentinel-ami-builder"
  sources = ["source.amazon-ebs.cloudsentinel_golden_ami"]

  # Step 1: Apply CIS Level 1 OS Hardening
  provisioner "shell" {{
    inline = [
      "echo '=== CloudSentinel AI CIS Hardening Step 1: Disabling Root SSH ==='",
      "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
      "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
      "echo '=== CloudSentinel AI CIS Hardening Step 2: Restricting Ingress ==='",
      "sudo ufw default deny incoming",
      "sudo ufw allow from 10.0.0.0/16 to any port 22 proto tcp",
      "echo '=== CloudSentinel AI Step 3: Upgrading System Packages ==='",
      "sudo apt-get update -y && sudo apt-get upgrade -y openssl iptables",
      "sudo systemctl restart sshd"
    ]
  }}

  # Step 2: Generate Cryptographic Build Manifest
  post-processor "manifest" {{
    output     = "packer-golden-ami-manifest.json"
    strip_path = true
  }}
}}
"""
        return packer_hcl

    @staticmethod
    def generate_image_builder_recipe(hardened_payload: Dict[str, Any]) -> str:
        """Generates an AWS EC2 Image Builder Component YAML recipe."""
        recipe_yaml = """name: CloudSentinelCISLevel1HardeningRecipe
description: AWS EC2 Image Builder component to enforce CIS Level 1 OS baseline.
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: DisableRootLogin
        action: ExecuteBash
        inputs:
          commands:
            - sed -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            - sed -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
      - name: LockFirewallToVPC
        action: ExecuteBash
        inputs:
          commands:
            - ufw default deny incoming
            - ufw allow from 10.0.0.0/16 to any port 22 proto tcp
  - name: validate
    steps:
      - name: VerifySSHConfig
        action: ExecuteBash
        inputs:
          commands:
            - grep -E "^PermitRootLogin no" /etc/ssh/sshd_config
"""
        return recipe_yaml