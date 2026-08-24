# 🛡️ CloudSentinel AI
### Autonomous Workload Security & Zero-Trust AMI Hardening Platform

CloudSentinel AI is an autonomous cloud governance framework designed to secure server migration pipelines before deployment into production cloud environments.

## 📌 Architecture Highlights
- **Pre-Deployment Interception:** Quarantines inbound migration images inside an isolated AWS VPC subnet.
- **Multi-Agent Collaborative AI:** Specialized sub-agents (IAM, Network, Security, Compliance) evaluate workloads and generate transparent risk reports.
- **Autonomous Hardening Engine:** Builds CIS-compliant Golden AMIs with automated AWS KMS encryption and security group lockdowns.
- **Closed-Loop Verification & Rollback:** Automatically re-scans the hardened artifact and triggers snapshot rollbacks if compliance thresholds (<90/100) are not met.
- **Cost & Compliance Governance:** Features live PCI-DSS, HIPAA, and SOC2 compliance validation alongside automated EC2 instance right-sizing.

## 🚀 Quickstart

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt