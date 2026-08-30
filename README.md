# 🛡️ CloudSentinel AI — Autonomous Multi-Agent Migration Security & AMI Hardening

CloudSentinel AI is an autonomous governance interceptor for cloud workload migrations into AWS. It intercepts unhardened virtual machines in an isolated quarantine subnet, orchestrates specialized domain AI agents (Storage, Network, IAM, Compliance, CVE Hunter), executes Zero-Trust hardening, and bakes verified **Golden AMIs** ($Score \ge 90/100$) before releasing them to production VPCs.

---

## 🏗️ 10-Service AWS Architecture

```text
[Quarantined EC2 Workload]
           │
           ▼
[Multi-Agent Blackboard (SupervisorAgent + Sub-Agents)]
   ├── SecurityAgent ──────► AWS KMS (AES-256 CMK)
   ├── NetworkAgent  ──────► AWS VPC & Security Groups (Private CIDRs)
   ├── IAMAgent      ──────► AWS IAM (Scoped Roles / Least Privilege)
   └── CVE & OS Agent ────► CIS Level 1 OS Hardening Scripts
           │
           ▼
[Automated Golden AMI Bake (EC2 CreateImage)]
           │
           ├─► Amazon S3 (Audit Vault Manifests)
           ├─► Amazon DynamoDB (Migration State Log)
           ├─► AWS WAF (Web Application Firewall ACL)
           ├─► Amazon CloudWatch (Metric Alarms)
           └─► AWS Config (Continuous Compliance Checks)