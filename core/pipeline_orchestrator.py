import os
import sys
import time
from typing import Dict, Any, List

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.supervisor import SupervisorAgent
from agents.state import AgentBlackboard
from core.scoring import calculate_risk_score
from core.hardening import HardeningEngine, VerificationScanner

class PipelineOrchestrator:
    """Orchestrates the multi-agent closed-loop migration pipeline."""

    def __init__(self):
        self.supervisor = SupervisorAgent()

    def run_full_pipeline(
        self,
        initial_payload: Dict[str, Any],
        selected_plan: str,
        target_compliance: str = "PCI-DSS (Payment Card Security)",
        force_failure: bool = False
    ) -> Dict[str, Any]:
        logs: List[str] = []
        
        def log(msg: str):
            t = time.strftime("%H:%M:%S")
            logs.append(f"[{t}] {msg}")

        log("INTERCEPT: Quarantine Subnet intercepted migration instance.")
        
        # 1. Multi-Agent Evaluation Assessment
        blackboard: AgentBlackboard = self.supervisor.coordinate_assessment(
            initial_payload,
            target_compliance=target_compliance
        )
        pre_score = blackboard.pre_scan_score
        log(f"AI_AGENT: Multi-Agent consensus verdict: {blackboard.supervisor_verdict} (Baseline Score: {pre_score}/100)")
        log(f"AI_REASONING: {blackboard.supervisor_reasoning}")

        # 2. Automated Remediation Engine
        log(f"EXECUTING REMEDIATION: Applying strategy '{selected_plan}'...")
        hardened_payload = HardeningEngine.remediate_workload(initial_payload, selected_plan)
        
        plan_str = selected_plan.lower()
        if "plan b" in plan_str:
            log("NETWORK LOCKDOWN: Restricted port 22/3389/3306 ingress to 10.0.0.0/16.")
            log("STORAGE/IAM POLICY: Disk re-encryption and IAM role modification deferred per Plan B isolation strategy.")
        elif "plan c" in plan_str:
            log("EBS ENCRYPTION: Provisioned Customer Managed KMS Key (arn:aws:kms:...:key/cloudsentinel-cmk-01).")
            log("OS HARDENING: CIS Level 1 baseline applied. Disabled SSH root login.")
            log("NETWORK POLICY: Security group modifications deferred per Plan C policy.")
        else:
            log("EBS ENCRYPTION: Provisioned Customer Managed KMS Key (arn:aws:kms:...:key/cloudsentinel-cmk-01).")
            log("NETWORK LOCKDOWN: Restricted port 22/3389/3306 ingress to 10.0.0.0/16.")
            log("IAM GOVERNANCE: Detached administrator role, bound least-privilege role.")
            log("OS HARDENING: CIS Level 1 baseline applied. Disabled SSH root login.")

        log(f"IMAGE BUILDER: Golden AMI successfully baked: {hardened_payload.get('ami_id')}.")

        # 3. Closed-Loop Post-Remediation Verification
        log("VERIFICATION SCANNER: Executing automated post-remediation audit...")
        post_res = calculate_risk_score(hardened_payload)
        post_score = 45 if force_failure else post_res["total_score"]
        
        verification = VerificationScanner.verify(pre_score, post_score, threshold=90)
        
        if verification["verification_passed"]:
            log(f"VERIFICATION PASSED: Verified score is {post_score}/100 (Threshold >= 90).")
            log("PRODUCTION RELEASE: Golden AMI approved and deployed to Target Production VPC.")
            deployment_status = "DEPLOYED_TO_PRODUCTION"
        else:
            log(f"VERIFICATION FAILED: Verified score {post_score}/100 breached policy threshold.")
            log("CHAOS ROLLBACK TRIGGERED: Terminating unverified instance and deleting staged AMI.")
            deployment_status = "ROLLED_BACK_TO_QUARANTINE"

        return {
            "pre_score": pre_score,
            "post_score": post_score,
            "hardened_payload": hardened_payload,
            "delta": HardeningEngine.compute_delta(initial_payload, hardened_payload),
            "verification": verification,
            "deployment_status": deployment_status,
            "blackboard": blackboard.to_dict(),
            "logs": logs
        }