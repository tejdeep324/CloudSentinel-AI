import time
from typing import Dict, Any, List
from agents.supervisor import SupervisorAgent
from core.scoring import calculate_risk_score
from core.hardening import HardeningEngine, VerificationScanner

class PipelineOrchestrator:
    def __init__(self):
        self.supervisor = SupervisorAgent()
        self.execution_logs: List[str] = []

    def log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.execution_logs.append(f"[{timestamp}] {message}")

    def run_full_pipeline(self, initial_payload: Dict[str, Any], selected_plan: str, force_failure: bool = False) -> Dict[str, Any]:
        self.execution_logs.clear()
        self.log("EVENT: Migration payload detected in S3 migration drop-bucket.")
        self.log("ACTION: Routing payload to isolated Quarantine VPC Subnet.")
        
        # 1. Pre-Assessment
        pre_eval = calculate_risk_score(initial_payload)
        pre_score = pre_eval["total_score"]
        self.log(f"SECURITY: Initial Risk Score calculated: {pre_score}/100 (Unsafe).")

        # 2. Multi-Agent AI Assessment
        self.log("AI_AGENT: Supervisor Agent initialized Sub-Agents (IAM, Network, Security, Compliance).")
        assessment = self.supervisor.coordinate_assessment(initial_payload)
        self.log(f"AI_AGENT: Multi-Agent consensus reached with {assessment['confidence_score']} confidence.")
        
        # 3. Execution of Hardening
        self.log(f"ORCHESTRATOR: Executing {selected_plan} via EC2 Image Builder.")
        hardened_payload = HardeningEngine.execute_remediation(initial_payload, selected_plan)
        
        # Simulate edge-case failure if requested
        if force_failure:
            hardened_payload["storage"]["encrypted"] = False
            self.log("SIMULATION_INJECT: Injected KMS key attachment failure to test rollback.")

        # 4. Post-Assessment & Verification
        post_eval = calculate_risk_score(hardened_payload)
        post_score = post_eval["total_score"]
        verification = VerificationScanner.verify(pre_score, post_score)

        # 5. Closed-Loop Rollback Decision
        if verification["verification_passed"]:
            self.log(f"VERIFICATION: PASSED ({post_score}/100). Verified Golden AMI ready for production deployment.")
            deployment_status = "DEPLOYED_TO_PRODUCTION"
        else:
            self.log(f"VERIFICATION: FAILED ({post_score}/100). Post-scan threshold (<90) not met.")
            self.log("ROLLBACK: Triggered automatic rollback. Revoked AMI and restored last-known safe snapshot.")
            deployment_status = "ROLLED_BACK_TO_SNAPSHOT"

        return {
            "deployment_status": deployment_status,
            "pre_score": pre_score,
            "post_score": post_score,
            "verification": verification,
            "hardened_payload": hardened_payload,
            "logs": self.execution_logs
        }