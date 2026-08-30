import os
import sys
import time
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class RecoverySnapshotManager:
    """Generates disaster recovery snapshots and rollback AWS CLI runbooks."""

    @staticmethod
    def generate_dr_runbook(payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            payload = {}
        instance_id = payload.get("instance_id", "i-quarantine-node")
        volume_id = (payload.get("storage") or {}).get("volume_id", "vol-quarantine-01")
        snapshot_id = f"snap-quarantine-backup-{int(time.time())}"

        runbook_sh = f"""#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel AI - Point-in-Time Rollback & DR Recovery Runbook
# Workload: {instance_id} | Volume: {volume_id}
# ==============================================================================

# 1. Pre-Hardening Safety Snapshot Creation
echo "[+] Capturing EBS Point-in-Time Snapshot..."
aws ec2 create-snapshot \\
    --volume-id {volume_id} \\
    --description "CloudSentinel pre-remediation safety checkpoint" \\
    --tag-specifications 'ResourceType=snapshot,Tags=[{{Key=Governance,Value=CloudSentinel}}]'

# 2. Rollback Command (In case of verification threshold breach)
cat << 'EOF' > rollback_workload.sh
echo "[!] Reverting instance to original quarantine snapshot..."
aws ec2 stop-instances --instance-ids {instance_id}
aws ec2 wait instance-stopped --instance-ids {instance_id}
aws ec2 detach-volume --volume-id {volume_id}
RESTORED_VOL_ID=$(aws ec2 create-volume --snapshot-id {snapshot_id} --availability-zone us-east-1a --tag-specifications 'ResourceType=volume,Tags=[{{Key=Name,Value=RestoredVolume}}]' --query 'VolumeId' --output text)
aws ec2 wait volume-available --volume-ids $RESTORED_VOL_ID
aws ec2 attach-volume --volume-id $RESTORED_VOL_ID --instance-id {instance_id} --device /dev/sda1
aws ec2 start-instances --instance-ids {instance_id}
echo "[+] Instance {instance_id} restored to snapshot {snapshot_id} and restarted."
EOF
chmod +x rollback_workload.sh
"""
        return {
            "snapshot_id": snapshot_id,
            "target_volume": volume_id,
            "target_instance": instance_id,
            "rollback_script": runbook_sh
        }