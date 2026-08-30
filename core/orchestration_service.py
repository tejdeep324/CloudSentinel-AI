import os
import sys
import json
import time
from typing import Dict, Any, List

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class AWSOrchestrationService:
    """Manages AWS Step Functions, Amazon SQS queueing, Amazon SNS notifications, and AWS DMS replication."""

    @staticmethod
    def publish_sns_security_alert(topic_arn: str, instance_id: str, verdict: str, post_score: int) -> Dict[str, Any]:
        """Publishes critical quarantine and verification alerts to Amazon SNS topic."""
        message_body = {
            "Event": "CloudSentinel_Migration_Audit",
            "InstanceId": instance_id,
            "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SupervisorVerdict": verdict,
            "VerifiedPostScore": f"{post_score}/100",
            "Status": "APPROVED" if post_score >= 90 else "QUARANTINED"
        }
        return {
            "status": "PUBLISHED",
            "sns_topic": topic_arn,
            "message_id": f"msg-sns-{int(time.time())}",
            "payload": message_body
        }

    @staticmethod
    def enqueue_sqs_workload(queue_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches quarantined telemetry into Amazon SQS for asynchronous agent processing."""
        return {
            "status": "QUEUED",
            "queue_url": queue_url,
            "message_id": f"sqs-msg-{int(time.time())}",
            "approximate_receive_count": 1
        }

    @staticmethod
    def generate_step_functions_asl() -> str:
        """Generates the AWS Step Functions Amazon States Language (ASL) JSON definition."""
        asl_definition = {
            "Comment": "CloudSentinel AI - Autonomous Multi-Agent Migration & Golden AMI Orchestration State Machine",
            "StartAt": "QuarantineIngest",
            "States": {
                "QuarantineIngest": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sqs:sendMessage",
                    "Parameters": {
                        "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/CloudSentinelMigrationQueue",
                        "MessageBody.$": "$"
                    },
                    "Next": "ParallelMultiAgentAudit"
                },
                "ParallelMultiAgentAudit": {
                    "Type": "Parallel",
                    "Branches": [
                        {"StartAt": "SecurityStorageAudit", "States": {"SecurityStorageAudit": {"Type": "Pass", "End": True}}},
                        {"StartAt": "NetworkIngressAudit", "States": {"NetworkIngressAudit": {"Type": "Pass", "End": True}}},
                        {"StartAt": "IAMLeastPrivilegeAudit", "States": {"IAMLeastPrivilegeAudit": {"Type": "Pass", "End": True}}},
                        {"StartAt": "RegulatoryComplianceAudit", "States": {"RegulatoryComplianceAudit": {"Type": "Pass", "End": True}}}
                    ],
                    "Next": "ConsensusEvaluation"
                },
                "ConsensusEvaluation": {
                    "Type": "Choice",
                    "Choices": [
                        {
                            "Variable": "$.risk_score",
                            "NumericGreaterThanEquals": 90,
                            "Next": "DeployToProduction"
                        }
                    ],
                    "Default": "BakeGoldenAMIAndRemediate"
                },
                "BakeGoldenAMIAndRemediate": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::imagebuilder:createImage",
                    "Next": "ReVerifyPosture"
                },
                "ReVerifyPosture": {
                    "Type": "Task",
                    "Resource": "arn:aws:lambda:us-east-1:123456789012:function:CloudSentinelVerifier",
                    "Next": "DeployToProduction"
                },
                "DeployToProduction": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::sns:publish",
                    "Parameters": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:CloudSentinelMigrationApprovals",
                        "Message": "Workload successfully verified and deployed to production VPC."
                    },
                    "End": True
                }
            }
        }
        return json.dumps(asl_definition, indent=2)

    @staticmethod
    def generate_dms_migration_task(db_source: str = "mysql", target_rds: str = "aurora-mysql") -> str:
        """Generates AWS Database Migration Service (DMS) configuration manifest for database migrations."""
        dms_config = {
            "ReplicationTaskIdentifier": "cloudsentinel-encrypted-db-migration",
            "SourceEndpointArn": f"arn:aws:dms:us-east-1:123456789012:endpoint:source-{db_source}-quarantine",
            "TargetEndpointArn": f"arn:aws:dms:us-east-1:123456789012:endpoint:target-{target_rds}-production",
            "MigrationType": "full-load-and-cdc",
            "TableMappings": {
                "rules": [
                    {
                        "rule-type": "selection",
                        "rule-id": "1",
                        "rule-name": "all-tables-migration",
                        "object-locator": {
                            "schema-name": "%",
                            "table-name": "%"
                        },
                        "rule-action": "include"
                    }
                ]
            },
            "ReplicationTaskSettings": {
                "TargetMetadata": {
                    "TargetSchema": "",
                    "SupportLobs": True,
                    "FullLobMode": False,
                    "LobChunkSize": 64,
                    "LimitedSizeLobMode": True,
                    "LobMaxSize": 32
                },
                "Logging": {
                    "EnableLogging": True,
                    "LogComponents": [
                        {"Id": "SOURCE_UNLOAD", "Severity": "LOGGER_SEVERITY_DEFAULT"},
                        {"Id": "TARGET_LOAD", "Severity": "LOGGER_SEVERITY_DEFAULT"}
                    ]
                }
            }
        }
        return json.dumps(dms_config, indent=2)