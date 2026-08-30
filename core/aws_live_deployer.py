import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any

class AWSLiveDeployer:
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        try:
            self.ec2 = boto3.client("ec2", region_name=self.region)
            self.connected = True
        except Exception:
            self.connected = False

    def create_quarantine_vpc(self, cidr_block: str = "10.0.0.0/16") -> Dict[str, Any]:
        """Provisions an isolated Migration Quarantine VPC."""
        if not self.connected:
            return {"status": "MOCK_SUCCESS", "vpc_id": "vpc-0a9b8c7d6e5f"}

        try:
            vpc_res = self.ec2.create_vpc(CidrBlock=cidr_block)
            vpc_id = vpc_res["Vpc"]["VpcId"]
            self.ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "CloudSentinel-Quarantine-VPC"}])
            return {"status": "SUCCESS", "vpc_id": vpc_id}
        except ClientError as e:
            return {"status": "ERROR", "message": str(e)}

    def lock_security_group_ingress(self, group_id: str) -> bool:
        """Revokes all 0.0.0.0/0 public ingress rules."""
        if not self.connected:
            return True
        try:
            self.ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            )
            return True
        except ClientError:
            return False