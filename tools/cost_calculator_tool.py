import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class FinOpsCostCalculatorTool:
    """FinOps utility to calculate compute right-sizing savings and ROI."""

    # Standard AWS On-Demand monthly pricing reference (US East N. Virginia)
    PRICING_TABLE = {
        "m5.2xlarge": 280.32,
        "m5.xlarge": 140.16,
        "m5.large": 70.08,
        "t3.xlarge": 121.44,
        "t3.large": 60.72,
        "t3.medium": 30.36,
        "t3.micro": 7.59
    }

    @classmethod
    def calculate_rightsizing_projection(cls, current_instance: str = "m5.large") -> Dict[str, Any]:
        """Calculates cost delta and percentage savings for right-sizing migration workloads."""
        current_cost = cls.PRICING_TABLE.get(current_instance, 70.08)
        
        # Recommend right-sized tier
        if "2xlarge" in current_instance:
            recommended_instance = "t3.xlarge"
        elif "xlarge" in current_instance:
            recommended_instance = "t3.large"
        else:
            recommended_instance = "t3.medium"

        optimized_cost = cls.PRICING_TABLE.get(recommended_instance, 30.36)
        monthly_savings = round(current_cost - optimized_cost, 2)
        percentage_savings = round((monthly_savings / current_cost) * 100, 1)

        return {
            "current_instance": current_instance,
            "recommended_instance": recommended_instance,
            "current_monthly_cost": current_cost,
            "optimized_monthly_cost": optimized_cost,
            "monthly_savings": monthly_savings,
            "percentage_savings": percentage_savings
        }