import os
import sys
from typing import Dict, Any

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class FinOpsCostCalculatorTool:
    """FinOps & GreenOps utility to calculate compute right-sizing savings and CO2 emission reduction."""

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

    # Estimated monthly kg CO2 equivalent per running instance type
    CARBON_FOOTPRINT_TABLE = {
        "m5.2xlarge": 42.5,
        "m5.xlarge": 21.3,
        "m5.large": 10.6,
        "t3.xlarge": 15.2,
        "t3.large": 7.6,
        "t3.medium": 3.8,
        "t3.micro": 0.9
    }

    @classmethod
    def calculate_rightsizing_projection(cls, current_instance: str = "m5.large") -> Dict[str, Any]:
        """Calculates financial savings and GreenOps environmental impact."""
        current_cost = cls.PRICING_TABLE.get(current_instance, 70.08)
        current_co2 = cls.CARBON_FOOTPRINT_TABLE.get(current_instance, 10.6)
        
        # Recommend right-sized tier based on telemetry
        if "2xlarge" in current_instance:
            recommended_instance = "t3.xlarge"
        elif "xlarge" in current_instance:
            recommended_instance = "t3.large"
        elif "large" in current_instance:
            recommended_instance = "t3.medium"
        elif current_instance == "t3.medium":
            recommended_instance = "t3.micro"
        else:
            recommended_instance = current_instance

        optimized_cost = cls.PRICING_TABLE.get(recommended_instance, current_cost)
        optimized_co2 = cls.CARBON_FOOTPRINT_TABLE.get(recommended_instance, current_co2)

        monthly_savings = max(0.0, round(current_cost - optimized_cost, 2))
        percentage_savings = round((monthly_savings / current_cost) * 100, 1) if current_cost > 0 else 0.0
        co2_reduction_kg = max(0.0, round(current_co2 - optimized_co2, 1))

        return {
            "current_instance": current_instance,
            "recommended_instance": recommended_instance,
            "current_monthly_cost": current_cost,
            "optimized_monthly_cost": optimized_cost,
            "monthly_savings": monthly_savings,
            "percentage_savings": percentage_savings,
            "current_co2_kg": current_co2,
            "optimized_co2_kg": optimized_co2,
            "monthly_co2_reduction_kg": co2_reduction_kg
        }