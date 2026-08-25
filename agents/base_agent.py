import os
import sys
from typing import Dict, Any, List, Optional

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.state import AgentBlackboard

class BaseAgent:
    """Base cognitive architecture for CloudSentinel domain agents."""

    def __init__(self, name: str, domain: str, system_prompt: str):
        self.name = name
        self.domain = domain
        self.system_prompt = system_prompt
        self.memory: List[Dict[str, str]] = []

    def evaluate(self, blackboard: AgentBlackboard) -> None:
        """Core execution cycle: Inspect -> Reason -> Write to Shared Blackboard."""
        raise NotImplementedError("Subclasses must implement the evaluate() method.")