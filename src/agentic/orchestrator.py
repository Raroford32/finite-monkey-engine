import os
from typing import Any, Dict, List, Optional

from .complex_planner import ComplexAttackPlanner
from .fork_validator import ForkValidator


class Orchestrator:
    """
    High-level coordinator for defensive agentic workflows.

    Responsibilities:
    - Plan complex, permissionless multi-step sequences (attacker-mindset simulation)
    - Validate on forked chains only and collect execution traces
    - Compute funds-at-risk (0–100) score with evidence weighting
    - Return structured artifacts suitable for reporting
    """

    def __init__(self, project_id: str, rpc_url: Optional[str] = None) -> None:
        self.project_id = project_id
        self.rpc_url = rpc_url or os.getenv("CHAIN_RPC_URL", "")
        self.planner = ComplexAttackPlanner()
        self.validator = ForkValidator(self.rpc_url)

    def run_defensive_assessment(self, contract_targets: List[str], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidate_sequences = self.planner.plan_attack_sequences(contract_targets, context)

        validated_findings: List[Dict[str, Any]] = []
        for seq in candidate_sequences:
            validation = self.validator.validate_on_fork(seq)

            finding = {
                "project_id": self.project_id,
                "contract_targets": contract_targets,
                "sequence": seq,
                "validation": validation,
            }
            validated_findings.append(finding)

        return validated_findings