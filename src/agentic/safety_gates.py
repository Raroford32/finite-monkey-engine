import os
from typing import Any, Dict


class SafetyGates:
    """
    Enforces defense-only constraints:
    - No mainnet writes, no broadcasting transactions
    - No private key usage outside fork sandbox
    - Only allowlisted actions
    """

    def __init__(self) -> None:
        self.mode = os.getenv("AGENT_MODE", "defense-only").lower()
        self.allow_offensive = False
        self.allowed_actions = {
            "simulate_forked_tx",
            "read_chain_state",
            "generate_sequence_hypothesis",
        }

    def assert_defense_only(self) -> None:
        if self.mode != "defense-only" or self.allow_offensive:
            raise RuntimeError("Safety violation: offensive mode is not permitted")

    def assert_non_mainnet_execution(self) -> None:
        network = os.getenv("CHAIN_NETWORK", "fork").lower()
        if network in {"mainnet", "livenet", "production"}:
            raise RuntimeError("Safety violation: execution on mainnet is forbidden")

    def is_sequence_allowed(self, sequence: Dict[str, Any]) -> bool:
        actions = sequence.get("actions", [])
        for action in actions:
            if action.get("type") not in self.allowed_actions:
                return False
        return True