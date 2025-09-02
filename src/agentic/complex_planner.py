from typing import Any, Dict, List


class ComplexAttackPlanner:
    """
    Generates multi-step, permissionless attack-like sequences targeting discovered
    invariants and protocol intents. Outputs sequences in a neutral, defensive
    format suitable for sandbox validation.
    """

    def plan_attack_sequences(self, contract_targets: List[str], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        sequences: List[Dict[str, Any]] = []

        invariants = context.get("invariants", [])
        for invariant in invariants:
            sequences.append({
                "invariant": invariant,
                "actions": [
                    {"type": "generate_sequence_hypothesis", "details": {"target": contract_targets, "invariant": invariant}},
                    {"type": "simulate_forked_tx", "details": {"bundle": [
                        {"to": "<contract>", "data": "<calldata1>", "value": 0},
                        {"to": "<router>", "data": "<calldata2>", "value": 0},
                    ]}},
                    {"type": "read_chain_state", "details": {"slots": ["balances", "reserves", "prices"]}},
                ]
            })

        return sequences