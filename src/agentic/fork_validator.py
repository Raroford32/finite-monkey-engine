from typing import Any, Dict


class ForkValidator:
    """
    Validates candidate sequences on a local fork or simulator.
    This stub returns a structured placeholder suitable for FAR scoring.
    """

    def __init__(self, rpc_url: str) -> None:
        self.rpc_url = rpc_url

    def validate_on_fork(self, sequence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "executed": True,
            "reproducible": True,
            "violations": [
                {
                    "invariant": sequence.get("invariant"),
                    "severity": "high",
                    "state_diff": {"balances_delta": {"attacker": 0, "protocol": 0}},
                }
            ],
            "economic": {
                "attacker_pnl": 0.0,
                "gas_cost": 0.0,
                "slippage": 0.0,
                "mev_risk": 0.0,
                "liquidity_bound": True,
            },
            "traces": [
                {"tx": 0, "to": "<contract>", "data": "<calldata1>", "success": True},
                {"tx": 1, "to": "<router>", "data": "<calldata2>", "success": True},
            ],
        }