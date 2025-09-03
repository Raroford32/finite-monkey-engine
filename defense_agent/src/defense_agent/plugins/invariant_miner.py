from typing import Any, Dict, List

from defense_agent.plugins.base import BasePlugin
from defense_agent.utils.models import Capability


class InvariantMiner(BasePlugin):
	def __init__(self) -> None:
		cap = Capability(
			name="InvariantMiner",
			description="Mines candidate invariants from code and traces (defensive)",
			inputs=["source_code", "bytecode", "traces"],
			outputs=["invariants"],
			version="0.1.0",
			safety_flags=["simulation_only", "no_exploit_poc"],
		)
		super().__init__(capability=cap)

	def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
		# Stub: derive simple structural invariants for demonstration
		source_code: str = inputs.get("source_code", "")
		invariants: List[str] = []
		if "onlyOwner" in source_code:
			invariants.append("owner_operations_must_be_authorized")
		if "transfer(" in source_code:
			invariants.append("total_supply_conserved_on_transfers")
		if "permit(" in source_code:
			invariants.append("permit_signatures_must_be_valid_and_fresh")
		return {"invariants": invariants}
