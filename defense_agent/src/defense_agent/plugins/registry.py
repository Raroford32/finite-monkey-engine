from typing import Dict, List

from defense_agent.utils.models import Capability


class CapabilityRegistry:
	def __init__(self) -> None:
		self._capabilities: Dict[str, Capability] = {}
		self._autoload_defaults()

	def register(self, capability: Capability) -> None:
		self._capabilities[capability.name] = capability

	def list_capabilities(self) -> dict:
		return {"capabilities": list(self._capabilities.values())}

	def _autoload_defaults(self) -> None:
		self.register(
			Capability(
				name="InvariantMiner",
				description="Mines candidate invariants from code and traces (defensive)",
				inputs=["source_code", "bytecode", "traces"],
				outputs=["invariants"],
				version="0.1.0",
				safety_flags=["simulation_only", "no_exploit_poc"],
			)
		)
		self.register(
			Capability(
				name="Explorer",
				description="Hybrid concolic/greybox explorer with novelty objectives (defensive)",
				inputs=["invariants", "fork_env"],
				outputs=["counterexamples"],
				version="0.1.0",
				safety_flags=["simulation_only", "no_mainnet_writes"],
			)
		)
