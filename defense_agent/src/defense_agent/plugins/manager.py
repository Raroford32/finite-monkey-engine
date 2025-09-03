from typing import Optional

from defense_agent.plugins.invariant_miner import InvariantMiner
from defense_agent.plugins.explorer import Explorer
from defense_agent.plugins.base import BasePlugin


class PluginManager:
	def create(self, name: str) -> Optional[BasePlugin]:
		if name == "InvariantMiner":
			return InvariantMiner()
		if name == "Explorer":
			return Explorer()
		return None
