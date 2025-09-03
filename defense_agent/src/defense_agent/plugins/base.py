from abc import ABC, abstractmethod
from typing import Any, Dict

from defense_agent.utils.models import Capability


class BasePlugin(ABC):
	def __init__(self, capability: Capability) -> None:
		self.capability = capability

	@abstractmethod
	def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
		raise NotImplementedError
