from typing import Any, Dict, Optional

from defense_agent.harness.fork import ForkEnv


class ForkExecutor:
	def __init__(self, env: ForkEnv) -> None:
		self.env = env

	def call(self, to: str, data: bytes, value: int = 0) -> Dict[str, Any]:
		# Placeholder for read-only call on fork (no broadcast)
		return {"to": to, "value": value, "data_len": len(data), "env": self.env.info()}

	def simulate_tx(self, from_addr: str, to: str, data: bytes, value: int = 0, gas: int = 30_000_00) -> Dict[str, Any]:
		# Placeholder for simulation on fork (no broadcast)
		return {
			"from": from_addr,
			"to": to,
			"value": value,
			"data_len": len(data),
			"gas": gas,
			"env": self.env.info(),
		}
