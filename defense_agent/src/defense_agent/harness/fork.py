from dataclasses import dataclass
from typing import Optional


@dataclass
class ForkEnv:
	chain_id: int
	rpc_url: str
	block_number: Optional[int] = None

	def info(self) -> str:
		b = f"@{self.block_number}" if self.block_number is not None else ""
		return f"Fork(chain={self.chain_id}, url={self.rpc_url}{b})"
