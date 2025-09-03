from typing import Any, Dict, Optional
import json
import urllib.request
import urllib.error

from defense_agent.harness.fork import ForkEnv


class ForkExecutor:
	def __init__(self, env: ForkEnv) -> None:
		self.env = env

	def call(self, to: str, data: bytes, value: int = 0) -> Dict[str, Any]:
		# Minimal JSON-RPC eth_call (read-only)
		payload = {
			"jsonrpc": "2.0",
			"method": "eth_call",
			"params": [
				{"to": to, "data": "0x" + data.hex(), "value": hex(value)},
				hex(self.env.block_number) if self.env.block_number is not None else "latest",
			],
			"id": 1,
		}
		return self._post_json(payload)

	def simulate_tx(self, from_addr: str, to: str, data: bytes, value: int = 0, gas: int = 30_000_00) -> Dict[str, Any]:
		# Minimal JSON-RPC eth_call as simulation stand-in (no broadcast)
		payload = {
			"jsonrpc": "2.0",
			"method": "eth_call",
			"params": [
				{"from": from_addr, "to": to, "data": "0x" + data.hex(), "value": hex(value), "gas": hex(gas)},
				hex(self.env.block_number) if self.env.block_number is not None else "latest",
			],
			"id": 1,
		}
		return self._post_json(payload)

	def get_chain_id(self) -> int:
		payload = {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}
		resp = self._post_json(payload)
		result = resp.get("result")
		return int(result, 16) if isinstance(result, str) else -1

	def get_block_number(self) -> int:
		payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
		resp = self._post_json(payload)
		result = resp.get("result")
		return int(result, 16) if isinstance(result, str) else -1

	def _post_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
		try:
			data = json.dumps(payload).encode()
			req = urllib.request.Request(self.env.rpc_url, data=data, headers={"Content-Type": "application/json"})
			with urllib.request.urlopen(req, timeout=30) as resp:
				return json.loads(resp.read().decode())
		except urllib.error.HTTPError as e:
			return {"error": {"code": e.code, "message": str(e)}}
		except Exception as e:
			return {"error": {"message": str(e)}}
