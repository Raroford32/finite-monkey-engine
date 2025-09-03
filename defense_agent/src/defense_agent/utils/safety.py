import os
from typing import Set


class Safety:
	def __init__(self) -> None:
		self._allowed_tokens: Set[str] = self._load_tokens()
		self._allowed_targets: Set[str] = self._load_targets()
		self.simulation_only: bool = True

	def _load_tokens(self) -> Set[str]:
		raw = os.getenv("DEFENSE_AGENT_SCOPE_TOKENS", "DEMO_TOKEN").strip()
		return {t for t in (x.strip() for x in raw.split(",")) if t}

	def _load_targets(self) -> Set[str]:
		raw = os.getenv("DEFENSE_AGENT_ALLOWED_TARGETS", "").strip()
		return {t for t in (x.strip() for x in raw.split(",")) if t}

	def is_scope_authorized(self, scope_token: str, target_name: str) -> bool:
		if scope_token not in self._allowed_tokens:
			return False
		if self._allowed_targets and target_name not in self._allowed_targets:
			return False
		return True

	def redact_text(self, text: str) -> str:
		return text[:2000] + ("..." if len(text) > 2000 else "")
