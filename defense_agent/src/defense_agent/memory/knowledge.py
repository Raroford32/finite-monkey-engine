from typing import Dict, List


class KnowledgeGraph:
	def __init__(self) -> None:
		self._nodes: Dict[str, Dict] = {}
		self._edges: List[tuple] = []

	def add_node(self, node_id: str, **attrs) -> None:
		self._nodes[node_id] = {**attrs}

	def add_edge(self, src: str, dst: str, rel: str) -> None:
		self._edges.append((src, rel, dst))

	def get_node(self, node_id: str) -> Dict:
		return self._nodes.get(node_id, {})

	def neighbors(self, node_id: str) -> List[str]:
		return [dst for src, _, dst in self._edges if src == node_id]
