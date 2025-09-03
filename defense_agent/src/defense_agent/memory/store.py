import json
import os
from typing import List, Dict, Any

from defense_agent.memory.vector import VectorIndex
from defense_agent.memory.knowledge import KnowledgeGraph


class MemoryStore:
    def __init__(self, path: str = ".defense_agent") -> None:
        self._path = path
        os.makedirs(self._path, exist_ok=True)
        self.vectors = VectorIndex()
        self.knowledge = KnowledgeGraph()
        self._journal_file = os.path.join(self._path, "journal.jsonl")

    def add_documents(self, docs: List[str]) -> None:
        self.vectors.add(docs)
        for d in docs:
            self._append_journal({"type": "doc", "text": d})

    def add_fact(self, node_id: str, **attrs: Any) -> None:
        self.knowledge.add_node(node_id, **attrs)
        self._append_journal({"type": "node", "id": node_id, "attrs": attrs})

    def add_relation(self, src: str, dst: str, rel: str) -> None:
        self.knowledge.add_edge(src, dst, rel)
        self._append_journal({"type": "edge", "src": src, "dst": dst, "rel": rel})

    def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        return [{"text": t, "score": s} for t, s in self.vectors.search(query, k=k)]

    def _append_journal(self, obj: Dict[str, Any]) -> None:
        with open(self._journal_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")

