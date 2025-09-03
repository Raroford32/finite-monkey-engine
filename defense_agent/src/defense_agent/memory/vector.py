from typing import List, Tuple

try:
	from sentence_transformers import SentenceTransformer
except Exception:  # lightweight fallback
	SentenceTransformer = None  # type: ignore


class VectorIndex:
	def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
		self._model_name = model_name
		self._model = None
		self._docs: List[str] = []
		self._vecs = None

	def _ensure_model(self) -> None:
		if self._model is None and SentenceTransformer is not None:
			self._model = SentenceTransformer(self._model_name)

	def add(self, docs: List[str]) -> None:
		self._ensure_model()
		self._docs.extend(docs)
		if self._model is None:
			return
		vecs = self._model.encode(docs, normalize_embeddings=True)
		if self._vecs is None:
			self._vecs = vecs
		else:
			import numpy as np
			self._vecs = np.vstack([self._vecs, vecs])

	def search(self, query: str, k: int = 5) -> List[Tuple[str, float]]:
		self._ensure_model()
		if self._model is None or not self._docs:
			return []
		q = self._model.encode([query], normalize_embeddings=True)[0]
		import numpy as np
		scores = (self._vecs @ q)
		idx = np.argsort(-scores)[:k]
		return [(self._docs[i], float(scores[i])) for i in idx]
