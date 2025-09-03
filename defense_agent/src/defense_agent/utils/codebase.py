import os
from typing import List


def read_text_files(root: str, exts: List[str] | None = None, max_bytes: int = 500_000) -> List[str]:
    if exts is None:
        exts = [".sol", ".vy", ".yul", ".md", ".txt"]
    docs: List[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if not any(fn.endswith(e) for e in exts):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "rb") as f:
                    data = f.read(max_bytes)
                docs.append(f"FILE:{path}\n" + data.decode(errors="ignore"))
            except Exception:
                continue
    return docs

