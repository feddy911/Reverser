from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Optional, Union

logger = logging.getLogger("revllm.cache")


def compute_file_md5(path: Union[str, Path], chunk_size: int = 1024 * 1024) -> str:
    """Считает md5 файла для идентификации бинарника в кэше."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class FileCache:
    """
    Простой файловый кэш результатов анализа r2.

    Структура:
    <root>/functions.json
    <root>/imports.json
    <root>/strings.json
    <root>/decompiled/0x1400117c6.json
    """

    def __init__(self, root: Union[str, Path]):
        self.root = Path(root)

    def _path_for(self, key: str) -> Path:
        return self.root / (key + ".json")

    def has(self, key: str) -> bool:
        return self._path_for(key).exists()

    def get(self, key: str) -> Optional[Any]:
        p = self._path_for(key)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Cache read error for %s: %s", key, exc)
            return None

    def put(self, key: str, data: Any) -> None:
        p = self._path_for(key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.warning("Cache write error for %s: %s", key, exc)