from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple


# Базовые includes для любого восстановленного C++ (без domain-зависимостей).
BASE_INCLUDES: Tuple[str, ...] = (
    "#include <cstdio>",
    "#include <cstring>",
    "#include <iostream>",
    "#include <string>",
    "#include <vector>",
    "#include <chrono>",
    "#include <fstream>",
)


@dataclass(frozen=True)
class DomainPack:
    """Опциональные sample/domain-подсказки для assembler/polisher.

    Пустой pack (name='none') — режим произвольного бинарника без hardcoded карт.
    """

    name: str = "none"
    extra_includes: Tuple[str, ...] = ()
    renames: Dict[str, str] = field(default_factory=dict)
    offset_map: str = ""
    idiom_map: str = ""

    @property
    def has_polish_hints(self) -> bool:
        return bool(self.offset_map.strip() or self.idiom_map.strip())

    def preamble(self, comment: str) -> List[str]:
        lines = [comment]
        lines.extend(BASE_INCLUDES)
        lines.extend(self.extra_includes)
        lines.append("")
        return lines


NONE_PACK = DomainPack(name="none")
