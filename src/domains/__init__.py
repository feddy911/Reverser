from __future__ import annotations

from typing import Dict, Optional

from src.domains.mycollatz import MYCOLLATZ
from src.domains.pack import NONE_PACK, DomainPack

_REGISTRY: Dict[str, DomainPack] = {
    "none": NONE_PACK,
    "mycollatz": MYCOLLATZ,
}


def get_domain_pack(name: Optional[str] = None) -> DomainPack:
    """Вернуть domain pack по имени из config (по умолчанию — пустой)."""
    key = (name or "none").strip().lower() or "none"
    if key not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"Unknown domain_pack={name!r}; known: {known}")
    return _REGISTRY[key]


def list_domain_packs() -> Dict[str, DomainPack]:
    return dict(_REGISTRY)
