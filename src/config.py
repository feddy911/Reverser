from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Union

import yaml


@dataclass
class AppConfig:
    """Конфигурация приложения."""
    binary_path: str = "samples/MyCollatz.exe"
    output_dir: str = "output"
    log_level: str = "INFO"

    # Ghidra headless
    ghidra_path: str = ""
    ghidra_timeout: int = 900

    # Кэширование
    use_cache: bool = True

    # Этап 2: фильтрация кандидатов
    min_function_size: int = 20

    # Этап 3: LLM
    use_llm: bool = False
    llm_top: int = 10
    ollama_url: str = "http://127.0.0.1:11434"
    model_name: str = "qwen2.5-coder:14b-instruct-q5_K_M"
    llm_timeout: int = 300
    llm_num_ctx: int = 8192

    # Скоринг: heuristic | ml
    scoring_mode: str = "heuristic"
    ml_weights_path: str = ""

    polish: bool = False

    # Порог score для cascade "called by user seed" (heuristic)
    hot_seed_score: int = 60

    # Optional domain pack: none | mycollatz
    domain_pack: str = "none"


def load_config(path: Union[str, Path]) -> AppConfig:
    """Загружает конфигурацию из YAML-файла."""
    config_path = Path(path)
    data: Dict[str, Any] = {}

    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception as exc:
            print(f"WARNING: cannot parse config.yaml ({exc}); using defaults")
            data = {}

    return AppConfig(
        binary_path=str(data.get("binary_path", AppConfig.binary_path)),
        output_dir=str(data.get("output_dir", AppConfig.output_dir)),
        log_level=str(data.get("log_level", AppConfig.log_level)),
        use_cache=bool(data.get("use_cache", AppConfig.use_cache)),
        min_function_size=int(data.get("min_function_size", AppConfig.min_function_size)),
        ghidra_path=str(data.get("ghidra_path", AppConfig.ghidra_path)),
        ghidra_timeout=int(data.get("ghidra_timeout", AppConfig.ghidra_timeout)),
        use_llm=bool(data.get("use_llm", AppConfig.use_llm)),
        llm_top=int(data.get("llm_top", AppConfig.llm_top)),
        ollama_url=str(data.get("ollama_url", AppConfig.ollama_url)),
        model_name=str(data.get("model_name", AppConfig.model_name)),
        llm_timeout=int(data.get("llm_timeout", AppConfig.llm_timeout)),
        llm_num_ctx=int(data.get("llm_num_ctx", AppConfig.llm_num_ctx)),
        hot_seed_score=int(data.get("hot_seed_score", AppConfig.hot_seed_score)),
        scoring_mode=str(data.get("scoring_mode", AppConfig.scoring_mode)),
        ml_weights_path=str(data.get("ml_weights_path", AppConfig.ml_weights_path)),
        polish=bool(data.get("polish", AppConfig.polish)),
        domain_pack=str(data.get("domain_pack", AppConfig.domain_pack)),
    )
