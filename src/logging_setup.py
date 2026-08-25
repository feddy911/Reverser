from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Union


def setup_logging(output_dir: Union[str, Path], level: str = "INFO") -> Path:
    """
    Настраивает логирование и создает директорию для конкретного запуска.

    Возвращает путь к директории запуска, например:
    output/logs/run_20260821_153015_123456
    """
    run_dir = (
        Path(output_dir)
        / "logs"
        / datetime.now().strftime("run_%Y%m%d_%H%M%S_%f")
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("revllm")
    logger.setLevel(level.upper())

    # Очищаем старые handlers, если они уже были добавлены.
    logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level.upper())
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # App log
    app_file_handler = logging.FileHandler(run_dir / "app.log", encoding="utf-8")
    app_file_handler.setLevel(logging.DEBUG)
    app_file_handler.setFormatter(formatter)
    logger.addHandler(app_file_handler)

    # Error log
    error_file_handler = logging.FileHandler(run_dir / "error.log", encoding="utf-8")
    error_file_handler.setLevel(logging.ERROR)
    error_file_handler.setFormatter(formatter)
    logger.addHandler(error_file_handler)

    logger.info("Run directory: %s", run_dir)
    return run_dir