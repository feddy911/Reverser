from __future__ import annotations

import argparse
import sys

from src.config import load_config
from src.pipeline.runner import run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reverse engineering pipeline: Ghidra → score → LLM restore"
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML config file",
    )

    parser.add_argument(
        "--binary",
        help="Override binary path from config",
    )

    parser.add_argument(
        "--output",
        help="Override output directory from config",
    )

    parser.add_argument(
        "--log-level",
        dest="log_level",
        help="Override log level: DEBUG, INFO, WARNING, ERROR",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = load_config(args.config)

    if args.binary:
        config.binary_path = args.binary

    if args.output:
        config.output_dir = args.output

    if args.log_level:
        config.log_level = args.log_level

    return run(config)


if __name__ == "__main__":
    sys.exit(main())
