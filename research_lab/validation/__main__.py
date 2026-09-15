from __future__ import annotations

import argparse

from .engine import WalkForwardValidationEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Research Lab walk-forward validation YAML")
    parser.add_argument("validation", help="path to validation YAML")
    parser.add_argument("--output", default="research_lab_output", help="result store directory")
    arguments = parser.parse_args()
    result = WalkForwardValidationEngine.local(arguments.output).run_yaml(arguments.validation)
    print(result.model_dump_json(indent=2))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
