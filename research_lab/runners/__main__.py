from __future__ import annotations

import argparse

from research_lab.runners import ExperimentRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a Research Lab experiment YAML")
    parser.add_argument("experiment", help="path to experiment YAML")
    parser.add_argument("--output", default="research_lab_output", help="result store directory")
    arguments = parser.parse_args()
    result = ExperimentRunner.local(arguments.output).run_yaml(arguments.experiment)
    print(result.model_dump_json(indent=2))
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
