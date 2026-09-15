from __future__ import annotations

import argparse

from research_lab.sweeps import ParameterSweepEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a local sequential Research Lab parameter sweep")
    parser.add_argument("sweep", help="path to sweep YAML")
    parser.add_argument("--output", default="research_lab_output", help="result store directory")
    arguments = parser.parse_args()
    result = ParameterSweepEngine.local(arguments.output).run_yaml(arguments.sweep)
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
