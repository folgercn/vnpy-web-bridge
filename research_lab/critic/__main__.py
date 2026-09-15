from __future__ import annotations

import argparse
from pathlib import Path

from research_lab.schemas import ValidationResult

from .engine import CriticAgent


def main() -> None:
    parser = argparse.ArgumentParser(description="Review a local Research Lab validation result")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--validation-id", help="validation ID stored under --output")
    source.add_argument("--validation-json", help="path to a validation JSON artifact")
    parser.add_argument("--candidate-id", help="optional stable candidate identifier")
    parser.add_argument("--output", default="research_lab_output", help="local artifact and SQLite directory")
    arguments = parser.parse_args()
    agent = CriticAgent.local(arguments.output)
    if arguments.validation_id:
        result = agent.review_persisted(arguments.validation_id, candidate_id=arguments.candidate_id)
    else:
        payload = Path(arguments.validation_json).read_text(encoding="utf-8")
        result = agent.review(ValidationResult.model_validate_json(payload), candidate_id=arguments.candidate_id)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
