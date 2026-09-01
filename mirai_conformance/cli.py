"""Command line interface for the independent checker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .corpus import compare_results, run_corpus, write_json
from .runtime import check_episode, check_evidence
from .validator import load_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mirai-conformance")
    parser.add_argument("--version", action="version", version="mirai-conformance 0.2.0a1")
    commands = parser.add_subparsers(dest="command", required=True)

    corpus = commands.add_parser("corpus", help="Run a public Mirai conformance corpus")
    corpus.add_argument("corpus")
    corpus.add_argument("--program-schema", required=True)
    corpus.add_argument("--output")

    compare = commands.add_parser("compare", help="Compare two conformance results")
    compare.add_argument("reference")
    compare.add_argument("candidate")
    compare.add_argument("--output")

    episode = commands.add_parser("episode", help="Validate a public pure episode")
    episode.add_argument("episode")
    episode.add_argument("--schema")
    episode.add_argument("--program")
    episode.add_argument("--output")

    evidence = commands.add_parser("evidence", help="Validate sanitized runtime evidence")
    evidence.add_argument("evidence")
    evidence.add_argument("--schema")
    evidence.add_argument("--output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "corpus":
        result = run_corpus(args.corpus, args.program_schema)
    elif args.command == "compare":
        result = compare_results(load_json(args.reference), load_json(args.candidate))
    elif args.command == "episode":
        result = check_episode(args.episode, args.schema, args.program)
    else:
        result = check_evidence(args.evidence, args.schema)
    if args.output:
        write_json(Path(args.output), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] in {"passed", "match"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
