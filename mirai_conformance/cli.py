"""Command line interface for the independent checker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .corpus import compare_results, run_corpus, write_json
from .graph_native import check_graph_native
from .runtime import check_episode, check_evidence
from .project import check_project
from .validator import load_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mirai-conformance")
    parser.add_argument("--version", action="version", version="mirai-conformance 0.3.0a1")
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

    graph_native = commands.add_parser("graph-native", help="Validate a Mirai 2.1 graph-native artifact")
    graph_native.add_argument("kind", choices=["source-catalog", "assimilation-proposal", "component-package", "relation-fact", "technology-draft", "activation-plan", "activation-run-result"])
    graph_native.add_argument("artifact")
    graph_native.add_argument("--schema", required=True)
    graph_native.add_argument("--graph-snapshot")
    graph_native.add_argument("--activation-plan")
    graph_native.add_argument("--output")
    project = commands.add_parser("project", help="Validate a Mirai 2.1 Project Capsule independently")
    project.add_argument("root")
    project.add_argument("--schemas", required=True)
    project.add_argument("--agent-brief")
    project.add_argument("--output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "corpus":
        result = run_corpus(args.corpus, args.program_schema)
    elif args.command == "compare":
        result = compare_results(load_json(args.reference), load_json(args.candidate))
    elif args.command == "episode":
        result = check_episode(args.episode, args.schema, args.program)
    elif args.command == "evidence":
        result = check_evidence(args.evidence, args.schema)
    elif args.command == "graph-native":
        result = check_graph_native(
            args.kind,
            load_json(args.artifact),
            load_json(args.schema),
            graph_snapshot=load_json(args.graph_snapshot) if args.graph_snapshot else None,
            activation_plan=load_json(args.activation_plan) if args.activation_plan else None,
        )
    else:
        result = check_project(args.root, args.schemas, args.agent_brief)
    if args.output:
        write_json(Path(args.output), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] in {"passed", "match"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
