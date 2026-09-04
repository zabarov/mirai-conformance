# Mirai Conformance

The `0.6.0a1` development line adds independent semantic validation for Mirai
2.5 Outcome Completion while retaining Mirai 2.4 retrieval coverage.

```bash
mirai-conformance retrieval answer path/to/answer.json \
  --schema path/to/retrieval-answer.schema.json \
  --evidence path/to/evidence-bundle.json
```

Status: independent checker alpha (`0.6.0a1`), bound to the exact Mirai 2.5
CI candidate revision declared in the workflow.

[![Conformance](https://github.com/zabarov/mirai-conformance/actions/workflows/conformance.yml/badge.svg)](https://github.com/zabarov/mirai-conformance/actions/workflows/conformance.yml)

`mirai-conformance` is an independent Python implementation of the public
Mirai conformance contracts. It does not import the TypeScript runtime and it
does not execute external effects.

Supported surfaces are the Mirai Program `1.0.0` pure-language corpus and
public runtime evidence:

- JSON Schema and semantic validation;
- safe expression evaluation;
- deterministic execution of pure control-flow nodes;
- output and decision-trace digest comparison;
- expected validation failures;
- cross-checking a Python result against a TypeScript reference result.
- pure episode digest, trace and program binding checks;
- sanitized runtime evidence, receipt sequence and effect-summary consistency;
- fail-closed canonical-write and learning-update boundaries.
- Mirai 2.1 source catalog, assimilation proposal, component, relation-fact,
  technology-draft, technology qualification, hybrid plan, shadow differential,
  activation-plan and activation-run contracts;
- independent graph snapshot, dependency DAG and aggregate trace digest checks.
- Mirai 2.1 Project Capsule manifest, lock, START, facade and Agent Brief checks.
- Mirai 2.2 source snapshots, normalized units, knowledge proposals, process
  observations/candidates, autonomy envelopes, evolution decisions, promotion
  receipts and bounded autonomic cycles.
- Mirai 2.4 retrieval descriptors, plans, evidence-bound answers, federated
  query envelopes/results and bounded evaluation reports.
- Mirai 2.5 Outcome Completion contracts, deterministic status classification,
  evidence bindings, delivery plans and controlled pilot results.

## Install

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Run The Shared Corpus

The checker consumes the corpus from a Mirai checkout. It does not copy or
reinterpret private runtime data.

```bash
mirai-conformance corpus \
  ../mirai/conformance/corpus/pure/corpus.json \
  --program-schema ../mirai/schemas/mirai-program.schema.json \
  --output result.json
```

To compare both implementations:

```bash
mirai-conformance compare \
  typescript-result.json \
  python-result.json
```

To validate pilot episodes and sanitized runtime evidence independently:

```bash
mirai-conformance episode \
  episode.json \
  --schema mirai-pure-episode.schema.json \
  --program program.mirai.json

mirai-conformance evidence \
  mirai-evidence.json \
  --schema mirai-sanitized-evidence.schema.json
```

The example filenames are placeholders. In a Mirai checkout, pass the actual
public fixture, schema and compiled program paths.

To validate a graph-resolved activation without importing the TypeScript
runtime:

```bash
mirai-conformance graph-native activation-plan \
  activation-plan.json \
  --schema activation-plan.schema.json \
  --graph-snapshot graph-snapshot.json

mirai-conformance graph-native activation-run-result \
  activation-run-result.json \
  --schema activation-run-result.schema.json \
  --activation-plan activation-plan.json

mirai-conformance project ../mirai \
  --schemas ../mirai/schemas \
  --agent-brief agent-brief.json

mirai-conformance autonomic evolution-decision \
  evolution-decision.json \
  --schema evolution-decision.schema.json \
  --proposal evolution-proposal.json \
  --envelope autonomy-envelope.json
```

To validate Outcome Completion independently:

```bash
mirai-conformance outcome assessment assessment.json \
  --schema outcome-assessment.schema.json \
  --contract outcome-contract.json \
  --candidates candidate-set.json \
  --evidence evidence-set.json
```

## Boundary

The Mirai 2.5 candidate will be pinned only after the Mirai and checker commits
are fixed. Local tests do not establish public cross-platform verification;
record the public CI run before treating the candidate as a stable release
gate.

Passing this checker proves agreement with the checked public corpus or
internal consistency of the supplied sanitized evidence. It does not prove
that an arbitrary Mirai program is correct, safe for production, or authorized
to perform an effect. Capability grants, approval signatures, secret values and
external world state remain host-local and outside this checker.

Release and clean-room verification steps are defined in the
[release checklist](docs/release-checklist.md).
