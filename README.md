# Mirai Conformance

Status: independent checker alpha (`0.2.0a1`)

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

## Boundary

Passing this checker proves agreement with the checked public corpus or
internal consistency of the supplied sanitized evidence. It does not prove
that an arbitrary Mirai program is correct, safe for production, or authorized
to perform an effect. Capability grants, approval signatures, secret values and
external world state remain host-local and outside this checker.
