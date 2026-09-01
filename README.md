# Mirai Conformance

Status: independent checker alpha

`mirai-conformance` is an independent Python implementation of the public
Mirai conformance contracts. It does not import the TypeScript runtime and it
does not execute external effects.

Its first supported surface is the Mirai Program `1.0.0` pure-language corpus:

- JSON Schema and semantic validation;
- safe expression evaluation;
- deterministic execution of pure control-flow nodes;
- output and decision-trace digest comparison;
- expected validation failures;
- cross-checking a Python result against a TypeScript reference result.

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

## Boundary

Passing this checker proves agreement with the checked public corpus. It does
not prove that an arbitrary Mirai program is correct, safe for production, or
authorized to perform an effect. Runtime capabilities, approvals and external
world state remain outside this pure checker.
