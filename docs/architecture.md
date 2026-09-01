# Checker Architecture

Status: alpha

The checker is deliberately separate from the Mirai TypeScript implementation.

```text
public Mirai corpus and schemas
-> Python shape and semantic validator
-> Python expression evaluator
-> Python deterministic pure interpreter
-> Python conformance result
-> implementation-neutral result comparison
```

The checker may share contracts and fixtures with Mirai. It must not import
Mirai TypeScript modules, invoke the Mirai CLI to obtain its result, or accept
an effect capability. Agreement therefore detects implementation drift across
two codebases while retaining one canonical corpus.

Future contract batches may add receipt, transition-trace and governed-episode
validation. They must remain evidence checks, not runtime authorization.

## Graph-Native Contracts

The checker validates Mirai 2.1 artifacts using Python-owned semantic code. It
recomputes canonical digests, graph snapshot binding, dependency frontiers,
deterministic path order, successful-path coverage and aggregate activation
trace digests. It does not import or call the TypeScript resolver or runtime.

Schema conformance is necessary but not sufficient. A schema-valid activation
plan still fails if its graph digest, dependency graph or deterministic order is
inconsistent. Runtime evidence never authorizes effects, canonical writes or
learning updates.
