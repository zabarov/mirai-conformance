# Release Checklist

Status: public alpha preparation

## Independence Boundary

- The checker must not import Mirai TypeScript modules or execute its CLI as
  validation logic.
- The shared corpus, schemas and public fixtures are inputs, not trusted
  expected verdicts.
- External effects, credentials, capability grants and approval signatures are
  outside the checker.

## Required Checks

1. Pin CI to an exact public Mirai revision and record that revision in the
   corresponding Mirai release-readiness evidence.
2. Run all tests on Linux, macOS and Windows with Python 3.12.
3. Run the shared corpus through the installed `mirai-conformance` command.
4. Build both wheel and source distribution from a clean checkout.
5. Verify that no Mirai TypeScript package is present in Python dependencies.
6. Record the checker revision and CI run in Mirai release-readiness evidence.

## Local Clean-Room Command

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
MIRAI_REPO=/path/to/exact/mirai-checkout \
  python -m unittest discover -s tests -v
```

Do not rely on an inherited `MIRAI_REPO`: bind it explicitly for every
clean-room run. A stale path is an environment/configuration failure, not a
conformance verdict.

Passing these checks establishes public reproducibility of the checked
contracts. It does not establish production safety or authorize a Mirai
runtime effect.
