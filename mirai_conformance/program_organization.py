"""Data-only differential corpus entrypoint. Never executes providers."""
import argparse
import json
from pathlib import Path
from referencing import Registry, Resource

from .validator import validate_program


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("program")
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--schema", required=True)
    args = parser.parse_args()
    try:
        program, catalog, schema = (json.loads(Path(p).read_text()) for p in (args.program, args.catalog, args.schema))
        registry = Registry()
        for name in ("graph-operation-snapshot", "cluster-proposal", "component-package"):
            dependency = json.loads(Path(args.schema).with_name(name + ".schema.json").read_text())
            registry = registry.with_resource(dependency["$id"], Resource.from_contents(dependency))
        errors = validate_program(program, schema=schema, catalog=catalog, schema_registry=registry)
    except (ValueError, KeyError, TypeError) as error:
        errors = [str(error)]
    print(json.dumps({"valid": not errors, "errors": errors, "scope": "program_binding_static_not_execution"}))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
