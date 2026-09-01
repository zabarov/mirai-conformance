"""Canonical JSON and digest helpers compatible with Mirai contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def digest_value(value: Any) -> str:
    payload = canonical_json(value).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def program_digest(program: dict[str, Any]) -> str:
    payload = {
        key: value
        for key, value in program.items()
        if key not in {"digest", "source_map"}
    }
    return digest_value(payload)
