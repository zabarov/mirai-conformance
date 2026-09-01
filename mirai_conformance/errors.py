"""Typed checker errors."""

from __future__ import annotations


class MiraiConformanceError(Exception):
    def __init__(self, code: str, message: str | None = None, node_id: str | None = None):
        super().__init__(message or code)
        self.code = code
        self.node_id = node_id


class ProgramValidationError(MiraiConformanceError):
    def __init__(self, errors: list[str]):
        super().__init__("program_invalid", ", ".join(errors))
        self.errors = errors
