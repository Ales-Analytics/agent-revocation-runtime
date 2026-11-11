"""Exception hierarchy for ales_core."""

from __future__ import annotations


class AlesError(Exception):
    """Base class for all ales_core errors."""


class LineageIncomplete(AlesError):
    """A derivation references parents that are not registered in the tenant."""

    def __init__(self, missing: list[tuple[str, str]]):
        self.missing = missing
        super().__init__(f"lineage incomplete; missing parents: {missing}")


class AuthorityWidening(AlesError):
    """A derivative claims wider authority than its parents permit."""


class DuplicateContext(AlesError):
    """A (context_id, object_version) already exists with different content."""


class InvalidEnvelope(AlesError):
    """The envelope is structurally unusable for the requested operation."""
