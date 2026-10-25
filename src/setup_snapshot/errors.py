from __future__ import annotations


class SnapshotError(Exception):
    """Any refusal: bad input, failed check, unsafe archive. Messages never contain secret values."""
