"""Offline release-signature and A/B update simulation primitives."""

from .core import (
    GuardError,
    abort_release,
    canonical_bytes,
    commit_release,
    load_json,
    rotate_root,
    stage_release,
    validate_root,
    validate_state,
    verify_release,
)

__all__ = [
    "GuardError",
    "abort_release",
    "canonical_bytes",
    "commit_release",
    "load_json",
    "rotate_root",
    "stage_release",
    "validate_root",
    "validate_state",
    "verify_release",
]
