"""Deterministic, test-only Ed25519 fixtures for the offline OTA simulator."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from otaguard.core import canonical_bytes


EPOCH = 1_800_000_000
ROOT_EXPIRY = EPOCH + 100_000
PAYLOAD = b"synthetic test image\x00v1\n"


def _test_key(label: str) -> Ed25519PrivateKey:
    """Derive reproducible private keys from explicitly test-only labels."""
    seed = hashlib.sha256(("TEST-ONLY-rudy-ota-guard-" + label).encode("ascii")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


KEYS = {name: _test_key(name) for name in ("root-a", "root-b", "release-a", "release-b", "outsider")}


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def make_key(
    keyid: str,
    key: Ed25519PrivateKey | None = None,
    *,
    roles: Iterable[str] = ("root", "release"),
    not_before: int = 1,
    expires_at: int = ROOT_EXPIRY,
    revoked: bool = False,
) -> dict[str, Any]:
    key = key or KEYS[keyid]
    return {
        "keyid": keyid,
        "public_key": public_b64(key),
        "not_before": not_before,
        "expires_at": expires_at,
        "revoked": revoked,
        "roles": list(roles),
    }


def make_root(
    *,
    version: int = 1,
    threshold: int = 1,
    keys: list[dict[str, Any]] | None = None,
    expires_at: int = ROOT_EXPIRY,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "type": "root",
        "version": version,
        "expires_at": expires_at,
        "threshold": threshold,
        "keys": keys if keys is not None else [make_key("root-a")],
    }


def make_state(
    *,
    target: str = "device-1",
    architecture: str = "amd64",
    active_slot: str = "A",
    last_sequence: int = 1,
    rollback_index: int = 1,
    active_release: str = "release-1",
    pending: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "target": target,
        "architecture": architecture,
        "active_slot": active_slot,
        "last_sequence": last_sequence,
        "rollback_index": rollback_index,
        "active_release": active_release,
        "pending": pending,
    }


def make_release(
    payload: bytes = PAYLOAD,
    *,
    sequence: int = 2,
    rollback_index: int = 2,
    release_id: str = "release-2",
    target: str = "device-1",
    architecture: str = "amd64",
    expires_at: int = ROOT_EXPIRY,
) -> dict[str, Any]:
    return {
        "schema": 1,
        "type": "release",
        "sequence": sequence,
        "release_id": release_id,
        "target": target,
        "architecture": architecture,
        "rollback_index": rollback_index,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "expires_at": expires_at,
    }


def signature_record(keyid: str, signed: dict[str, Any], key: Ed25519PrivateKey | None = None) -> dict[str, str]:
    signer = key or KEYS[keyid]
    return {
        "keyid": keyid,
        "sig": base64.b64encode(signer.sign(canonical_bytes(signed))).decode("ascii"),
    }


def envelope(signed: dict[str, Any], signers: Iterable[str] = ("root-a",)) -> dict[str, Any]:
    return {"signed": signed, "signatures": [signature_record(keyid, signed) for keyid in signers]}


def rotation_envelope(
    new_root: dict[str, Any],
    *,
    old_signers: Iterable[str] = ("root-a",),
    new_signers: Iterable[str] = ("root-b",),
) -> dict[str, Any]:
    signers = list(dict.fromkeys([*old_signers, *new_signers]))
    return envelope(new_root, signers)


def write_payload(path: Path, payload: bytes = PAYLOAD) -> Path:
    path.write_bytes(payload)
    return path


def json_bytes(value: Any) -> bytes:
    """Write a fixture in a stable but deliberately ordinary JSON form."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
