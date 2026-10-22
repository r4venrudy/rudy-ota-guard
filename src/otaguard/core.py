"""Offline primitives for the educational Rudy OTA Guard format.

This module deliberately does not fetch artifacts, discover trust roots, write
device state, or claim to implement a production secure-update standard.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_JSON_BYTES = 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_INT = (1 << 53) - 1
MAX_KEYS = 32
MAX_SIGNATURES = 64
_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PREFIX = b"RUDY-OTA-GUARD-v1\n"


class GuardError(Exception):
    """Stable, short validation or I/O failure suitable for CLI reporting."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _fail(code: str, message: str) -> None:
    raise GuardError(code, message)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key", "JSON object contains a duplicate key")
        result[key] = value
    return result


def _bad_constant(_: str) -> None:
    _fail("schema", "nonstandard JSON numeric constant")


def load_json(path: str | os.PathLike[str]) -> Any:
    """Load one bounded UTF-8 JSON document, rejecting ambiguous syntax."""
    try:
        file_path = Path(path)
        info = file_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail("file_type", "JSON input must be an ordinary regular nonsymlink file")
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        fd = os.open(file_path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
                _fail("file_type", "JSON input must be an ordinary regular nonsymlink file")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                raw = handle.read(MAX_JSON_BYTES + 1)
        finally:
            os.close(fd)
    except GuardError:
        raise
    except (OSError, ValueError, TypeError):
        _fail("io", "unable to read input")
    if len(raw) > MAX_JSON_BYTES:
        _fail("size_limit", "JSON input exceeds the 1 MiB limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                          parse_constant=_bad_constant)
    except GuardError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail("schema", "invalid JSON input")


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail("schema", f"{label} has missing, unknown, or invalid fields")
    return value


def _int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INT:
        _fail("schema", f"{label} must be an integer in range")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail("schema", f"{label} is invalid")
    return value


def _b64(value: Any, expected: int, label: str) -> bytes:
    if type(value) is not str or len(value) > 256:
        _fail("schema", f"{label} is invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        _fail("schema", f"{label} is invalid base64")
    if len(decoded) != expected or base64.b64encode(decoded).decode("ascii") != value:
        _fail("schema", f"{label} has invalid length or encoding")
    return decoded


def _root_keys(root: Any) -> list[dict[str, Any]]:
    obj = _object(root, {"schema", "type", "version", "expires_at", "threshold", "keys"}, "root")
    if _int(obj["schema"], "root schema") != 1 or obj["type"] != "root":
        _fail("schema", "unsupported root schema")
    _int(obj["version"], "root version", minimum=1)
    _int(obj["expires_at"], "root expiry", minimum=1)
    threshold = _int(obj["threshold"], "root threshold", minimum=1)
    keys = obj["keys"]
    if type(keys) is not list or not 1 <= len(keys) <= MAX_KEYS or threshold > len(keys):
        _fail("schema", "root key count or threshold is invalid")
    seen_ids: set[str] = set()
    seen_public: set[bytes] = set()
    normalized: list[dict[str, Any]] = []
    for item in keys:
        key = _object(item, {"keyid", "public_key", "not_before", "expires_at", "revoked", "roles"}, "root key")
        keyid = _identifier(key["keyid"], "key id")
        pub = _b64(key["public_key"], 32, "public key")
        before = _int(key["not_before"], "key not-before")
        expiry = _int(key["expires_at"], "key expiry", minimum=1)
        if before >= expiry or type(key["revoked"]) is not bool:
            _fail("schema", "root key time or revocation flag is invalid")
        roles = key["roles"]
        if (type(roles) is not list or not roles
                or any(type(r) is not str or r not in ("root", "release") for r in roles)):
            _fail("schema", "root key roles are invalid")
        if len(set(roles)) != len(roles):
            _fail("schema", "root key roles contain duplicates")
        if keyid in seen_ids or pub in seen_public:
            _fail("schema", "root key ids and public keys must be unique")
        seen_ids.add(keyid)
        seen_public.add(pub)
        normalized.append({"keyid": keyid, "public": pub, "not_before": before,
                           "expires_at": expiry, "revoked": key["revoked"], "roles": roles})
    return normalized


def validate_root(root: dict[str, Any], now: int) -> None:
    _int(now, "current time", minimum=1)
    _root_keys(root)
    expiry = root["expires_at"]
    if now >= expiry:
        _fail("expired", "trust root has expired")


def canonical_bytes(signed: dict[str, Any]) -> bytes:
    if type(signed) is not dict:
        _fail("schema", "signed body must be a JSON object")
    try:
        encoded = json.dumps(signed, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail("schema", "signed body cannot be canonicalized")
    if len(encoded) > MAX_JSON_BYTES:
        _fail("size_limit", "signed body exceeds the 1 MiB limit")
    return _PREFIX + encoded


def _validate_release(body: Any) -> dict[str, Any]:
    obj = _object(body, {"schema", "type", "sequence", "release_id", "target", "architecture",
                         "rollback_index", "payload_sha256", "payload_size", "expires_at"}, "release")
    if _int(obj["schema"], "release schema") != 1 or obj["type"] != "release":
        _fail("schema", "unsupported release schema")
    _int(obj["sequence"], "sequence", minimum=1)
    for name in ("release_id", "target", "architecture"):
        _identifier(obj[name], name)
    _int(obj["rollback_index"], "rollback index")
    if type(obj["payload_sha256"]) is not str or not _SHA256.fullmatch(obj["payload_sha256"]):
        _fail("schema", "payload hash must be lowercase SHA-256 hex")
    size = _int(obj["payload_size"], "payload size")
    if size > MAX_PAYLOAD_BYTES:
        _fail("size_limit", "payload exceeds the 256 MiB limit")
    _int(obj["expires_at"], "release expiry", minimum=1)
    return obj


def _validate_envelope(envelope: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    env = _object(envelope, {"signed", "signatures"}, "envelope")
    if type(env["signatures"]) is not list or len(env["signatures"]) > MAX_SIGNATURES:
        _fail("schema", "signature list is invalid or too large")
    signatures: list[dict[str, Any]] = []
    seen_keyids: set[str] = set()
    for item in env["signatures"]:
        sig = _object(item, {"keyid", "sig"}, "signature")
        keyid = _identifier(sig["keyid"], "signature key id")
        raw = _b64(sig["sig"], 64, "signature")
        # Repeated records are rejected. Threshold counting is independently
        # based on unique public keys, including during root transitions.
        if keyid in seen_keyids:
            _fail("signature", "duplicate signer record")
        seen_keyids.add(keyid)
        signatures.append({"keyid": keyid, "raw": raw})
    return env["signed"], signatures


def _check_signatures(body: dict[str, Any], signatures: list[dict[str, Any]],
                      root: dict[str, Any], now: int, role: str,
                      *, allow_missing: bool = False,
                      skip_ineligible: bool = False) -> list[str]:
    keys = _root_keys(root)
    by_id = {key["keyid"]: key for key in keys}
    threshold = root["threshold"]
    message = canonical_bytes(body)
    counted_public: set[bytes] = set()
    signers: list[str] = []
    for sig in signatures:
        key = by_id.get(sig["keyid"])
        if key is None:
            if allow_missing:
                continue
            _fail("signature", "signature references an unknown signer")
        if key["revoked"]:
            if skip_ineligible:
                continue
            _fail("key_revoked", "signature uses a revoked key")
        if not (key["not_before"] <= now < key["expires_at"]):
            if skip_ineligible:
                continue
            _fail("key_expired", "signature uses a key outside its validity period")
        if role not in key["roles"]:
            if skip_ineligible:
                continue
            _fail("signature", "signer is not authorized for this role")
        try:
            Ed25519PublicKey.from_public_bytes(key["public"]).verify(sig["raw"], message)
        except InvalidSignature:
            _fail("signature", "signature verification failed")
        if key["public"] not in counted_public:
            counted_public.add(key["public"])
            signers.append(key["keyid"])
    if len(counted_public) < threshold:
        _fail("threshold", "signature threshold was not met")
    return sorted(signers)


def validate_state(state: dict[str, Any]) -> None:
    obj = _object(state, {"schema", "target", "architecture", "active_slot", "last_sequence",
                          "rollback_index", "active_release", "pending"}, "state")
    if _int(obj["schema"], "state schema") != 1:
        _fail("schema", "unsupported state schema")
    _identifier(obj["target"], "state target")
    _identifier(obj["architecture"], "state architecture")
    if type(obj["active_slot"]) is not str or obj["active_slot"] not in ("A", "B"):
        _fail("schema", "active slot must be A or B")
    _int(obj["last_sequence"], "last sequence")
    _int(obj["rollback_index"], "state rollback index")
    _identifier(obj["active_release"], "active release")
    pending = obj["pending"]
    if pending is None:
        return
    p = _object(pending, {"sequence", "release_id", "rollback_index", "payload_sha256",
                          "payload_size", "slot", "verified_at"}, "pending state")
    _int(p["sequence"], "pending sequence", minimum=1)
    _identifier(p["release_id"], "pending release id")
    _int(p["rollback_index"], "pending rollback index")
    if type(p["payload_sha256"]) is not str or not _SHA256.fullmatch(p["payload_sha256"]):
        _fail("schema", "pending payload hash is invalid")
    if _int(p["payload_size"], "pending payload size") > MAX_PAYLOAD_BYTES:
        _fail("size_limit", "pending payload exceeds the 256 MiB limit")
    if type(p["slot"]) is not str or p["slot"] not in ("A", "B"):
        _fail("schema", "pending slot must be A or B")
    _int(p["verified_at"], "pending verification time", minimum=1)
    if p["sequence"] <= obj["last_sequence"]:
        _fail("replay", "pending sequence is not newer than active state")
    if p["rollback_index"] < obj["rollback_index"]:
        _fail("rollback", "pending rollback index is lower than active state")
    if p["slot"] == obj["active_slot"]:
        _fail("pending", "pending update must target the inactive slot")


def _hash_payload(payload_path: str | os.PathLike[str], expected_size: int) -> str:
    try:
        path = Path(payload_path)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            _fail("file_type", "payload must be an ordinary regular nonsymlink file")
        if info.st_size > MAX_PAYLOAD_BYTES:
            _fail("size_limit", "payload exceeds the 256 MiB limit")
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
                _fail("file_type", "payload must be an ordinary regular nonsymlink file")
            if opened.st_size > MAX_PAYLOAD_BYTES:
                _fail("size_limit", "payload exceeds the 256 MiB limit")
            digest = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "rb", closefd=False) as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_PAYLOAD_BYTES or total > expected_size:
                        _fail("payload_size", "payload length does not match the signed size")
                    digest.update(block)
            if total != expected_size:
                _fail("payload_size", "payload length does not match the signed size")
            return digest.hexdigest()
        finally:
            os.close(fd)
    except GuardError:
        raise
    except (OSError, ValueError, TypeError):
        _fail("io", "unable to read payload")


def _verify_release(envelope: Any, root: dict[str, Any], state: dict[str, Any],
                    payload_path: str | os.PathLike[str], now: int) -> tuple[dict[str, Any], list[str], str]:
    _int(now, "current time", minimum=1)
    validate_root(root, now)
    validate_state(state)
    if state["pending"] is not None:
        _fail("pending", "an update is already pending")
    body, signatures = _validate_envelope(envelope)
    release = _validate_release(body)
    signers = _check_signatures(release, signatures, root, now, "release")
    if release["expires_at"] <= now:
        _fail("expired", "release manifest has expired")
    if release["target"] != state["target"] or release["architecture"] != state["architecture"]:
        _fail("target", "release target or architecture does not match state")
    if release["sequence"] <= state["last_sequence"]:
        _fail("replay", "release sequence is not newer than active state")
    if release["rollback_index"] < state["rollback_index"]:
        _fail("rollback", "release rollback index is lower than active state")
    actual_hash = _hash_payload(payload_path, release["payload_size"])
    if actual_hash != release["payload_sha256"]:
        _fail("payload_hash", "payload hash does not match signed manifest")
    inactive = "B" if state["active_slot"] == "A" else "A"
    return release, signers, inactive


def verify_release(envelope: dict[str, Any], root: dict[str, Any], state: dict[str, Any],
                   payload_path: str | os.PathLike[str], now: int) -> dict[str, Any]:
    release, signers, inactive = _verify_release(envelope, root, state, payload_path, now)
    return {"status": "verified", "release_id": release["release_id"],
            "sequence": release["sequence"], "rollback_index": release["rollback_index"],
            "payload_sha256": release["payload_sha256"], "payload_size": release["payload_size"],
            "signers": signers, "inactive_slot": inactive}


def stage_release(envelope: dict[str, Any], root: dict[str, Any], state: dict[str, Any],
                  payload_path: str | os.PathLike[str], now: int) -> dict[str, Any]:
    release, _, inactive = _verify_release(envelope, root, state, payload_path, now)
    result = copy.deepcopy(state)
    result["pending"] = {"sequence": release["sequence"], "release_id": release["release_id"],
                         "rollback_index": release["rollback_index"],
                         "payload_sha256": release["payload_sha256"],
                         "payload_size": release["payload_size"], "slot": inactive,
                         "verified_at": now}
    validate_state(result)
    return result


def commit_release(state: dict[str, Any], healthy: bool) -> dict[str, Any]:
    validate_state(state)
    if type(healthy) is not bool or not healthy:
        _fail("health", "commit requires an explicit healthy=true result")
    pending = state["pending"]
    if pending is None:
        _fail("pending", "no staged update is pending")
    result = copy.deepcopy(state)
    result["active_slot"] = pending["slot"]
    result["last_sequence"] = pending["sequence"]
    result["rollback_index"] = pending["rollback_index"]
    result["active_release"] = pending["release_id"]
    result["pending"] = None
    validate_state(result)
    return result


def abort_release(state: dict[str, Any]) -> dict[str, Any]:
    validate_state(state)
    if state["pending"] is None:
        _fail("pending", "no staged update is pending")
    result = copy.deepcopy(state)
    result["pending"] = None
    validate_state(result)
    return result


def rotate_root(envelope: dict[str, Any], current_root: dict[str, Any], now: int) -> dict[str, Any]:
    _int(now, "current time", minimum=1)
    validate_root(current_root, now)
    body, signatures = _validate_envelope(envelope)
    if type(body) is not dict:
        _fail("schema", "new root must be an object")
    new_root = copy.deepcopy(body)
    validate_root(new_root, now)
    if new_root["version"] != current_root["version"] + 1:
        _fail("schema", "new root version must increment by exactly one")
    if new_root["expires_at"] <= now:
        _fail("expired", "new root must remain valid in the future")

    old_keys = {key["keyid"]: key for key in _root_keys(current_root)}
    new_keys = {key["keyid"]: key for key in _root_keys(new_root)}
    # A record may be recognized by either trust set, but a key id that is
    # reused for a different public key is ambiguous and therefore rejected.
    for keyid in old_keys.keys() & new_keys.keys():
        if old_keys[keyid]["public"] != new_keys[keyid]["public"]:
            _fail("schema", "root rotation may not rebind an existing key id")
    old_signers = _check_signatures(body, signatures, current_root, now, "root", allow_missing=True,
                                    skip_ineligible=True)
    new_signers = _check_signatures(body, signatures, new_root, now, "root", allow_missing=True,
                                    skip_ineligible=True)
    recognized = old_keys.keys() | new_keys.keys()
    if any(sig["keyid"] not in recognized for sig in signatures):
        _fail("signature", "root transition contains an unknown signer")
    if len(old_signers) < current_root["threshold"]:
        _fail("threshold", "old root signature threshold was not met")
    if len(new_signers) < new_root["threshold"]:
        _fail("threshold", "new root signature threshold was not met")
    return copy.deepcopy(new_root)
