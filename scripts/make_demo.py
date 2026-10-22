"""Regenerate public, deterministic, synthetic examples. NEVER use these keys in production."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NOW = 1_900_000_000
PREFIX = b"RUDY-OTA-GUARD-v1\n"
ROOT = Path(__file__).resolve().parents[1]


def canonical(body):
    return PREFIX + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def private_key(name):
    # PUBLIC TEST seed, intentionally reproducible and not a secret.
    seed = hashlib.sha256(("RUDY PUBLIC DEMO ONLY, NOT A SECRET: " + name).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def key_record(name):
    return {
        "keyid": name,
        "public_key": base64.b64encode(private_key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii"),
        "not_before": NOW - 1000,
        "expires_at": NOW + 86400,
        "revoked": False,
        "roles": ["root", "release"],
    }


def sign(body, names):
    return {"signed": body, "signatures": [
        {"keyid": name, "sig": base64.b64encode(private_key(name).sign(canonical(body))).decode("ascii")}
        for name in names
    ]}


def main():
    out = ROOT / "examples"
    out.mkdir(exist_ok=True)
    payload = b"RUDY OTA GUARD - SYNTHETIC DEMO PAYLOAD, NOT FIRMWARE\n" * 7
    pinned = {"schema": 1, "type": "root", "version": 1, "expires_at": NOW + 86400,
              "threshold": 2, "keys": [key_record("release-a"), key_record("release-b")]}
    state = {"schema": 1, "target": "lab-controller", "architecture": "arm64", "active_slot": "A",
             "last_sequence": 0, "rollback_index": 1, "active_release": "factory", "pending": None}
    release = {"schema": 1, "type": "release", "sequence": 1, "release_id": "lab-v1.1.0",
               "target": state["target"], "architecture": state["architecture"], "rollback_index": 2,
               "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_size": len(payload),
               "expires_at": NOW + 3600}
    replacement = {**pinned, "version": 2, "keys": [key_record("release-b"), key_record("release-c")]}
    documents = {"root.json": pinned, "state.json": state,
                 "manifest.json": sign(release, ["release-a", "release-b"]),
                 "rotation.json": sign(replacement, ["release-a", "release-b", "release-c"])}
    for name, document in documents.items():
        (out / name).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "payload.bin").write_bytes(payload)
    print("Synthetic examples regenerated. Fixed verification time: 1900000000. Demo keys are public and unsafe for real releases.")


if __name__ == "__main__":
    main()
