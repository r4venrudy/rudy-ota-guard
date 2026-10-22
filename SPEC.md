# Rudy OTA Guard implementation contract

Offline educational/portfolio release-verification and A/B transaction simulator. No networking, no real devices, no bootloader changes, no production certification claims. Python >=3.11, established cryptography Ed25519, stdlib unittest. Source package `src/otaguard`.

## Data model

All JSON objects reject duplicate keys, unknown keys and noninteger numeric inputs. Integers exclude bool, range 0..2^53-1. Text identifiers ASCII `[A-Za-z0-9._-]{1,80}`. Keys/public-key/signature base64 strictly validated. Fixed UTC epoch `now` supplied explicitly by API/CLI, positive. JSON file max 1MiB. Canonical signing bytes: `b'RUDY-OTA-GUARD-v1\n' + json.dumps(signed, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')`. This is a restricted project format, not RFC8785/TUF/Uptane compatibility.

Pinned root document (operator-trusted input, not magically self-authenticating):
`{"schema":1,"type":"root","version":1,"expires_at":2000000000,"threshold":1,"keys":[{"keyid":"root-a","public_key":"BASE64_ED25519_RAW32","not_before":1,"expires_at":2000000000,"revoked":false,"roles":["root","release"]}]}`.
Keys unique keyid AND unique public_key, max32 keys. Threshold 1..count valid keys. At verification count UNIQUE eligible signer PUBLIC KEYS (not duplicated signature records); eligible role, not revoked, `not_before <= now < expires_at`; require root `now < expires_at`. Malformed/unknown signature signer must fail closed. Max64 signature records.

Envelope: `{"signed": BODY, "signatures":[{"keyid":"root-a","sig":"BASE64_RAW64"}]}`.
Release BODY has EXACT keys: `schema:1,type:"release",sequence:int,release_id:id,target:id,architecture:id,rollback_index:int,payload_sha256:lowercase64hex,payload_size:int,expires_at:int`.
Initial device state EXACT keys: `schema:1,target:id,architecture:id,active_slot:"A"|"B",last_sequence:int,rollback_index:int,active_release:id,pending:null|PENDING`.
PENDING EXACT fields: `sequence,release_id,rollback_index,payload_sha256,payload_size,slot,verified_at` matching validated release plus inactive slot and timestamp. Reject inconsistent pending sequence <= last_sequence, rollback below current, or pending.slot==active_slot. State is caller-trusted simulation input: no hardware/TPM monotonic-storage guarantee.

## API in otaguard.core

- `GuardError(code, message)` with `.code` and `.message`.
- `load_json(path)` bounded strict JSON parser.
- `canonical_bytes(signed:dict)->bytes`.
- `validate_root(root, now)->None`.
- `validate_state(state)->None`.
- `verify_release(envelope, root, state, payload_path, now)->dict`: no state changes, require no pending update; validate payload size max256MiB, streaming SHA256, exact length/hash, ordinary regular nonsymlink explicit payload path, never path from signed data. Verify threshold, target/architecture, sequence>last_sequence, rollback_index>=current, expiry. Return deterministic report `{"status":"verified","release_id":...,"sequence":...,"rollback_index":...,"payload_sha256":...,"payload_size":...,"signers":[sorted unique keyids],"inactive_slot":"A"|"B"}`.
- `stage_release(envelope,root,state,payload_path,now)->dict`: calls verification, returns deep-copied state with pending, active state/counters unchanged.
- `commit_release(state, healthy:bool)->dict`: healthy must true, pending required, validate state; promote pending slot/release/counters, clear pending. No health attestation claim.
- `abort_release(state)->dict`: pending required, clear pending only, all active values unchanged.
- `rotate_root(envelope,current_root,now)->dict`: signed BODY is full new root as above; new.version==old.version+1, future expiry; verify envelope under BOTH eligible old-root threshold and eligible new-root threshold, only signatures belonging to relevant root count. Reject totally unknown signer not present in either root, no duplicate public keys. Return deep-copied new root. Handles revocation by removing/revoking keys via authorized root transition. Cannot rotate an expired old root.

Errors short stable codes e.g. schema, duplicate_key, size_limit, signature, threshold, expired, key_expired, key_revoked, target, rollback, replay, payload_hash, payload_size, pending, health, file_type. Tests may check rejection without assuming every exact code until interface stabilizes, never swallow success for bad fixture.

## CLI in otaguard.cli / __main__

Commands `verify`, `stage` (both `--manifest --root --state --payload --now`), `commit` (`--state --healthy`), `abort` (`--state`), `rotate-root` (`--manifest --root --now`). Read inputs only, print deterministic JSON result/new state/root to stdout. NO in-place writes, no root/key generation or implicit state persistence, no hidden signing or network. Exit0 successful,2 rejected invalid input,3 IO failure. Error JSON no traceback/secret/full paths. stdout redirected by operator explicitly to a NEW file; document never overwrite trusted state while reading it.

## Team ownership

Security agent owns src/otaguard/core.py + cli.py + __main__.py + __init__.py only. Software agent owns tests/ only, independent signed fixture helpers and adversarial tests. Support agent owns README.md, docs/, assets/banner.svg, .github/workflows/ci.yml, LICENSE, .gitignore only. Root owns packaging, demo generator/example outputs, integration fixes/review and publication. No external actions or nested agents by workers.

## Acceptance

Real valid and invalid Ed25519 signatures, target binding, monotonic sequence/replay, rollback index, key expiry/revocation, signer de-dup, dual-threshold rotation, expired root rejection, A/B stage/abort/health-gated commit, payload tampering/length, strict malformed input, deterministic outputs, CLI subprocess exit/error checks. All tests synthetic/offline. Run Windows locally and Linux through GitHub Actions before claiming Linux support. Document clock, trust-anchor/state persistence and caller health assumptions. No claim this implements secure boot or production OTA/TUF/Uptane.
