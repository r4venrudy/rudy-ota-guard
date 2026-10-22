# Format and state model

RUDY OTA Guard accepts a small, versioned JSON format. The implementation contract is in `SPEC.md`; this document explains the operational model and the assumptions a caller must supply.

## Inputs

- **Root document:** operator-provided trusted Ed25519 public keys, key validity intervals, roles, revocation flags, expiry, and threshold. The root is not self-authenticating; trust in its initial contents comes from outside this project.
- **Release envelope:** a signed release body plus signatures. The body binds an identifier, target, architecture, sequence, rollback index, payload hash and length, and expiry.
- **Device state:** caller-provided target, architecture, active A/B slot, accepted sequence and rollback index, active release, and optional pending transition.
- **Payload:** a separate path explicitly supplied by the caller. A signed document cannot choose a local path.
- **Time:** a positive Unix timestamp passed explicitly as `--now` for verification/staging/root rotation.

The parser is bounded and strict: JSON files are limited to 1 MiB, numeric values are restricted integers, and duplicate or unknown fields are rejected. The payload is hashed incrementally and is limited to 256 MiB.

## Verification and transition

`verify` validates the root and state, confirms the release threshold using unique eligible public keys, checks target/architecture, expiry, sequence and rollback constraints, then checks the payload length and SHA-256. It returns a report and does not alter state.

`stage` performs the same verification and returns a copy of state with a pending update for the inactive slot. It leaves active release, sequence, and rollback values unchanged. `abort` clears that pending update and leaves active values alone. `commit --healthy` promotes the pending values only when the caller supplies the health assertion. This simulator does not observe or attest actual device health.

`rotate-root` requires the proposed root to be authorized by eligible thresholds from both the current and proposed root. The old root must still be valid at the supplied time. A new root is returned on stdout; the program does not install it or persist it.

## Canonical signature bytes

The project signs the prefix `RUDY-OTA-GUARD-v1\n` followed by compact, sorted-key ASCII JSON for the signed object. This is a restricted project encoding, not a general JSON canonicalization standard. Do not assume interoperability with another update framework.

## Safe output handling

The CLI is read-only with respect to its inputs and writes result JSON to stdout. Choose a distinct new path when redirecting output. Never overwrite a root or state file while it is being used as an input. The program does not make backups or manage durable state for a real device.
