# Threat model and limits

## Intended use

This portfolio project demonstrates offline parsing and release-verification logic with synthetic fixtures. It is for code review, learning, and test scenarios. It is not a production update client and must not be used to authorize firmware or software deployment.

## In-scope checks

- Reject malformed, ambiguous, oversized, or structurally unexpected JSON.
- Verify release signatures and unique-key threshold counts against the supplied root.
- Bind releases to a target and architecture; enforce expiry, sequence, and rollback rules.
- Hash a separately supplied regular payload file and compare exact size and digest.
- Model A/B state transitions and old/new-root threshold authorization.
- Keep commands deterministic and offline, with no hidden input writes.

## Trust assumptions

The caller must provide an authentic root, a trustworthy current time, and a trustworthy current state. This code does not establish any of those facts. The state document has no TPM, secure element, filesystem anti-rollback, or other hardware-backed persistence. A caller can replace it or supply a stale copy. Threshold and key-revocation rules only have meaning if the root itself is authentic and protected.

The `--healthy` option is an explicit caller assertion. There is no device agent, boot validation, liveness signal, watchdog, or health attestation. Staging and commit are returned state values; no slot is written or activated.

## Out of scope

- Secure boot, bootloader controls, firmware installation, device communication, network downloads, and production OTA operations.
- TUF/Uptane compatibility, standards compliance, certification, or assurance that a production system is secure.
- Key generation, private-key custody, signing workflows, trust-anchor provisioning, or persistent state storage.
- Protection against a compromised host, Python runtime, operating system, storage device, or caller.
- A guarantee that an approved payload is safe, correct, or compatible with real hardware.

Use isolated synthetic data only. Never place real device payloads, private keys, customer data, or employer material in this repository.
