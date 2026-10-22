# Testing and development

## Requirements

- Python 3.11 or newer
- `cryptography==50.0.2` for Ed25519

Install the local package and run the standard-library test suite:

```sh
python -m pip install .
python -m unittest discover -s tests -v
```

The tests should build independent synthetic Ed25519 fixtures. Do not check in private keys or depend on live services. The contract expects coverage for valid and invalid signatures, signer de-duplication, target binding, sequence/replay and rollback rejection, key expiry/revocation, dual-threshold root rotation, payload tampering and size mismatch, strict malformed JSON, A/B staging/abort/health-gated commit, deterministic output, and CLI exit/error behavior.

The supported local test command uses `unittest`; CI runs it on Ubuntu, Windows, and macOS with Python 3.11 and 3.13. A CI pass only demonstrates that this test suite passed in those runners. It is not a security certification or production OTA validation.

Keep new tests offline and deterministic. Include a failing adversarial fixture for each new validation rule, and confirm bad input fails closed without exposing secrets, full local paths, or tracebacks in CLI errors.
