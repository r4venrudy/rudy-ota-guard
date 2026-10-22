# Contributing

Create a local environment with Python 3.11 or later, install with `python -m pip install -e .`, and run `python -m unittest discover -s tests -v`.

Security-sensitive changes need an adversarial regression fixture that fails before the fix. Keep all test releases and payloads synthetic. Do not attach customer firmware, private keys, device identifiers, logs or employer data to issues or pull requests.

This initial portfolio implementation was developed with AI assistance and human-directed requirements. Generated changes must be reviewed and exercised with actual tests. Build/CI results and limitations are reported separately from feature intentions.

The project format is deliberately small and is not a TUF or Uptane implementation. Interoperability, hardware trust, protected monotonic counters, production key custody, live installation and verified boot are out of scope.
