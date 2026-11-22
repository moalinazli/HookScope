# Contributing

Reproduce any reported parsing discrepancy using a minimal, non-malicious fixture and include the Python version, operating system, exact command, expected result and actual result.

Run `python -m unittest discover -s tests -v` before a pull request. New parsers should remain offline and must not import or execute inspected code. When changing output structure, update `schema_version` and the tests.

Do not contribute real credentials, live malicious payloads or proprietary third-party code. Preserve upstream licenses and citations for any reused material.
