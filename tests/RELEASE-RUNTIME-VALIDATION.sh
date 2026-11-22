#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 -m compileall -q hookscope
python3 -m unittest discover -s tests -q
python3 -m hookscope --version
python3 -m hookscope wheel examples/synthetic-wheel/demo-1.0-py3-none-any.whl --python-version 3.15 --format json --strict >/dev/null
python3 -m hookscope scan --root examples --format sarif >/dev/null
