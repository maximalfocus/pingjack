#!/usr/bin/env bash
# The complete verification gate. Runs inside the container; the host needs no Python.
set -euo pipefail

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "== mypy =="
mypy

echo "== pytest =="
pytest -q

echo "== verification boundary green =="
