#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
ruff check app tests
mypy app
