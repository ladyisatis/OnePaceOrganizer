#!/usr/bin/env bash

set -e
set -u

if ! command -v python3 &> /dev/null; then
    echo "Python not found in PATH - please install via Homebrew (on Mac) or your favorite package manager."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
REQUIRED_VERSION="3.13"

if [ ! "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    echo "This program requires Python 3.13 or newer."
    exit 1
fi

if [ ! -d "venv" ]; then
    python3 -m venv venv
    . venv/bin/activate
    python -m pip install -U pip setuptools
    python -m pip install poetry
    poetry install --no-interaction --no-root
    deactivate
fi

. venv/bin/activate

if [[ "${1:-gui}" == "console" ]]; then
    python src/main.py
else
    python src/gui.py
fi

deactivate
