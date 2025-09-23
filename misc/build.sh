#!/bin/bash

set -e

rm -rf build dist
mkdir -p dist

COMMON_OPTS="--clean --noconfirm -F"
ICON_OPT="" #ICON_OPT="--icon=icon.ico"
PATH_SEPARATOR=":"

#DATA_OPT="--add-data data/posters${PATH_SEPARATOR}data/posters --add-data pyproject.toml${PATH_SEPARATOR}."
DATA_OPT="--add-data pyproject.toml${PATH_SEPARATOR}. --add-data .mode${PATH_SEPARATOR}."

if ! command -v python3 &> /dev/null; then
    echo "Python not found in PATH - please install via Homebrew (on Mac) or your favorite package manager."
    exit 1
fi

if ! command -v uv &> /dev/null; then
    echo "uv not found in PATH - please install it via: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
REQUIRED_VERSION="3.13"

if [ ! "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    echo "This program requires Python 3.13 or newer."
    exit 1
fi

echo 'gui' > .mode

uv run pyinstaller $COMMON_OPTS $ICON_OPT \
  --name OnePaceOrganizer-gui \
  --windowed \
  --distpath "dist" \
  --workpath build/gui \
  $DATA_OPT \
  main.py

echo 'console' > .mode

uv run pyinstaller $COMMON_OPTS $ICON_OPT \
  --name OnePaceOrganizer-cli \
  --console \
  --distpath "dist" \
  --workpath build/console \
  $DATA_OPT \
  main.py

rm -rf build
