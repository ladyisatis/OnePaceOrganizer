#!/bin/bash

set -e

rm -rf build dist
mkdir -p dist

COMMON_OPTS="--clean --noconfirm"
ICON_OPT="" #ICON_OPT="--icon=icon.ico"

case "$(uname -s)" in
    Linux*)     PLATFORM=linux; PATH_SEPARATOR=":" ;;
    Darwin*)    PLATFORM=mac; PATH_SEPARATOR=":" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM=windows; PATH_SEPARATOR=";" ;;
    *)          echo "Unsupported platform: $(uname -s)"; exit 1 ;;
esac

DATA_OPT="--add-data data/posters${PATH_SEPARATOR}data/posters --add-data pyproject.toml${PATH_SEPARATOR}pyproject.toml"

poetry run pyinstaller $COMMON_OPTS $ICON_OPT \
  --name OnePaceOrganizer-gui \
  --windowed \
  --distpath "dist" \
  --workpath build/gui \
  $DATA_OPT \
  src/gui.py

poetry run pyinstaller $COMMON_OPTS $ICON_OPT \
  --name OnePaceOrganizer-cli \
  --console \
  --distpath "dist" \
  --workpath build/cli \
  $DATA_OPT \
  src/main.py

rm -rf build
