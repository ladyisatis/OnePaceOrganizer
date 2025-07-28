#!/bin/bash

set -e

rm -rf build dist
mkdir -p dist

COMMON_OPTS="--clean --noconfirm -F"
ICON_OPT="" #ICON_OPT="--icon=icon.ico"
PATH_SEPARATOR=":"

#DATA_OPT="--add-data data/posters${PATH_SEPARATOR}data/posters --add-data pyproject.toml${PATH_SEPARATOR}."
DATA_OPT="--add-data pyproject.toml${PATH_SEPARATOR}."

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
