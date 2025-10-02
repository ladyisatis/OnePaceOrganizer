#!/usr/bin/env bash

set -e

rm -rf build dist
mkdir -p dist

if ! command -v uv &> /dev/null; then
    echo "uv not found in PATH - please install it via: https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi

if [[ -z "${BUILD_OS}" ]]; then
  case "$(uname -s)" in
      Darwin*)
          BUILD_OS="macos"
          ;;
      CYGWIN*|MINGW*|MSYS*|NT*)
          BUILD_OS="windows"
          ;;
      *)
          BUILD_OS="linux"
          ;;
  esac
fi


if [[ -z "${ICON_FILE}" ]]; then
  if [ "${BUILD_OS}" == "windows" ]; then
    ICON_FILE="misc/icon.ico"
  elif [ "${BUILD_OS}" == "macos" ]; then
    ICON_FILE="misc/icon.icns"
  else
    ICON_FILE="misc/icon.png"
  fi
fi

echo 'gui' > .mode

uv run pyinstaller --clean --noconfirm -F \
  --name OnePaceOrganizer-gui \
  --icon "$ICON_FILE" \
  --windowed \
  --hidden-import=ssl --hidden-import=_ssl \
  --distpath "dist" \
  --exclude-module "prompt_toolkit" \
  --workpath build/gui \
  --add-data "pyproject.toml:." \
  --add-data ".mode:." \
  $EXTRA_OPTS \
  main.py

echo 'console' > .mode

uv run pyinstaller --clean --noconfirm -F \
  --name OnePaceOrganizer-cli \
  --icon "$ICON_FILE" \
  --console \
  --hidden-import=ssl --hidden-import=_ssl \
  --distpath "dist" \
  --exclude-module "qasync" \
  --exclude-module "PySide6" \
  --workpath build/console \
  --add-data "pyproject.toml:." \
  --add-data ".mode:." \
  $EXTRA_OPTS \
  main.py

rm -rf build

if [ ! -d "metadata" ]; then
  ZIP_URL="https://github.com/ladyisatis/one-pace-metadata/archive/refs/heads/main.zip"
  ZIP_FILE="metadata.zip"

  if command -v wget >/dev/null 2>&1; then
      wget -O "$ZIP_FILE" "$ZIP_URL"
  elif command -v curl >/dev/null 2>&1; then
      curl -L -o "$ZIP_FILE" "$ZIP_URL"
  else
      echo "Exiting: wget and curl not found" >&2
      exit 1
  fi

  unzip "$ZIP_FILE"
  rm "$ZIP_FILE"

  mv one-pace-metadata-main metadata

  find metadata -maxdepth 1 -type f \
      ! -name "data.json" \
      ! -name "arcs.yml" \
      ! -name "tvshow.yml" \
      -exec rm -f {} +;

  find metadata -mindepth 1 -maxdepth 1 -type d \
      ! -name "episodes" \
      ! -name "posters" \
      -exec rm -rf {} +;
fi

[ ! -f "posters.zip" ] && zip -r posters.zip posters
[ ! -d "temp_zip" ] && mkdir -p temp_zip
[ ! -d "temp_zip/metadata" ] && cp -r metadata temp_zip/metadata
[ ! -d "temp_zip/posters" ] && cp -r posters temp_zip/posters

if [ "$BUILD_OS" == "windows" ]; then
  cp dist/OnePaceOrganizer-cli.exe temp_zip/
  cp dist/OnePaceOrganizer-gui.exe temp_zip/

  pushd temp_zip && zip -r ../OnePaceOrganizer-win-x64.zip . && popd
  rm -rf temp_zip

  mv dist/OnePaceOrganizer-cli.exe OnePaceOrganizer-cli-win-x64.exe
  mv dist/OnePaceOrganizer-gui.exe OnePaceOrganizer-gui-win-x64.exe

elif [ "$BUILD_OS" == "macos" ]; then
  mkdir -p dist/OnePaceOrganizer.app/Contents/MacOS
  cp dist/OnePaceOrganizer-gui dist/OnePaceOrganizer.app/Contents/MacOS/OnePaceOrganizer

  cp dist/OnePaceOrganizer-gui temp_zip/OnePaceOrganizer-gui-macos-arm64
  cp dist/OnePaceOrganizer-cli temp_zip/OnePaceOrganizer-cli-macos-arm64
  cp -r dist/OnePaceOrganizer.app temp_zip/

  pushd temp_zip && zip -r ../OnePaceOrganizer-macos-arm64.zip . && popd
  rm -rf temp_zip

  mv dist/OnePaceOrganizer.app OnePaceOrganizer-gui-macos-arm64.app
  mv dist/OnePaceOrganizer-gui OnePaceOrganizer-gui-macos-arm64
  mv dist/OnePaceOrganizer-cli OnePaceOrganizer-cli-macos-arm64

else
  cp dist/OnePaceOrganizer-gui temp_zip/OnePaceOrganizer-gui-linux-x64
  cp dist/OnePaceOrganizer-cli temp_zip/OnePaceOrganizer-cli-linux-x64

  pushd temp_zip && zip -r ../OnePaceOrganizer-linux-x64.zip . && popd
  rm -rf temp_zip

  mv dist/OnePaceOrganizer-cli OnePaceOrganizer-cli-linux-x64
  mv dist/OnePaceOrganizer-gui OnePaceOrganizer-gui-linux-x64

fi
