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

OS_ARCH="$(uname -m)"

echo 'gui' > .mode

uv run pyinstaller --clean --noconfirm -F \
  --name="OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}" \
  --icon="$ICON_FILE" \
  --debug=all \
  --windowed \
  --hidden-import=ssl --hidden-import=_ssl --hidden-import=httpx \
  --distpath "dist" \
  --exclude-module "prompt_toolkit" \
  --workpath build/gui \
  --add-data "pyproject.toml:." \
  --add-data ".mode:." \
  --add-data "$ICON_FILE:." \
  $EXTRA_OPTS \
  main.py

echo 'console' > .mode

uv run pyinstaller --clean --noconfirm -F \
  --name="OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}" \
  --icon="$ICON_FILE" \
  --debug=all \
  --console \
  --hidden-import=ssl --hidden-import=_ssl --hidden-import=httpx \
  --distpath "dist" \
  --exclude-module "qasync" \
  --exclude-module "PySide6" \
  --workpath build/console \
  --add-data "pyproject.toml:." \
  --add-data ".mode:." \
  --add-data "$ICON_FILE:." \
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

[ ! -d "temp_zip" ] && mkdir -p temp_zip
[ ! -d "temp_zip/metadata" ] && cp -r metadata temp_zip/metadata
[ ! -d "temp_zip/posters" ] && cp -r posters temp_zip/posters

if [ "$BUILD_OS" == "windows" ]; then
  cp "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.exe" "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}.exe" temp_zip/

  pwsh -Command "Compress-Archive -Path 'temp_zip\\*' -DestinationPath 'OnePaceOrganizer-${BUILD_OS}-${OS_ARCH}.zip'"
  rm -rf temp_zip

  mv "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.exe" "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}.exe" .

elif [ "$BUILD_OS" == "macos" ]; then
  brew install create-dmg

  [ -d "build/dmg" ] && rm -rf build/dmg
  [ ! -d "build/dmg" ] && mkdir -p build/dmg
  cp -r "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.app" "build/dmg/One Pace Organizer GUI.app"

  create-dmg \
    --volname "One Pace Organizer GUI" \
    --volicon "$ICON_FILE" \
    --window-pos 200 200 \
    --window-size 600 600 \
    --icon-size 128 \
    --icon "One Pace Organizer GUI.app" 175 120 \
    --hide-extension "One Pace Organizer GUI.app" \
    --app-drop-link 425 120 \
    "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.dmg" \
    "build/dmg/"

  rm -rf build/dmg/*
  cp -r "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}" "build/dmg/OnePaceOrganizer-cli"

  create-dmg \
    --volname "One Pace Organizer CLI" \
    --volicon "$ICON_FILE" \
    --window-pos 200 200 \
    --window-size 300 300 \
    --icon-size 128 \
    --icon "OnePaceOrganizer-cli" 175 120 \
    "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}.dmg" \
    "build/dmg/"

  cp -r "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.app" "temp_zip/OnePaceOrganizer-gui.app"
  cp "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}" "temp_zip/OnePaceOrganizer-cli"

  pushd temp_zip && zip -r "../OnePaceOrganizer-${BUILD_OS}-${OS_ARCH}.zip" . && popd
  rm -rf temp_zip

  mv "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}.dmg" "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}.dmg" .

else
  [ ! -f "posters.zip" ] && zip -r posters.zip posters

  cp "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}" "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}" temp_zip/

  pushd temp_zip && zip -r "../OnePaceOrganizer-${BUILD_OS}-${OS_ARCH}.zip" . && popd
  rm -rf temp_zip

  mv "dist/OnePaceOrganizer-gui-${BUILD_OS}-${OS_ARCH}" "dist/OnePaceOrganizer-cli-${BUILD_OS}-${OS_ARCH}" .

fi
