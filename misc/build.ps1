$BuildDir = "dist"
$CommonOptions = "--clean --noconfirm -F" # --icon=icon.ico

try {
    $uvVersion = & uv --version 2>$null
} catch {
    Write-Host "uv not found in PATH, please see the following page to install it:"
    Write-Host "https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
}

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path "$BuildDir" -Force | Out-Null

Set-Content -Path ".\.mode" -Value "gui"
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-gui" --windowed --distpath "$BuildDir" --exclude-module "prompt_toolkit" --workpath "build/gui" --add-data "pyproject.toml:." --add-data ".mode:." "main.py"

Set-Content -Path ".\.mode" -Value "console"
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-cli" --console --distpath "$BuildDir" --exclude-module "qasync" --exclude-module "PySide6" --workpath "build/console" --add-data "pyproject.toml:." --add-data ".mode:." "main.py"

if (Test-Path build) { Remove-Item build -Recurse -Force }
