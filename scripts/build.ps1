$BuildDir = "dist"
$CommonOptions = "--clean --noconfirm -F" # --icon=icon.ico

try {
    $pythonVersion = & python --version 2>$null
} catch {
    Write-Host "Python not found in PATH, please install via running the following command"
    Write-Host "in Administrator Mode in PowerShell: winget install Python.Python.3.13 -e"
    exit 1
}

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
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-gui" --windowed --distpath "$BuildDir" --workpath "build/gui" --add-data "pyproject.toml:." --add-data ".mode:." "src/main.py"

Set-Content -Path ".\.mode" -Value "console"
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-cli" --console --distpath "$BuildDir" --workpath "build/console" --add-data "pyproject.toml:." --add-data ".mode:." "src/main.py"

if (Test-Path build) { Remove-Item build -Recurse -Force }
