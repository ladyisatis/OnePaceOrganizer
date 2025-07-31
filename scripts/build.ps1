$BuildDir = "dist"
$CommonOptions = "--clean --noconfirm -F" # --icon=icon.ico

try {
    $pythonVersion = & python --version 2>$null
} catch {
    Write-Host "Python not found in PATH, please install via running the following command"
    Write-Host "in Administrator Mode in PowerShell: winget install Python.Python.3.13 -e"
    exit 1
}

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path "$BuildDir" -Force | Out-Null

if (-Not (Test-Path venv)) {
    & python -m venv venv
    & .\venv\Scripts\Activate.ps1
    & .\venv\Scripts\python.exe -m pip install --upgrade pip setuptools
    pip install poetry
    poetry install --no-interaction --no-root
    deactivate
}

& .\venv\Scripts\Activate.ps1

poetry run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-gui" --windowed --distpath "$BuildDir" --workpath "build/gui" --add-data "pyproject.toml:." "src/gui.py"
poetry run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-cli" --console --distpath "$BuildDir" --workpath "build/cli" --add-data "pyproject.toml:." "src/main.py"

deactivate

if (Test-Path build) { Remove-Item build -Recurse -Force }
