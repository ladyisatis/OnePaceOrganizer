param (
    [string]$mode = "gui"
)

$ErrorActionPreference = "Stop"

try {
    $pythonVersion = & python --version 2>$null
} catch {
    Write-Host "Python not found in PATH, please install via running the following command"
    Write-Host "in Administrator Mode in PowerShell: winget install Python.Python.3.13 -e"
    exit 1
}

if (-Not (Test-Path venv)) {
    & python -m venv venv
    & .\venv\Scripts\Activate.ps1
    & .\venv\Scripts\python.exe -m pip install --upgrade pip setuptools
    pip install poetry
    poetry install --no-interaction --no-root
    deactivate
}

& .\venv\Scripts\Activate.ps1

if ($mode -eq "console") {
    python src/main.py
} else {
    python src/gui.py
}

deactivate
