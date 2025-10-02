try {
    $uvVersion = & uv --version 2>$null
} catch {
    Write-Host "uv not found in PATH, please see the following page to install it:"
    Write-Host "https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
}

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path dist) { Remove-Item dist -Recurse -Force }
if (Test-Path metadata) { Remove-Item metadata -Recurse -Force }
New-Item -ItemType Directory -Path "dist" -Force | Out-Null

Set-Content -Path ".\.mode" -Value "gui"
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-gui" --icon "$env:ICON_FILE" --windowed --distpath "dist" --hidden-import=ssl --hidden-import=_ssl --exclude-module "prompt_toolkit" --workpath "build/gui" --add-data "pyproject.toml:." --add-data ".mode:." $env:EXTRA_OPTS "main.py"

Set-Content -Path ".\.mode" -Value "console"
uv run pyinstaller --clean --noconfirm -F --name "OnePaceOrganizer-cli" --icon "$env:ICON_FILE" --console --distpath "dist" --hidden-import=ssl --hidden-import=_ssl --exclude-module "qasync" --exclude-module "PySide6" --workpath "build/console" --add-data "pyproject.toml:." --add-data ".mode:." $env:EXTRA_OPTS "main.py"

if (Test-Path build) { Remove-Item build -Recurse -Force }

Invoke-WebRequest -Uri "https://github.com/ladyisatis/one-pace-metadata/archive/refs/heads/main.zip" -OutFile "metadata.zip"
Expand-Archive -Path "metadata.zip" -DestinationPath "."
Remove-Item "metadata.zip"

Rename-Item "one-pace-metadata-main" "metadata"

Get-ChildItem -Path "metadata" -File | Where-Object {
    $_.Name -notin @("data.json", "arcs.yml", "tvshow.yml")
} | Remove-Item -Force

Get-ChildItem -Path "metadata" -Directory | Where-Object {
    $_.Name -notin @("episodes", "posters")
} | Remove-Item -Recurse -Force

Compress-Archive -Path posters -DestinationPath posters.zip

New-Item -ItemType Directory -Path temp_zip
Copy-Item dist\OnePaceOrganizer-cli.exe -Destination temp_zip
Copy-Item dist\OnePaceOrganizer-gui.exe -Destination temp_zip

Copy-Item -Recurse metadata -Destination temp_zip\metadata
Copy-Item -Recurse posters -Destination temp_zip\posters

Compress-Archive -Path temp_zip\* -DestinationPath OnePaceOrganizer-win-x64.zip

Remove-Item -Recurse -Force temp_zip
Rename-Item dist\OnePaceOrganizer-cli.exe OnePaceOrganizer-cli-win-x64.exe
Rename-Item dist\OnePaceOrganizer-gui.exe OnePaceOrganizer-gui-win-x64.exe
