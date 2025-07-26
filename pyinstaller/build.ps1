$BuildDir = "dist"
$CommonOptions = "--clean --noconfirm"
$IconOption = ""  # $IconOption = "--icon=icon.ico"
$Platform = "windows"
$PathSep = ";"

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
New-Item -ItemType Directory -Path "$BuildDir" -Force | Out-Null

$DataOptions = @(
    "--add-data `"data/posters${PathSep}data/posters`"",
    "--add-data `"pyproject.toml${PathSep}pyproject.toml`""
)

$DataOptionString = $DataOptions -join " "

poetry run pyinstaller $CommonOptions $IconOption `
    --name "OnePaceOrganizer-gui" `
    --windowed `
    --distpath "$BuildDir" `
    --workpath "build/gui" `
    $DataOptionString `
    "src/gui.py"

poetry run pyinstaller $CommonOptions $IconOption `
    --name "OnePaceOrganizer-cli" `
    --console `
    --distpath "$BuildDir" `
    --workpath "build/cli" `
    $DataOptionString `
    "src/main.py"

if (Test-Path build) { Remove-Item build -Recurse -Force }
