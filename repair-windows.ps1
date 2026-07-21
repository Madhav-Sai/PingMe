$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path $Root 'pingme.py'

if (-not (Test-Path -LiteralPath $Source)) {
    throw "pingme.py was not found beside repair-windows.ps1"
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    $Python = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $Python) {
    throw 'Python was not found in PATH.'
}

if ($Python.Name -eq 'py.exe' -or $Python.Name -eq 'py') {
    $Scripts = & $Python.Source -3 -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))"
    $PythonCommand = @($Python.Source, '-3')
} else {
    $Scripts = & $Python.Source -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))"
    $PythonCommand = @($Python.Source)
}

$Scripts = $Scripts.Trim()
if (-not $Scripts) {
    throw 'Unable to determine the Python user Scripts directory.'
}

New-Item -ItemType Directory -Path $Scripts -Force | Out-Null
$InstalledScript = Join-Path $Scripts 'pingme.py'
$Launcher = Join-Path $Scripts 'pingme.cmd'

Remove-Item -LiteralPath (Join-Path $Scripts 'pingme.bat') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Scripts 'pingme.exe') -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $Source -Destination $InstalledScript -Force

$PythonExe = $PythonCommand[0]
$Extra = if ($PythonCommand.Count -gt 1) { $PythonCommand[1] + ' ' } else { '' }
$CmdContent = "@echo off`r`n`"$PythonExe`" $Extra`"$InstalledScript`" %*`r`n"
Set-Content -LiteralPath $Launcher -Value $CmdContent -Encoding Ascii -NoNewline

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$Entries = @()
if ($UserPath) {
    $Entries = $UserPath -split ';' | Where-Object { $_ -and ($_ -ne $Scripts) }
}
[Environment]::SetEnvironmentVariable('Path', (($Scripts) + ';' + ($Entries -join ';')).TrimEnd(';'), 'User')
$env:Path = "$Scripts;$env:Path"

Remove-Item Alias:pingme -ErrorAction SilentlyContinue
Remove-Item Function:pingme -ErrorAction SilentlyContinue

$Version = & $Launcher --version
if ($LASTEXITCODE -ne 0 -or $Version -notmatch '3\.0\.4') {
    throw "PingMe verification failed: $Version"
}

$FeatureCheck = Select-String -LiteralPath $InstalledScript -Pattern 'FILE SCAN STATUS' -Quiet
if (-not $FeatureCheck) {
    throw 'The installed script does not contain the file status table.'
}

Write-Host "[+] Installed: $InstalledScript" -ForegroundColor Green
Write-Host "[+] Launcher:  $Launcher" -ForegroundColor Green
Write-Host "[+] Verified:  $Version" -ForegroundColor Green
Write-Host "[+] Run now:   pingme -f .\host.txt" -ForegroundColor Cyan
