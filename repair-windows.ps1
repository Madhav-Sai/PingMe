$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source = Join-Path $Root 'pingme.py'

if (-not (Test-Path -LiteralPath $Source)) {
    throw "pingme.py was not found beside repair-windows.ps1"
}

$Candidates = @()
$PythonOnPath = Get-Command python -ErrorAction SilentlyContinue
if ($PythonOnPath) { $Candidates += ,@($PythonOnPath.Source) }
$PyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($PyLauncher) { $Candidates += ,@($PyLauncher.Source, '-3') }
$LocalPythonRoot = Join-Path $env:LOCALAPPDATA 'Programs\Python'
if (Test-Path -LiteralPath $LocalPythonRoot) {
    Get-ChildItem -LiteralPath $LocalPythonRoot -Directory -Filter 'Python*' |
        Sort-Object Name -Descending |
        ForEach-Object {
            $Executable = Join-Path $_.FullName 'python.exe'
            if (Test-Path -LiteralPath $Executable) { $Candidates += ,@($Executable) }
        }
}

$PythonCommand = $null
$Scripts = $null
foreach ($Candidate in $Candidates) {
    $Executable = $Candidate[0]
    $InterpreterArgs = @($Candidate | Select-Object -Skip 1)
    try {
        $CandidateScripts = & $Executable @InterpreterArgs -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))" 2>$null
        if ($LASTEXITCODE -eq 0 -and $CandidateScripts) {
            $PythonCommand = $Candidate
            $Scripts = $CandidateScripts
            break
        }
    } catch {
        continue
    }
}

if (-not $PythonCommand) {
    throw 'No working Python 3 interpreter was found.'
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

$ExpectedVersion = Select-String -LiteralPath $Source -Pattern '^VERSION\s*=\s*["'']([^"'']+)' |
    ForEach-Object { $_.Matches[0].Groups[1].Value } |
    Select-Object -First 1
$Version = & $Launcher --version
if (-not $ExpectedVersion -or $LASTEXITCODE -ne 0 -or $Version -notmatch [regex]::Escape($ExpectedVersion)) {
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
