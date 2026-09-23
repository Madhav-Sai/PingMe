<#
.SYNOPSIS
  Registers a Windows scheduled task that runs a PingMe check on an interval.
.EXAMPLE
  .\Register-PingMeTask.ps1 -Targets C:\pingme\targets.txt -Minutes 15 -Notify "https://hooks.slack.com/services/XXX"
#>
param(
    [Parameter(Mandatory = $true)][string]$Targets,
    [int]$Minutes = 15,
    [string]$Notify = "",
    [string]$TaskName = "PingMe check"
)

$ErrorActionPreference = "Stop"
$pingme = (Get-Command pingme -ErrorAction SilentlyContinue).Source
if (-not $pingme) { throw "pingme is not on PATH. Run 'python install.py' first." }
if (-not (Test-Path $Targets)) { throw "Target file not found: $Targets" }

$workDir = Split-Path -Parent (Resolve-Path $Targets)
$arguments = "`"$((Resolve-Path $Targets).Path)`" --changes --quiet --exit-zero --html `"$workDir\pingme-report.html`""
if ($Notify) { $arguments += " --notify `"$Notify`"" }

$action = New-ScheduledTaskAction -Execute $pingme -Argument $arguments -WorkingDirectory $workDir
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Write-Host "Registered '$TaskName': every $Minutes minutes, reports in $workDir"
