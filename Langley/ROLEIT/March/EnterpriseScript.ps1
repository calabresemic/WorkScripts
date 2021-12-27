#get current directoy
$scriptpath = $MyInvocation.MyCommand.Path
$currentdir = Split-Path $scriptpath

$BaseScirptLocation = $currentdir + '\BaseScript\BaseScript.ps1'
$NetworkDashboard = $currentdir + '\Network-Dashboard\Get-Dashboard.ps1'

#$wshell = New-Object -ComObject Wscript.Shell
#$wshell.Popup("Operation Completed",0,"Done",0x1)

# Launch Base Script
. $BaseScirptLocation

# Launch Network Dashboard
. $NetworkDashboard