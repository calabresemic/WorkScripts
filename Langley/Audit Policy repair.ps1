#Created by Michael Calabrese (1468714589)

$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
    $scriptpath = "'" + $MyInvocation.MyCommand.Definition + "'"
    Start-Process -FilePath PowerShell.exe -Verb runAs -ArgumentList "& $scriptPath"
    exit
    }

if((Get-ItemProperty 'C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv').IsReadOnly){
    "C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv was set to read only"
    Set-ItemProperty 'C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv' -Name IsReadOnly -Value $false
    "Read only has been removed"}
else{"C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv was set correctly"}

if((Get-ItemProperty C:\Windows\security\audit\audit.csv).IsReadOnly){
    "`nC:\Windows\security\audit\audit.csv was set to read only"
    Set-ItemProperty C:\Windows\security\audit\audit.csv -Name IsReadOnly -Value $false
    "Read only has been removed"}
else{"`nC:\Windows\security\audit\audit.csv was set correctly"}

"`nUpdating Group Policy"
gpupdate /force | Out-Null

"`nGenerating GPResult to desktop... please wait"
gpresult /h $env:USERPROFILE\Desktop\gpresult.html
$gpresult=Get-Content $env:USERPROFILE\Desktop\gpresult.html

"`nChecking results for source of Audit Policy settings"
if(($gpresult -match "System Integrity").replace("<td>",";").split(";")[3].split("<")[0] -match "Local Group Policy"){"Script failed to repair Audit Policy"}
elseif(($gpresult -match "System Integrity").replace("<td>",";").split(";")[3].split("<")[0] -notmatch "GPO-OU-C"){"Slightly more aggressive steps are required"

"Removing the audit.csv files"
Remove-Item 'C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv' -Force
Remove-Item C:\Windows\security\audit\audit.csv -Force

"Clearing the audit policy"
auditpol /clear

"Please restart the computer"
}
else{"Script successfully repaired the Audit Policy"}

pause