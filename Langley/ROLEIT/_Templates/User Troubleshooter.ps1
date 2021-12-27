$SamAccountName=Read-Host "Users EDI with letter"
$user=Get-ADUser $SamAccountName -Properties l,o
$l = $user.l.replace(" ","_")
$o = $user.o.replace(" ","_")
$AllUsersLogonScript = "\\area52.afnoapps.usaf.mil\$l\Logon_Scripts\AllUsersLogonScript.ps1"
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

if(Test-Path $AllUsersLogonScript){ "The all users script is located at $AllUsersLogonScript" } else { "The path $AllUsersLogonScript doesn't exist" }

if(Test-Path $unitScript){ "The unit script is located at $unitScript" } else { "The path $unitScript doesn't exist" }