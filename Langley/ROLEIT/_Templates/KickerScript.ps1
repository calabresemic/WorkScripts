<#
 KickerScript.ps1
 Written by SSgt Calabrese, 83 NOS
 Implimented by MTO 2020-336-004, NIPRNet Base Login Script Best Practices
 #>

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$l = $Adobj.properties.l.replace(" ","_")
$o = $Adobj.properties.o.replace(" ","_")
$AllUsersLogonScript = "\\area52.afnoapps.usaf.mil\$l\Logon_Scripts\AllUsersLogonScript.ps1"
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

#================================
Powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $AllUsersLogonScript
Powershell.exe -NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $unitScript