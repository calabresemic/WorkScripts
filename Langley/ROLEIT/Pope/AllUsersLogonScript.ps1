<#
 PetersonLoginKicker.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 Version 1
 Modified for Pope AFB 12/10/2020 by SSgt Calabrese (1468714589)
#>

#Load Functions
Function Show-Popup($WindowTitle,$Message)
{
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("$message","$windowTitle",'ok','Error')
}

#########  Run External Scripts  ##########

Powershell.exe -executionpolicy bypass -file \\tmkh-hc-001v\LogonScripts\Network-Dashboard\Get-Dashboard.ps1

###########################################

########  Create Desktop Shortcuts  #######

# We Care Resource Guide

#Test for OneDrive
if(Test-Path $home\Desktop){$dir="$home\Desktop"}
else{$dir="$home\OneDrive - United States Air Force\Desktop"}

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$dir\Resource Guide.lnk")
$Shortcut.TargetPath ="https://www.pope.af.mil/About-Us/WE-CARE-Resource-Guide/"
$Shortcut.IconLocation = "\\52tmkh-fs-004\43 AMOG\Assets\WeCare1.ico"
$Shortcut.Save()

###########################################

###########  Power Management  ############ maybe revisit this

powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0

###########################################

#########  Launch AMC Launchpad  ##########

start https://eim2.amc.af.mil/org/PopeAAF/Launch%20Pad/default.aspx

###########################################

$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

If(test-path $unitscript)
{
    Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file $unitScript
}
Else
{
If($l -eq ""){Write-EventLog -EventId 1130 -LogName Application -Message "User account missing l `(city`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"}
if($o -eq ""){Write-EventLog -EventId 1130 -LogName Application -Message "User account missing o `(organization`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"}
If(($l -ne "") -and ($o -ne "")){Write-EventLog -EventId 1130 -LogName Application -Message "Cannot find login script $unitscript. Check that the user account is properly configured and/or that the following script path is accessible: $unitscript" -EntryType Error -source "Windows Error Reporting"}
Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. City `n 2. Organization/Unit" 
}