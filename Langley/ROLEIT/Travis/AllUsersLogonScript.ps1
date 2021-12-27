<#
 PetersonLoginKicker.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 Version 1
 Modified for Travis AFB 12/10/2020 by SSgt Calabrese (1468714589)
#>

#Load Functions
Function Show-Popup($WindowTitle,$Message)
{
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("$message","$windowTitle",'ok','Error')
}

Function Map-NetworkDrive($driveletter,$path,$sharename)
{
	if($driveletter -in (get-psdrive).name)
	{
		Remove-PSDrive -name $driveletter
        net use "$($driveletter):" /DELETE
        Remove-SmbMapping "$($driveletter):" -Force -UpdateProfile -ErrorAction SilentlyContinue
		New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
        (New-Object -ComObject Shell.Application).NameSpace("$($driveletter):").Self.Name=$sharename
	}
	Else
	{
		New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
        (New-Object -ComObject Shell.Application).NameSpace("$($driveletter):").Self.Name=$sharename
	}
}

##### Local CS scripts

#Computer Log
& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\ComputerTracking\ComputerTracking.vbs"

#Java Site Exemption List
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\JavaSiteExemptions\JavaSiteExemptions.vbs" 

#Computer setting changes
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\Settings\Settings.vbs"

#Create PII Encryption Folder
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\efs_script\run_efs_script.vbs"

#Calls phishing popup
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\PhishingPopUp\popup.vbs"

#Call script to check on status of WMI, Guardian.ps1, Autoupdater.ps1 and if PS remoting is enabled
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\Automated_Patching_DB\BasicChecks.vbs"

#Call SIPR Uptime On Tuesdays and Thursdays
#& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\SIPRUptime\SIPRUptime.vbs"

#Calls Cyber Awareness Popup
& cscript /nologo "\\xdat-fs-001v\adminfs$\01 - Logon Scripts\IAPopUp\popup.vbs"

##############################

#####Base Settings

Map-NetworkDrive T "\\xdat-fs-001v\travis$" "TRAVIS"

##############################

$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $Adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

#####Base Drive Mappings 
If("Travis CSA_FSA" -in $groups)
{
Map-NetworkDrive X "\\xdat-fs-001v\adminfs$" "ADMIN"
}

If("GLS_Travis_FARM ALL" -in $groups)
{
Map-NetworkDrive O "\\xdat-fs-001v\erm_fs$\erm$" "Travis FARM"
}

##############################

#Direct to Unit Scripts
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
