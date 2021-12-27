<#
 PetersonLoginKicker.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 Version 2
 #Change Log
 #11 Dec 2020 - SSgt Calabrese - Edited error handling for unit logon scripts
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

Function Show-Powerpoint($filepath)
{
if(Test-Path $filepath){
    $application = New-Object -ComObject powerpoint.application
    $presentation = $application.Presentations.open($filepath)
    $application.visible = "msoTrue"
    $presentation.SlideShowSettings.Run()
    }
}

$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

If("97AMW_LOGONSCRIPTEXEMPT" -notin $groups)
{
####Map Base Drives
Map-NetworkDrive R "\\aggn-fs-001p\ERM"
Map-NetworkDrive S "\\aggn-fs-001p\AAFB Shared"
#########################

#####Splashpage Powerpoint
Show-Powerpoint "\\area52.afnoapps.usaf.mil\altus_afb\Logon_Scripts\Slides.ppsx"
#########################

#####AETC Theme
PowerShell.exe -ExecutionPolicy Bypass -File \\area52.afnoapps.usaf.mil\altus_afb\Logon_Scripts\Source_Files\Powershell\SetTheme.ps1
#########################
}

If(($l -eq "") -and ($o -eq "")){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing l `(city`) attribute and o `(organization`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. City `n 2. Organization/Unit"}
Elseif($l -eq ""){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing l `(city`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. City"}
Elseif($o -eq ""){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing o `(organization`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. Organization/Unit"
    }
ElseIf(test-path $unitscript)
{
    #If all attributes are set and there is a unit script, run it
    Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file $unitScript
}
Else{Exit}