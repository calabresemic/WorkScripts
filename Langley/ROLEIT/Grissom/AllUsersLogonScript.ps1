<#
 AllUsersLogonScript.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 #>

<# Revision History
 #11 Dec 2020 - Michael Calabrese (1468714589) - Edited error handling for unit logon scripts. Added groups to this part of the script, added all functions to this script.
#>

#Load Functions
#================================
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

Function Map-Printer($printer)
{
	Add-Printer –ConnectionName $printer
}

Function Show-Popup($WindowTitle,$Message)
{
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("$message","$windowTitle",'ok','Information')
}

Function Show-Powerpoint($filepath)
{
if(Test-Path $filepath){
    Invoke-Item $filepath
    }
}

Function Set-Background($image,$attempts)
{
#Highly recommend using a BMP image.Tested fine with only requiring 5 updates of the user system params. If you experience issues add a number for the $attemps variable when calling the function.
if($attempts -eq $null){$attempts=5}
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d $image /f
for ($i=0; $i -le $attempts; $i++)
    {
    RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters, 1, true
    }
}

Function Create-Shortcut($name,$target,$icon)
{

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$([Environment]::GetFolderPath("Desktop"))\$name")
$Shortcut.TargetPath =$target
if($icon -ne $null){$Shortcut.IconLocation = $icon}
$Shortcut.Save()
}

Function Set-Favorites($Name,$URL,$Location)
{
    $IEFav = [Environment]::GetFolderPath('Favorites','None')
    $WShShell = New-Object -comObject WScript.Shell
    $IEFav = Join-Path -Path $IEFav -ChildPath $Location
    If(!(Test-Path $IEFav))
    {
        New-Item -Path $IEFav -ItemType "Directory" | Out-Null
    }
    $FullPath = Join-Path -Path $IEFav -ChildPath "$($Name).url"
    $Shortcut = $WshShell.CreateShortcut($FullPath)
    $Shortcut.TargetPath = $URL
    $Shortcut.Save()
}

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

$adobjComputer = ([adsisearcher]"Samaccountname=$($env:COMPUTERNAME)$").findone()
$adobjComputer.Properties.distinguishedname
If ($objComputer.DistinguishedName -match 'Virtual Computers'){$isvirtual=$true}
else{$isvirtual=$false}

#Use this section for all base users
#================================

$workingdir=$PSScriptRoot
#$workingdir="\\area52.afnoapps.usaf.mil\grissom_afb\Logon_Scripts"
$userdesktop=[Environment]::GetFolderPath("Desktop")

$McAfeeUpdate = "$workingdir\BaseScript\McAfeeUpdate\McAfeeUpdate.vbs"
$LogUserComputer = "$workingdir\BaseScript\Custom\Log-User-Computer.vbs"
$LogCompUpdates = "$workingdir\BaseScript\Custom\Log-Comp-Updates.vbs"
$MapScanDrive = "$workingdir\BaseScript\custom\MapScanDrive.ps1"

# Network Dashboard Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$UserDesktop\Network Dashboard.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Nop -Executionpolicy bypass ""$workingdir\AllUsersLogonScript.ps1"""
$shortcut.IconLocation = "c:\windows\system32\shell32.dll,21"
$Shortcut.Save()

# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$workingdir\BaseScript\Icons\tier0_logo.ico" -target 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx'

# WingmanToolkit Shortcut
Create-Shortcut -Name 'Wingman Toolkit.lnk' -Icon "$workingdir\BaseScript\Icons\WingmanToolkit.ico" -target 'http://afrc.wingmantoolkit.org'

# Grissom IPTV Shortcut
Create-Shortcut -Name 'Grissom IPTV.lnk' -Icon 'C:\Program Files\Internet Explorer\iexplore.exe' -target 'https://afrciptv.eim.us.af.mil'

###########################################
########  Setting Drive Mappings  #########
###########################################

#HomeDrives
#$HomeDrivePath = Get-HomeDirectory $currentUser
#if (Test-Path $HomeDrivePath) {
    NET USE h: /d /Y
 #   NET USE h: $HomeDrivePath /Persistent:Yes
#}

If("GUS_DOMAIN USERS" -in $groups){
    Map-NetworkDrive W "\\CTGC-FS-001\434 WG_SHARE"
    Map-NetworkDrive V "\\CTGC-FS-002\GRISSOM INFO"
    Map-NetworkDrive U "\\CTGC-FS-001\gusfs01_data"
    Map-NetworkDrive r "\\CTGC-FS-002\gusfs02_data"
}

If("GUS_TEMS" -in $groups){
    Map-NetworkDrive T "\\CTGC-FS-001\434 MSG\SVS"
}

If("GUS_PA STAFF" -in $groups){
    Map-NetworkDrive P "\\CTGC-FS-001\434 ARW\PA\PA STAFF"
}

If(("GUS_FM USERS" -in $groups) -or ("GUS_FM ADMIN" -in $groups)){
    Map-NetworkDrive Q "\\CTGC-FS-001\434 ARW\FM\JESSE'S CORNER"
}

If("GUS_MDS USERS GROUP" -in $groups){
    Map-NetworkDrive Q "\\CTGC-FS-001\434 ARW\AMDS"
}

If(("GUS_FD MANAGERS" -in $groups) -or ("GUS_FD USERS" -in $groups)){
    Map-NetworkDrive O "\\CTGC-FS-002\FIRE DEPARTMENT"
}

If("GUS_BOOM OPERATORS" -in $groups){
	Map-NetworkDrive K "\\CTGC-FS-001\434 OG\DOT\BOOM - FORM F"
}

If("GUS_MXG Qanttas Users" -in $groups){
	Map-NetworkDrive K "\\CTGC-FS-001\434 MXG\QA\Qanttas\Qanttas"
}

If("GUS_CEV MANAGERS" -in $groups){
    Map-NetworkDrive N "\\CTGC-FS-002\CEV"
}

# AF-OSI DRIVE MAPPINGS 
#
If("GLS_434 OSI Members(M)" -in $groups){
    Map-NetworkDrive I "\\hqcuina02.area52.afnoapps.usaf.mil\public"
	Map-NetworkDrive W "\\CTGC-FS-001\434 WG_SHARE"
	Map-NetworkDrive V "\\CTGC-FS-002\GRISSOM INFO"
	Map-NetworkDrive U "\\CTGC-FS-001\gusfs01_data"
	Map-NetworkDrive R "\\CTGC-FS-002\gusfs02_data"
} 	
#
#
If("AFOSI FIR 1 HQ" -in $groups){
    Map-NetworkDrive P "\\Reg1fps\public2"
    Map-NetworkDrive X "\\REG1FPS\CVX"
}

If("AFOSI FIS 10 (Security)" -in $groups){
    Map-NetworkDrive K "\\d10fisfpsn.area52.afnoapps.usaf.mil\erk"
    Map-NetworkDrive L "\\d10fisfpsn.area52.afnoapps.usaf.mil\public"
    Map-NetworkDrive M "\\d10fisfpsn.area52.afnoapps.usaf.mil\training"
    Map-NetworkDrive N "\\d10fisafps.area52.afnoapps.usaf.mil\public"
    Map-NetworkDrive O "\\d10fisafps.area52.afnoapps.usaf.mil\training"
    Map-NetworkDrive P "\\d10fisafps.area52.afnoapps.usaf.mil\public"
    Map-NetworkDrive Q "\\d10fisafps.area52.afnoapps.usaf.mil\erk"
    Map-NetworkDrive R "\\d10fisafps.area52.afnoapps.usaf.mil\serf"	
}

If("AFOSI PJ Det 2 (Security)" -in $groups){	
    Map-NetworkDrive K "\\r7sbufps01\public"
    Map-NetworkDrive P "\\pjsbu002fps\public"
}

If(("GRISSOM HELP DESK OPERATORS" -in $groups) -or ("GUS_NCC TECHNICIANS" -in $groups) -or ("GUS_NCC ADMINS" -in $groups)){
    Map-NetworkDrive N "\\ctgc-fs-001\NCC"
    copy "N:\NCC Documentation\InfoCenter\Source\CS InfoCenter.*" $userdesktop
}

If(("GUS_SC Software Managers" -in $groups) -or ("GUS_SC Software Users" -in $groups)){
    Map-NetworkDrive Z "\\CTGC-FS-001\434 msg\cs\cfp\software"
}

###########################################
###########  Power Management  ############
###########################################

#These set the workstation to never go to sleep and instead turn off the display
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0

###########################################
#########  Run External Scripts  ##########
###########################################

#VBS Scripts
#cscript.exe $remap_printer
#cscript.exe $SecondaryHomePages
cscript.exe $McAfeeUpdate
cscript.exe $LogUserComputer
cscript.exe $LogCompUpdates
#. $hp640
.  $MapScanDrive
Start-Process powershell "$workingdir\Network-Dashboard\Get-Dashboard.ps1"

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================

#GROUP MEMBERSHIP SPECIFIC ACTIONS
#================================
# Add more groups by copying the information below
# Replace Groupname with security group name to target specific users
# Two options below for filtering in or out of a group

#If("Groupname" -in $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}

#If("Groupname" -notin $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}


#ERROR HANDLING FOR UNIT SCRIPTS
#================================
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