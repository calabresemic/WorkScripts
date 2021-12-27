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
#CREATE SHORTCUT
#================================
# Create a shortcut on the user's desktop
# Optional icon image can be specified if necessary or desired.
# Supports OneDrive desktops

#Create-Shortcut "shortcutname.lnk" "targetlocation" "iconfile"

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

# Setting the script to ignore all errors and continue
$ErrorActionPreference = 'SilentlyContinue'

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}

$adobjComputer = ([adsisearcher]"Samaccountname=$($env:COMPUTERNAME)$").findone()
$compgroups=$adobjComputer.Properties.memberof | %{$_.split("=")[1].split(",")[0]}
If ($objComputer.DistinguishedName -match 'Virtual Computers'){$isvirtual=$true}
else{$isvirtual=$false}

#Use this section for all base users
#================================

$workingdir=$PSScriptRoot
#$workingdir="\\area52.afnoapps.usaf.mil\Pittsburgh_afb\Logon_Scripts"
$userdesktop=[Environment]::GetFolderPath("Desktop")

# External Scripts
$VPNFix                = "$workingdir\BaseScript\VPNFIX\VPNFIX.ps1"
$PrinterRemap          = "$workingdir\BaseScript\Custom\remap_printer.vbs"
$UpdateSharePaths      = "$workingdir\BaseScript\Update-SharePaths\Update-SharePaths.ps1"
$hp640	               = "$workingdir\BaseScript\Custom\hp640.ps1"
$VDIOvercommitted      = "$workingdir\BaseScript\custom\VDIOvercommitted.ps1"

#Connect PrintRelease
$Printers = gwmi win32_printer | select-object -ExpandProperty name
If ($Printers -notcontains 'PrintRelease')
{Map-Printer '\\arty-mp-001v\PrintRelease'}

###########################################
#############  Security Notice  ###########
###########################################
Show-Popup -WindowTitle 'Security Notice' -Message 'SECURITY REMINDER: REMOVE AND SECURE YOUR CAC each time line of sight is lost and always PROTECT PII!'

###########################################
########  Create Desktop Shortcuts  #######
###########################################

# Network Dashboard Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$UserDesktop\Network Dashboard.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Nop -WindowStyle Hidden -Executionpolicy bypass ""$workingdir\AllUsersLogonScript.ps1"""
$shortcut.IconLocation = "c:\windows\system32\shell32.dll,21"
$Shortcut.Save()

# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$workingdir\BaseScript\tier0_logo.ico" -target 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx'

# WingmanToolkit Shortcut
Create-Shortcut -Name 'Wingman Toolkit.lnk' -Icon "$workingdir\BaseScript\WingmanToolkit.ico" -target 'http://afrc.wingmantoolkit.org'

# ARPC User Guide # INC000024845650 2019-09-03
Create-Shortcut -Name 'ARPC User Guide.lnk' -Icon "$currentdir\Icons\HowToGuide.ico" -Target 'https://afrc.eim.us.af.mil/sites/ARPC_N3/dpx/dpxi/dpxio/CFP%20Self%20Help/ARPC%20User%20Guide.pdf?Web=1'

# Install a Printer Icon
Create-Shortcut -Name 'Install a Printer.lnk' -icon 'imageres.dll,46' -target '\\ARTY-MP-002v'

Remove-Item -Path "$UserDesktop\ConvertToPDF.vbs"
Remove-Item -Path "$UserDesktop\XFDL to PDF\ConvertToPDF.vbs" -Force
Remove-Item -Path "$UserDesktop\XFDL to PDF\Convert XFD Instructions\*" -Force
Remove-Item -Path "$UserDesktop\XFDL to PDF\Convert XFD Instructions" -Force
Remove-Item -Path "$UserDesktop\XFDL to PDF" -Force

###########################################
########  Setting Drive Mappings  #########
###########################################
#Map Scan Drive
Map-NetworkDrive S "\\Arpfs04\home" -sharename "Scanned_Documents"

Map-NetworkDrive L '\\arpfs07.AREA52.AFNOAPPS.USAF.MIL\apps'
Map-NetworkDrive X '\\arpfs07.AREA52.AFNOAPPS.USAF.MIL\milmod'
Map-NetworkDrive O '\\arpfs04.AREA52.AFNOAPPS.USAF.MIL\office'
Map-NetworkDrive H '\\arpfs06.AREA52.AFNOAPPS.USAF.MIL\Home'

If ($groups -contains 'ARPC_EDOCS') {
    Map-NetworkDrive P \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\edocs
}
 
If (($groups -contains 'ARPC_SCOH') -or ($groups -contains 'ARPC_CFP')-or ($groups -contains 'ARPC_Network')) {
    Map-NetworkDrive N \\arpfs02.AREA52.AFNOAPPS.USAF.MIL\software
}
    
If (($groups -contains 'ARPC_BarCodeReaderUsers') -or ($groups -contains 'ARPC_DAA Orders Query') -or ($groups -contains 'ARPC_DAA Supervisor List') -or ($groups -contains 'ARPC_DAA Tech List')) {
    Map-NetworkDrive G \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\DA_Orders
}

If (($groups -contains 'arpc_DPR') -or ($groups -contains 'arpc_RSOI') -or ($groups -contains 'arpc_XPX')) {
    Map-NetworkDrive S \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\OADB
}
   
If ($groups -contains 'arpc_cpo') {
    Map-NetworkDrive Z \\arpfs04.AREA52.AFNOAPPS.USAF.MIL\CPO$
}
        
If ($groups -contains 'ARPC_Muster') {
    Map-NetworkDrive K \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\Muster
}
    
If (($groups -contains 'ARPC_PayPool') -or ($groups -contains 'ARPC_PayPool Admins')) {
    Map-NetworkDrive P \\arpfs02.AREA52.AFNOAPPS.USAF.MIL\PAA
}
   
If (($groups -contains 'arpc_domain admins') -or ($groups -contains 'ARPC_IA') -or ($groups -contains 'ARPC_AD Admin') -or ($groups -contains 'ARPC_Network')) {
    Map-NetworkDrive I \\arpfs02.AREA52.AFNOAPPS.USAF.MIL\net-management
}

If (($groups -contains 'arpc_forcedevelop') -or ($groups -contains 'arpc_forcedevadmin')){
    Map-NetworkDrive N \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\DPA
}

If (($groups -contains 'arpc_DigitalMicro') -or ($groups -contains 'arpc_DigMicroAdmin')) {
    Map-NetworkDrive T \\arpfs07.AREA52.AFNOAPPS.USAF.MIL\DigitalMicrofiche
}

If ($groups -contains 'ARPC_AGR ADM') {
    Map-NetworkDrive U '\\arpfs07.AREA52.AFNOAPPS.USAF.MIL\DPA\AGR Management'
}

###########################################
###########  Power Management  ############
###########################################

#These set the workstation to never go to sleep and instead turn off the display
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0

###########################################
#########  Other / Temp Scripts  ##########
###########################################

# TEMPORARY - Disable Adobe Office Addin - TEMPORARY

[int]$LoadBehaviour = 0

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Excel\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Excel\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\MS Project\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\MS Project\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\OneNote\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\OneNote\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Outlook\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Outlook\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\PowerPoint\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\PowerPoint\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

If (Test-Path -Path 'HKCU:\Software\Microsoft\Office\Word\Addins\PDFMaker.OfficeAddin')
{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\Word\Addins\PDFMaker.OfficeAddin' -Name 'LoadBehavior' -Value $LoadBehaviour -ErrorAction SilentlyContinue
}

###########################################
#########  Run External Scripts  ##########
###########################################

# Powershell Scripts
# . $VPNFix
. $UpdateSharePaths
. $hp640
# VBS Scripts
cscript.exe $PrinterRemap

if($isvirtual -and ('HQ AFRC VMAdmins' -notin $groups) -and ('HQ AFRC VMAdmin Users' -notin $groups) ) {
    Start-Job -FilePath $VDIOvercommitted
}

powershell.exe -Nop -WindowStyle Hidden -Executionpolicy bypass -File "$workingdir\Network-Dashboard\Get-Dashboard.ps1"

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