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

Function Pin-App { 
    param(
        [string]$appname,
        [switch]$unpin
    )
    try{
        if ($unpin.IsPresent){
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'From "Start" UnPin|Unpin from Start'} | %{$_.DoIt()}
            return "App '$appname' unpinned from Start"
        }else{
            ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $appname}).Verbs() | ?{$_.Name.replace('&','') -match 'To "Start" Pin|Pin to Start'} | %{$_.DoIt()}
            return "App '$appname' pinned to Start"
        }
    }catch{
        Write-Error "Error Pinning/Unpinning App! (App-Name correct?)"
    }
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
$LogLogin              = "$workingdir\BaseScript\Custom\Log-Login.ps1"
$VPNFix                = "$workingdir\BaseScript\VPNFIX\VPNFIX.ps1"
$UpdateSharePaths      = "$workingdir\BaseScript\Update-SharePaths\Update-SharePaths.ps1"
$IE_HomePage           = "$workingdir\BaseScript\Custom\ie_home_page.ps1"
$hp640	               = "$workingdir\BaseScript\Custom\hp640.ps1"
$MapScanDrive          = "$workingdir\BaseScript\custom\MapScanDrive.ps1"

# Network Dashboard Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$UserDesktop\Network Dashboard.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Nop -WindowStyle Hidden -Executionpolicy bypass ""$workingdir\AllUsersLogonScript.ps1"""
$shortcut.IconLocation = "c:\windows\system32\shell32.dll,21"
$Shortcut.Save()

#CFP Shortcut
if("GLS_911 CS_CFP" -in $groups) {
Create-Shortcut -Name '911_CS_FAIS_Tool.lnk' -Icon "$workingdir\BaseScript\Custom\CS_logo.ico" -target "$workingdir\BaseScript\Custom\CFP_FAIS_Tool.vbs"
}

# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$workingdir\BaseScript\tier0_logo.ico" -target 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx'

# WingmanToolkit Shortcut
Create-Shortcut -Name 'Wingman Toolkit.lnk' -Icon "$workingdir\BaseScript\WingmanToolkit.ico" -target 'http://afrc.wingmantoolkit.org'

# 911 AW SharePoint Shortcut
Create-Shortcut -Name '911 AW SharePoint.lnk' -Icon "$workingdir\BaseScript\911AW.ico" -Target 'https://afrc.eim.us.af.mil/sites/911aw/SitePages/Home.aspx'

# Drive Map Self Help Shortcut
$Appfolder = "$env:USERPROFILE\AppData\Local\temp"
$hta = "$workingdir\BaseScript\Custom\DPMSH.hta"
Copy-Item -Path $hta -Destination $Appfolder -Force
Create-Shortcut -Name 'Drive_Map_Self_Help.lnk' -Icon "$workingdir\BaseScript\Custom\FOLDER.ICO" -Target "$Appfolder\DPMSH.hta"

# E-Tools Shortcut
If ('GLS_Pittsburgh_ETOV-eTools' -in $compgroups) {
    if(-not(Test-Path 'C:\E-Tools\GFileTOs' -ErrorAction Ignore)){
        MD 'C:\E-Tools\GFileTOs'
    }

    $Source = '\\pitfs01\MXG\MXQ\GFileTOs\'
    $Destination = 'C:\E-TOOLS\GFileTOs'

    ROBOCOPY.EXE $Source $Destination /XO /PURGE
	
    if(-not(Test-Path ("$UserDesktop\GFileTOs.lnk"))){
        $Source2 = "$workingdir\BaseScript\Custom\"
        $Destination2 = "$UserDesktop\"

        ROBOCOPY.EXE $Source2 $Destination2 GFileTOs.lnk /S /XO
    }
}

# Enable Proxy in Internet Explorer
$ShellApp = New-Object -ComObject Shell.Application
$ShellApp.Windows() | Where { $_.Name -eq "Internet Explorer" } | ForEach { $_.Quit() }
$RegKey ="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $RegKey -Name ProxyEnable -Value 1

#Pin Office Apps
Pin-App "Outlook 2016"
Pin-App "Word 2016" 
Pin-App "Excel 2016"
Pin-App "PowerPoint 2016"
Pin-App "Access 2016"
Pin-App "Publisher 2016"
Pin-App "Internet Explorer"
Pin-App "Outlook 2013"
Pin-App "Word 2013" 
Pin-App "Excel 2013"
Pin-App "PowerPoint 2013"
Pin-App "Access 2013"
Pin-App "Publisher 2013"

###########################################
##############  Newsletter  ###############
###########################################
$UTA=$false

if($UTA){
$SrcDirnl = '\\pitfs01\365_Day_Drive\PA\Newsletter'
$SrcDir = "$workingdir\BaseScript\Custom"
$DestDir = "$($env:USERPROFILE)\AppData\Local\Newsletter\Temp"
$newsfile = '911_AW_Newsletter.pdf'
$vbsfile = 'newsletter.vbs'
$DOCDIR = "$($env:USERPROFILE)\AppData\Local\Newsletter"
$TARGETDIR = "$DOCDIR\MatchedLog"
if(!(Test-Path -Path $TARGETDIR )){
    New-Item -ItemType directory -Path "$DOCDIR\Temp"

}
ROBOCOPY.EXE $SrcDirnl $DestDir $newsfile /IS /r:1 /w:1
ROBOCOPY.EXE $SrcDir $DestDir $vbsfile /IS /r:1 /w:1
wscript.exe "$($env:USERPROFILE)\AppData\Local\Newsletter\Temp\newsletter.vbs"
}

###########################################
###  Turn on Email sign and encryption  ###
###########################################

Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\14.0\Outlook\Security' -Name 'InitEncrypt' -Value '0'
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\14.0\Outlook\Security' -Name 'InitSign' -Value '1'

###########################################
########  Setting Drive Mappings  #########
###########################################

If("PIT_MXG_ALL" -in $groups)
{
Map-NetworkDrive M '\\pitfs01\MXG'
}

If("PIT_FEDLOG_USERS" -in $groups)
{
Map-NetworkDrive F '\\PITfs01\FEDLOG'
}

If("Pit_Farms" -in $groups)
{
Map-NetworkDrive R '\\PITFS04\ERM'
}

If("PIT_AW_ALL" -in $groups)
{
Map-NetworkDrive W '\\PITFS01\AW'
}

If("PIT_Domain_Users" -in $groups)
{
Map-NetworkDrive U '\\PITFS01\365_Day_Drive'
Map-NetworkDrive P '\\PITFS01\Plans_Programs'
}

If("PIT_ASTS_ALL" -in $groups)
{
Map-NetworkDrive T '\\PITFS01\ASTS'
}

If("PIT_MSG_ALL" -in $groups)
{
Map-NetworkDrive S '\\PITFS01\MSG'
}

If("PIT_OG_ALL" -in $groups)
{
Map-NetworkDrive O '\\PITFS01\OG'
}

If("PIT_OG_ALL" -in $groups)
{
Map-NetworkDrive X '\\PITFS01\COT'
}

Map-NetworkDrive N "\\thgc-fs-005v\HOME" -sharename "Scanned_Documents"

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
#. $DesktopAnywhereUsers
. $LogLogin -SharePath '\\Pitfs01\ezaudit$\LOGS'
#. $VPNFix
. $UpdateSharePaths
# Set Internet Explorer Home Pages
. $IE_HomePage
#Windows10 Script
. $hp640
#Map Scan Drives
.  $MapScanDrive

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