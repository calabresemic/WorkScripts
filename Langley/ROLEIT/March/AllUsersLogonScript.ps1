<#
 AllUsersLogonScript.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 #>

<# Revision History
 11 Dec 2020 - Michael Calabrese (1468714589) - Edited error handling for unit logon scripts. Added groups to this part of the script, added all functions to this script.
 17 Dec 2020 - Michael Calabrese (1468714589) - Fixed onedrive detection for shortcuts
 1 Feb 2021 - Michael Calabrese (1468714589) - Unit scripts moved to the kicker
 5 Feb 2021 - Michael Calabrese (1468714589) - Updated Map-NetworkDrive, Set-IEHomePage(recommend moving to GPO), Removed Set-Background, added nested group membership
#>

#Load Functions
#================================
Function Map-NetworkDrive($DriveLetter,$Path,$ShareName){
	$mapped=Get-PSDrive -Name $driveletter -ErrorAction SilentlyContinue
    if($mapped){
        if($mapped.DisplayRoot -ne $path)
	    {      
            Remove-PSDrive -name $driveletter
            net use "$($driveletter):" /DELETE /Y
            Remove-SmbMapping "$($driveletter):" -Force -UpdateProfile -ErrorAction SilentlyContinue
		    New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
            (New-Object -ComObject Shell.Application).NameSpace("$($driveletter):").Self.Name=$sharename
	    }
    }
	Else
	{
		New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
        (New-Object -ComObject Shell.Application).NameSpace("$($driveletter):").Self.Name=$sharename
	}
}

Function Map-Printer($Printer){
	Add-Printer –ConnectionName $printer
}

Function Show-Popup($WindowTitle,$Message){
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("$message","$windowTitle",'ok','Information')
}

Function Show-Powerpoint($Filepath){
if(Test-Path $filepath){
    Invoke-Item $filepath
    }
}

Function Create-Shortcut($Name,$Target,$Icon){

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$([Environment]::GetFolderPath("Desktop"))\$name")
$Shortcut.TargetPath =$target
if($icon -ne $null){$Shortcut.IconLocation = $icon}
$Shortcut.Save()
}

Function Set-Favorites($Name,$URL,$Location){
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

Function Set-IEHomePage($URL){
    New-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Value $URL -PropertyType String -Force | Out-Null
}

# Setting the script to ignore all errors and continue
$ErrorActionPreference = 'SilentlyContinue'

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()

#Gather nested groups
#================================
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#Use this section for all base users
#================================

$workingdir=$PSScriptRoot
#$workingdir="\\area52.afnoapps.usaf.mil\March_afb\Logon_Scripts"
$userdesktop=[Environment]::GetFolderPath("Desktop")

# External Scripts
$VDIOvercommitted      = "$workingdir\BaseScript\custom\VDIOvercommitted.ps1"

#Connect PrintRelease
$Printers = gwmi win32_printer | select-object -ExpandProperty name
If ($Printers -notcontains 'PrintRelease')
{Map-Printer '\\52pczp-qs-001v\PrintRelease'}

###########################################
#########  Collabortive Computing  ########
###########################################

# Collaborative Computer Awareness Popup
$msg = "(1)  Look at the wall areas the camera faces. Remove any sensitive information from those wall areas including anything sensitive that may be beyond the confines of the user's office.`n
    (2) Remove any sensitive information from the use'rs desktop area to preclude inadvertent remote viewing of such information should the webcam fall from its perch.`n
    (3) Alert employees in the immediate work area to suspend any sensitive conversations until the webcam conversation are completed.`n
    (4) Post a sign at the office or cubicle entrance to alert others that an unclassified webcam conversation is taking place`n
    (5) Follow incident-reporting procedures if transmission of classified material by visual or other means occurs over an unclassified webcam."

Show-Popup -Message $msg -WindowTitle 'Collaborative Computing Awareness'

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

###########################################
########  Setting Drive Mappings  #########
###########################################
Map-NetworkDrive S "\\rivfs22\home" -ShareName "Scanned_Documents"

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
Start-Job -FilePath $VDIOvercommitted

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