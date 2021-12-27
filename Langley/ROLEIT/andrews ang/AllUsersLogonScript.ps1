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

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()

#Gather nested groups
#================================
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#Use this section for all base users
#================================
#***Shared Drive Mappings For all Base Users***
Map-NetworkDrive Y "\\AJXX-FS-005v\Groups"
Map-NetworkDrive O "\\AJXX-FS-002v\OfficialRecords$"
Map-NetworkDrive J "\\AJXX-FS-004v\DCANG"
Map-NetworkDrive G "\\ajxx-fs-003v\wing"

#Modify homepage for 113th SharePoint homepage
Set-IEHomePage "https://cs2.eis.af.mil/sites/12794/default.aspx"

#Internet Explorer proxy changes
reg add “HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings” /v AutoConfigURL /f

reg add “HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings” /v ProxyEnable /t REG_DWORD /d 1 /f

reg add “HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings” /v ProxyServer /t REG_SZ /d andrews.proxy.us.af.mil:8080 /f

reg add “HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings” /v AutoDetect /t REG_DWORD /d 0 /f

#McAfee
& "C:\Program Files\McAfee\Agent\x86\McScanCheck.exe"
& "C:\Program Files\McAfee\Agent\x86\UpdaterUI.exe"

If("GLS_113 WG_USERS-CAT-1" -in $groups)
{
    #If folder doesn't exist, create it
    if(!(Test-Path "\\ajxx-fs-001v\cat1$\$env:Username")){New-Item -ItemType Directory -Path "\\ajxx-fs-001v\cat1$\$env:Username"}
    Map-NetworkDrive H "\\ajxx-fs-001v\cat1$\$env:Username"
    #CFP Logs
    if(!(Test-Path "\\ajxx-fs-001v\cat1$\$env:Username\CFPLogs")){New-Item -ItemType Directory -Path "\\ajxx-fs-001v\cat1$\$env:Username\CFPLogs"}
    #Hide CFP Logs
    attrib +h "\\ajxx-fs-001v\cat1$\$env:Username\CFPLogs"
}
elseIf("GLS_113 WG_USERS-CAT-2" -in $groups)
{
    #If folder doesn't exist, create it
    if(!(Test-Path "\\ajxx-fs-001v\cat2$\$env:Username")){New-Item -ItemType Directory -Path "\\ajxx-fs-001v\cat2$\$env:Username"}
    Map-NetworkDrive H "\\ajxx-fs-001v\cat2$\$env:Username"
    #CFP Logs
    if(!(Test-Path "\\ajxx-fs-001v\cat2$\$env:Username\CFPLogs")){New-Item -ItemType Directory -Path "\\ajxx-fs-001v\cat2$\$env:Username\CFPLogs"}
    #Hide CFP Logs
    attrib +h"\\ajxx-fs-001v\cat2$\$env:Username\CFPLogs"
}

#TrackLogins
$LogFolder="\\ajxx-nm-001v\computerlogs$\$env:COMPUTERNAME"
$date=Get-Date -Format 'MM/dd/yyy'
$time=Get-Date -Format 'HH:mm:ss tt'
$MAC=(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.MACAddress -ne $null}).MACAddress

#If folder doesn't exist, create it
if(!(Test-Path $LogFolder)){New-Item -ItemType Directory -Path $LogFolder}
"LOGON :$env:Username;$env:COMPUTERNAME;$time;$date;$MAC." >> "$LogFolder\LogFile.txt"

#SH Desktop Link
Remove-Item "$([Environment]::GetFolderPath("Desktop"))\Selfies.lnk" -ErrorAction SilentlyContinue
Create-Shortcut -Name "CFP Selfies.lnk" -Target "https://cs2.eis.af.mil/sites/12794/msg/CF/SitePages/Selfies.aspx" -Icon "\\area52.afnoapps.usaf.mil\andrews_ang\Logon_Scripts\DesktopIcon\CFPSelfies.ico"

#SP Desktop Link
Create-Shortcut -Name "113th Wing SharePoint.lnk" -Target "https://cs2.eis.af.mil/sites/12794/default.aspx" -Icon "\\area52.afnoapps.usaf.mil\andrews_ang\Logon_Scripts\DesktopIcon\113thWingOfficialPatch.ico"

#Printer
Create-Shortcut -Name "Printers.lnk" -Target "\\AJXX-QS-001v" -Icon "\\area52.afnoapps.usaf.mil\andrews_ang\Logon_Scripts\DesktopIcon\printers.ico"

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

#If( ("Groupname" -in $groups) -or ("Groupname" -in $groups) )
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