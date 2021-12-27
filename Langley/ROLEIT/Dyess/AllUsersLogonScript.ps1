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

#Login Advertisements
if(Test-Path "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_1.jpg"){
Mshta.exe "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_1.hta"
}
if(Test-Path "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_2.jpg"){
Mshta.exe "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_2.hta"
}
if(Test-Path "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_3.jpg"){
Mshta.exe "\\area52.afnoapps.usaf.mil\dyess_afb\Logon_Scripts\login_advertisement_3.hta"
}

#p12pfx Delete
Get-ChildItem $env:USERPROFILE\*.pfx | Remove-Item
Get-ChildItem $env:USERPROFILE\*.p12 | Remove-Item

#Comp Info
#McAfee checks
if(Test-Path "C:\Program Files\McAfee\Agent\x86\FrmInst.exe"){$Agent='Good'}
else{$Agent='Bad'}

if(Test-Path "C:\Program Files\McAfee\DLP\Agent\x86\fcagd.exe"){$DLP='Good'}
else{$DLP='Bad'}

if(Test-Path "C:\Program Files\McAfee\Host Intrusion Prevention\FireSvc.exe"){$HIPS='Good'}
else{$HIPS='Bad'}

if(Test-Path "C:\Program Files\McAfee\Endpoint Security\Threat Prevention\mfetp.exe"){$EPS='Good'}
else{$EPS='Bad'}

#computer information
$NetAdapter=Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.MACAddress -ne $null}
$IP = $NetAdapter.IPAddress -join ","
$MAC = $NetAdapter.MACAddress  -join ","
$BIOS = Get-WmiObject Win32_Bios
$SN = $BIOS.SerialNumber
$Model=(Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMinformation" -Name Model).Model
$disk=Get-CimInstance win32_logicaldisk | Where-Object {$_.DriveType -eq 3}

$output=[pscustomobject]@{
    'Computer Name:'=$env:COMPUTERNAME;
    'SDC Version'=$Model;
    'Serial Number:'=$SN;
    'MAC Address'=$MAC;
    'I.P. Address'=$IP;
    'Current User'=$env:Username;
    'McAfee Agent'=$Agent;
    DLP=$DLP;
    HIPS=$HIPS;
    'Endpoint Security'=$EPS;
    'Directory:'=$disk.Name;
    'Size:'="$([math]::Round($disk.Size/1gb))GB";
    'Free Space:'="$([math]::Round($disk.FreeSpace/1gb))GB"}

$output | Export-Csv "\\fnwz-as-patch1p\F\CompInfo\$env:COMPUTERNAME-$SN.csv" -Force -NoTypeInformation

#---Common Mappings---
Map-NetworkDrive J "\\FNWZ-FS-03pv\Dyess_7BW_STAFF_WS\base_data_ws\base_data"
Map-NetworkDrive M "\\FNWZ-FS-03pv\Dyess_7BW_STAFF_WS\base_data_ws\base_multimedia"

If("First Sergeant Folder Access" -in $groups)
{
Map-NetworkDrive K "\\FNWZ-FS-03pv\Dyess_7BW_STAFF_WS\base_data_ws\Dyess First Sergeant"
}

#ERM Drives
($groups | where {($_ -match 'ERM_') -or ($_ -match 'FARM_')}).ForEach{
    Switch($_){
        "ERM_7BWSTAFF_MAP" {Map-NetworkDrive X "\\FNWZ-FS-03PV\Dyess_7BW_STAFF"}




        }
    }

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