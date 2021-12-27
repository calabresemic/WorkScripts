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
[string]$UserCN = $adobj.Properties.cn

#Gather nested groups
#================================
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#Use this section for all base users
#================================
#Creates Tier 0.lnk on current user's desktop on logon
Create-Shortcut -Name "Tier 0.lnk" -Target "https://eim.amc.af.mil/org/319arw/Tier0/default.aspx" -Icon "https://eim.amc.af.mil/org/319arw/Tier0/Picture%20Library/Stock%20Photos/tier0_icon_red.ico"

#Creates WaterCooler.lnk on current user's desktop on logon
Create-Shortcut -Name "Events-Calendar.lnk" -Target "http://www.grandforks.af.mil/Home/Events-Calendar" -Icon "\\jfsdns20vdm1\319-arw-g$\PA\WaterCoolerSlides\Sven.ico"

#Run CA Removal 
start "\\jfsl-fs-01pv\319-msg-g\319-CS\SCO\Software\CA_Removal\FBCA_crosscert_remover_v108.exe" -ArgumentList "/SILENT"
REG DELETE HKCU\Software\Microsoft\SystemCertificates\CA\Certificates /f

#Place Excel PII configuration file in users' APPDATA folder - maybe remove
if(Test-Path "c:\ExcelPII\a.crc"){Copy-Item "C:\ExcelPII\a.crc" -Destination "$env:APPDATA\Microsoft\AddIns" -Container}

#Launch browser and navigate to Base Home Page
start "https://www.grandforks.af.mil/Coronavirus/"

#----Save Log files----
$CLogPath = "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs\Computers\$env:COMPUTERNAME.csv"
$ULogPath = "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs\Users\$env:username-$UserCN.csv"

#computer information
$NetAdapter=Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.MACAddress -ne $null}
$IP = $NetAdapter.IPAddress -join ","
$MAC = $NetAdapter.MACAddress  -join ","
$OS = Get-WmiObject Win32_OperatingSystem
$OSCaption = $OS.Caption
$OSVer = $OS.Version

#date info
$date=Get-Date -Format "MM/dd/yyyy"
$time=Get-Date -Format "HH:mm:ss tt"

$output=[pscustomobject]@{'Date'= $date;'Time'= $time;'Username'= $env:Username;'Display Name'= $UserCN;'Computer Name'= $env:COMPUTERNAME;'OS Name'= $OSCaption;'OS Version'= $OSVer;'MAC Address'= $MAC;'IP Address'= $IP}

$output | Export-Csv $ClogPath -NoTypeInformation -Append
$output | Export-Csv $ULogPath -NoTypeInformation -Append

#CCRI Popup
$message="- Never leave Common Access Cards (CACs) or SIPR tokens unattended
- Know your Cybersecurity Liason (CSL) & Unit Security Managers
- Know your Network Incident Procedures
- Report violations/incidents to unit CSLs and/or Security Managers
- Never connect unapproved USB devices to government systems
- Log out & restart NIPR machines daily
- Connect SIPR workstations every Tuesday & Thursday from 0900-1600
- Follow weekly Cyber Monday emails
- Keep work areas/facilities clean & organized: Clean Desk policy
- Digitally sign all e-mails w/attachments or hyperlinks
- Encrypt e-mails containing FOUO/PII data"

Show-Popup -Message $message -WindowTitle "CCRI Information"

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================
If("GF JFSD Server Shop" -in $groups)
{
Map-NetworkDrive H "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
Map-NetworkDrive L "\\jfsl-fs-001v\servershop"
Map-NetworkDrive S "\\jfsl-fs-01pv\GrandForks_319_RW_S"
Map-NetworkDrive T "\\jfsl-fs-001v\servershop\servershop\software"
Map-NetworkDrive W "\\jfsl-fs-001v\servershop\csa"
}

If("gls_grand forks_CFP-CSA" -in $groups)
{
Map-NetworkDrive H "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
Map-NetworkDrive S "\\jfsl-fs-01pv\GrandForks_319_RW_S"
Map-NetworkDrive W "\\jfsl-fs-001v\servershop\csa"
}

If("319 CS_SCOI" -in $groups)
{
Map-NetworkDrive L "\\jfsl-fs-001v\SCOI$"
Map-NetworkDrive W "\\jfsl-fs-001v\servershop\csa"
}

If("GF CS CSA" -in $groups)
{
Map-NetworkDrive H "\\jfsl-fs-01pv\GrandForks_319_MSG\319-CS\SCO\Audit_Logs"
Map-NetworkDrive W "\\jfsl-fs-001v\servershop\csa"
}

If("GF CSA ALL" -in $groups)
{
Map-NetworkDrive W "\\jfsl-fs-001v\servershop\csa"
}

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