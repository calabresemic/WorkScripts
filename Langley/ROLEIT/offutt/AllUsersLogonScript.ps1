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
Create-Shortcut "55 FSS.lnk" "http://offutt55fss.com/onoffutt" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\Icons\55FSS.ico"
Create-Shortcut "55 WG OPSEC.lnk" "https://usaf.dps.mil/sites/Offutt/55thWing/wingstaff/wgprograms/IP/SitePages/Home.aspx" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\Icons\opsec.ico"
Create-Shortcut "Offutt Printers.lnk" "\\sgbp-qs-001v" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\Icons\Print.ico"
Create-Shortcut "SDSS.lnk" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\SDSS.oft" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\SDSS.ico"
Create-Shortcut "Innovate Your Ideas.lnk" "https://usaf.dps.mil/sites/Offutt/55thWing/Innovate%20Your%20Ideas/SitePages/Home.aspx" "\\area52.afnoapps.usaf.mil\offutt_afb\Logon_Scripts\Scripts\Icons\InnovateYourIdeas.ico"

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================

#GROUP MEMBERSHIP SPECIFIC ACTIONS
#================================
# Add more groups by copying the information below
# Replace Groupname with security group name to target specific users
# Two options below for filtering in or out of a group

If("USG_55 CG_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-01pv.area52.afnoapps.usaf.mil\Offutt_55WG_CG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 WG_STAFF_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-01pv.area52.afnoapps.usaf.mil\Offutt_55WG_STAFF_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 OG_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-02pv.area52.afnoapps.usaf.mil\Offutt_55WG_OG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_AFWA_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-02pv.area52.afnoapps.usaf.mil\Offutt_557WW_Group_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_557 WW_Wing Staff_All" -in $groups)
{
Map-NetworkDrive I "\\sgbp-fs-02pv.area52.afnoapps.usaf.mil\Offutt_557WW_Staff_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 MDG_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-03pv.area52.afnoapps.usaf.mil\Offutt_55WG_MDG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 MXG_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-02pv.area52.afnoapps.usaf.mil\Offutt_55WG_MXG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 ISS_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-04pv.area52.afnoapps.usaf.mil\Offutt_55ISS_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 MSG_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-04pv.area52.afnoapps.usaf.mil\Offutt_55MSG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_TENET UNITS_WS" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-05pv.area52.afnoapps.usaf.mil\Offutt_Tenant_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("USG_55 MSG_AFICA" -in $groups)
{
Map-NetworkDrive J "\\sgbp-fs-01pv.area52.afnoapps.usaf.mil\Offutt_AFICA"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

If("595CACG_Sharedrive" -in $groups)
{
Map-NetworkDrive H "\\sgbp-fs-02pv.area52.afnoapps.usaf.mil\Offutt_595CACG_WS"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}

#If("Groupname" -notin $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}