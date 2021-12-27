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

Function Set-Background($image,$attempts){
#Highly recommend using a BMP image.Tested fine with only requiring 5 updates of the user system params. If you experience issues add a number for the $attemps variable when calling the function.
if($attempts -eq $null){$attempts=5}
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d $image /f
for ($i=0; $i -le $attempts; $i++)
    {
    RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters, 1, true
    }
}

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$adobjComputer = ([adsisearcher]"Samaccountname=$($env:COMPUTERNAME)$").findone()
$compgroups = $adobjComputer.Properties.memberof | %{$_.split("=")[1].split(",")[0]}

#Gather nested groups
#================================
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#Use this section for all base users
#================================

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================

#GROUP MEMBERSHIP SPECIFIC ACTIONS
#================================
# Add more groups by copying the information below
# Replace Groupname with security group name to target specific users
# Two options below for filtering in or out of a group

If("123AW-All" -in $groups)
{
Map-NetworkDrive W "\\NSQN-FS-001v.area52.afnoapps.usaf.mil\Wing_Org" -ShareName "Wing Org"
Create-Shortcut -Name "Network Incident Response Aid.lnk" -Target "\\NSQN-fs-001v\wing_org\000_scripts\PinItem\Network_Incident_Response_Aid.pdf" -Icon "\\NSQN-fs-001V.area52.afnoapps.usaf.mil\WING_ORG\000_scripts\PinItem\CF_Icon.ico"
Copy-Item "\\NSQN-fs-001V.area52.afnoapps.usaf.mil\WING_ORG\000_scripts\PinItem\Update McAfee.lnk" -Destination "$([Environment]::GetFolderPath("Desktop"))\Update McAfee.lnk"
}

If("123AW_CCREPORTS_Root" -in $groups) 
{
Map-NetworkDrive Z "\\NSQN-FS-002v.area52.afnoapps.usaf.mil\CC-Reports1" -ShareName "CC Reports"

#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
}


If("GLS_Louisville_CFS-CSA" -in $groups) 
{
Map-NetworkDrive S "\\NSQN-FS-004v.area52.afnoapps.usaf.mil\software" -ShareName "CSA Utility"

}

#If("Groupname" -notin $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}

if("123AW_Comp_Replace" -in $compgroups){
Set-Background -image "\\nsqn-fs-001v\wing_org\000_scripts\Comp_Replace.bmp"
}