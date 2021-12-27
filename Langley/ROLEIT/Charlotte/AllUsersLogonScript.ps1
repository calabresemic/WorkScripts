<#
 AllUsersLogonScript.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 #>

<# Revision History
 11 Dec 2020 - Michael Calabrese (1468714589) - Edited error handling for unit logon scripts. Added groups to this part of the script, added all functions to this script.
 17 Dec 2020 - Michael Calabrese (1468714589) - Fixed onedrive detection for shortcuts
 1  Feb 2021 - Michael Calabrese (1468714589) - Unit scripts moved to the kicker
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
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}

#Use this section for all base users
#================================

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================

if( ("NCCHAR PRIME_SITE_RALEIGH" -in $groups) -or ("NCCHAR PRIME_SITE_CHARLOTTE" -in $groups) )
{
Map-NetworkDrive M "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\ORG"
Map-NetworkDrive O "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\ERM"
Map-NetworkDrive S "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\SHARE\SHARE_CHAR"
Map-NetworkDrive W "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\APPS\APPS_CHAR"
Map-NetworkDrive Y "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\APPS\JUKE"
}

if("NCCHAR PRIME_SITE_NEWLONDON" -in $groups)
{
Map-NetworkDrive M "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\ORG"
Map-NetworkDrive O "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\ERM"
Map-NetworkDrive S "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\SHARE\SHARE_GSU"
Map-NetworkDrive W "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\APPS\APPS_NEWL"
Map-NetworkDrive Y "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\APPS\JUKE"
}

If("145 AW Public Affairs" -in $groups)
{
Map-NetworkDrive V "\\AREA52.AFNOAPPS.USAF.MIL\CHARLOTTE\PA"
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

#If("Groupname" -notin $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}