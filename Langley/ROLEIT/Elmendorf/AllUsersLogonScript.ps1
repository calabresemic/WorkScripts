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
	$mapped=Get-PSDrive -Name $driveletter
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
$longGroups = (([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique
$Groups = $longGroups.replace('AREA52\','')

#Use this section for all base users
#================================
If("GLS_11AF_FILESHARE" -in $groups)
{
Map-NetworkDrive O "\\elfs1.AREA52.AFNOAPPS.USAF.mil\11AF_erm\11AF\176 ACS"
Map-NetworkDrive L "\\elfs3.AREA52.AFNOAPPS.USAF.mil\exempt\11af_exempt"
Map-NetworkDrive P "\\elfs2.AREA52.AFNOAPPS.USAF.mil\11af"
Map-NetworkDrive M "\\elfs2.AREA52.AFNOAPPS.USAF.mil\611th"
}

If("GLS_611AOC-RCC_FILESHARE" -in $groups)
{
Map-NetworkDrive M "\\elfs1.AREA52.AFNOAPPS.USAF.mil\rcc_ERM"
}

If("GLS_611AOC_FILESHARE" -in $groups)
{
Map-NetworkDrive P "\\elfs2.AREA52.AFNOAPPS.USAF.mil\611th"
Map-NetworkDrive O "\\elfs1.AREA52.AFNOAPPS.USAF.mil\611 AOC_ERM"
Map-NetworkDrive N "\\elfs1.AREA52.AFNOAPPS.USAF.mil\11af_ERM"
Map-NetworkDrive Q "\\elfs3.AREA52.AFNOAPPS.USAF.mil\exempt\611th_exempt"
}

If("GLS_611CES-GEOBASE_FILESHARE" -in $groups)
{
Map-NetworkDrive Z "\\elfs3.AREA52.AFNOAPPS.USAF.mil\geobase"
}

If("GLS_RCC_FILESHARE" -in $groups)
{
Map-NetworkDrive M "\\elfs1.AREA52.AFNOAPPS.USAF.mil\rcc_ERM"
}

If("3 WG_XP USERS" -in $groups)
{
Map-NetworkDrive Z "\\elfs3.AREA52.AFNOAPPS.USAF.mil\3wg\3WG-XP\XPF"
}

If("GLS_673MDG-CHCSII_FILESHARE" -in $groups)
{
Map-NetworkDrive O "\\3MDG-File-Srv0.AREA52.AFNOAPPS.USAF.mil\CHCSII"
}


If( ("GLS_11 AF_RCC" -in $groups) -and ("GLS_611AOC-RCC_FILESHARE</" -in $groups) )
{
Map-NetworkDrive H "\\fileserver\sharename"
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