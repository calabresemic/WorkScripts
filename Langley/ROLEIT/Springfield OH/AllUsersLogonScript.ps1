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

Function Set-RegistryValue($Path,$Name,$Value,$PropertyType)
{
#Acceptable PropertyType Values are:Binary,DWord,ExpandString,MultiString,String,QWord

if(!(Test-Path $Path)){
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $value -PropertyType $PropertyType -Force | Out-Null}
else{
    New-ItemProperty -Path $Path -Name $Name -Value $value -PropertyType $PropertyType -Force | Out-Null}
}

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}

#Use this section for all base users
#================================
#Internet Explorer

$Folder1 = "178 WG Links"
$Folder2 = "178 NCC_CFP Links"

Set-RegistryValue -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "Start Page" -Value "https://usaf.dps.mil/sites/34122/SitePages/Home.aspx" -PropertyType String

#Map Drives for All Users
Map-NetworkDrive O "\\waar-fs-03v\official"
Map-NetworkDrive S "\\waar-fs-05v\S drive"
Map-NetworkDrive W "\\waar-fs-05v\178 WING SHARE"
Map-NetworkDrive P "\\waar-fs-05v\photo drive"

#Map Drives Based on Group Membership
If("USG_178 CF_NCC" -in $groups) {
    Map-NetworkDrive A "\\ang-ss-01\shared\software"
    Map-NetworkDrive X "\\waar-fs-01v\Software"
}

#IE FAVORITES For All Users
Remove-Item "$([Environment]::GetFolderPath('Favorites','None'))\$Folder1" -Recurse -Force

Set-Favorites -Name '178 CF Sharepoint' -URL "https://org2.eis.af.mil/sites/34122/MSG/CF/ComputerSelf-Help/SitePages/Home.aspx" -Location $Folder1
Set-Favorites -Name 'Outlook WebMail' -URL "https://web-cols03.mail.mil/owa" -Location $Folder1
Set-Favorites -Name 'Milconnect' -URL "https://www.dmdc.osd.mil/self_service/rapids/unauthenticated;jsessionid=V2GE4CTqlz6peZHl78cZggrCVGcNqo9kHatZQMMyyOSvMW1uVFqS!-129434391?execution=e1s1" -Location $Folder1

#IE FAVORITES Based on Group Membership
If("USG_178 CF_NCC" -in $groups) {
    Remove-Item "$([Environment]::GetFolderPath('Favorites','None'))\$Folder2" -Recurse -Force

    Set-Favorites -Name 'IAOExpress' -URL "https://esd.us.af.mil/esdportal/ESDToolboxMain.aspx" -Location $Folder2



}

#Map Printers Based on Group Membership
If("178 WG CF" -in $groups) {
    Map-Printer "\\WAAR-QS-02v.area52.afnoapps.usaf.mil\CF HPM680C-001"
    Map-Printer "\\WAAR-QS-02v.area52.afnoapps.usaf.mil\CF-MultiBlackLAS-001"
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

#If("Groupname" -notin $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#}