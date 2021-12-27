<#
 AllUsersLogonScript.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 #>

<# Revision History
 11 Dec 2020 - Michael Calabrese (1468714589) - Edited error handling for unit logon scripts. Added groups to this part of the script, added all functions to this script.
 17 Dec 2020 - Michael Calabrese (1468714589) - fixed onedrive detection for shortcuts
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
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

#Use this section for all base users
#================================

#Map Q for all users
Map-NetworkDrive Q "\\LYBH-FS-01\Working_Files"

#Map U for all users based on DoDID/username
Map-NetworkDrive U "\\LYBH-FS-05\$($env:username.Substring(0,10))$"


#Map R for all users based on access to the 130AW-ERM group
#If 130AW-ERM is contained in the group name then user has R drive rights.

if(($groups | %{$_ -like "130AW-ERM*"}) -contains $true)
{
Map-NetworkDrive R "\\LYBH-FS-03\eRecords$"
}


#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================

#Map Z based on group membership

If("130AW.CC.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\130AW_Secure$"
}

ELSEIF("130AW.WG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\AW$"
}

ELSEIF("130AW.MSG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\MSG$"
}

ELSEIF("130AW.MXG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\MXG$"
}

ELSEIF("130AW.OG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\OG$"
}

ELSEIF("130AW.MDG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\MDG$"
}

ELSEIF("130AW.WVANG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\WVANG$"
}

ELSEIF("130AW.CP.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\CP$"
}

ELSEIF("130AW.CES.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\CES$"
}

ELSEIF("130AW.CF.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\CF$"
}

ELSEIF("130AW.MSC.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\MSC$"
}

ELSEIF("130AW.XP.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\XP$"
}

ELSEIF("130AW.CEF.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\CEF$"
}

ELSEIF("130AW.Starbase.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\Starbase$"
}

ELSEIF("130AW.FSS.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\FSS$"
}

ELSEIF("130AW.PA.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\PA$"
}

ELSEIF("130AW.SFS.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\SFS$"
}

ELSEIF("130AW.IG.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\IG$"
}

ELSEIF("130AW.JA.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\JA$"
}

ELSEIF("130AW.LGRR.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\LGRR$"
}

ELSEIF("130AW.LS.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\LS$"
}

ELSEIF("130AW.APS.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\APS$"
}

ELSEIF("130AW.FM.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\FM$"
}

ELSEIF("130AW.LOD.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\LOD$"
}

ELSEIF("130AW.SE.Secure" -in $groups)
{
Map-NetworkDrive Z "\\LYBH-FS-02\SE$"
}

#END OF Z DRIVE MAPPING

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


#ERROR HANDLING FOR UNIT SCRIPTS
#================================
If(($l -eq "") -and ($o -eq "")){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing l `(city`) attribute and o `(organization`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. City `n 2. Organization/Unit"}
Elseif($l -eq ""){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing l `(city`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. City"}
Elseif($o -eq ""){
    Write-EventLog -EventId 1130 -LogName Application -Message "User account missing o `(organization`) attribute.  Contact ESD to have this information updated." -EntryType Error -source "Windows Error Reporting"
    Show-popup "Login Script Failure" "Login script failed to execute due to a missing file or improper user account configuration. The following attributes for domain user $CN need to be verified in DRA. These attributes are found under the `'USAF Account Settings`' section. `n`n 1. Organization/Unit"
    }
ElseIf(test-path $unitscript)
{
    #If all attributes are set and there is a unit script, run it
    Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file $unitScript
}
Else{Exit}