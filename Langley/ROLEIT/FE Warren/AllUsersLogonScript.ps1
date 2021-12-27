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

#Open Base Web Page
start-process "https://cs2.eis.af.mil/sites/10728/few/SitePages/Home.aspx"

#Open AFGSC Mission and Vision statement picture
Start-Process "\\ghzo-fs-001p\ghzo-fs-001p$\Base_Information\PopUps\AFGSCMissionandVision.jpg"

#Shared Drive Mappings For all Base Users
Map-NetworkDrive O "\\ghzo-fs-001p\ghzo-fs-001p$\Base_Information"
Map-NetworkDrive H "\\ghzo-fs-001p\ghzo-fs-001p$\hold"
#Map-NetworkDrive J "\\ghzo-fs-001p\ghzo-fs-001p$\organizations"

If("FE_IG" -in $groups)
{
Map-NetworkDrive Z "\\ghzo-fs-001p\ghzo-fs-001p$\ig$"
}

If("FE_WGM" -in $groups)
{
Map-NetworkDrive T "\\ghzo-fs-001p\ghzo-fs-001p$\tools"
}

If("FE_mps" -in $groups)
{
Map-NetworkDrive M "\\ghzo-fs-001p\ghzo-fs-001p$\mps$"
}

If("FE_erm" -in $groups)
{
Map-NetworkDrive Y "\\ghzo-fs-001p\ghzo-fs-001p$\erm$"
}

If("GLS_AFGSC_MES" -in $groups)
{
Map-NetworkDrive K "\\ghzo-fs-001p\ghzo-fs-001p$\AFGSC_MES"
}

If("FE_90CS" -in $groups)
{
Map-NetworkDrive X "\\ghzo-fs-001p\ghzo-fs-001p$\90MSG\90CS"
}

If("FE_90OG" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\90OG"
}

If("FE_90MXG" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\90MXG"
}

If("FE_20AF" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\20AF"
}

If("FE_90sfg" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\90sfg"
}

If("FE_90MSG" -in $groups)
{
Map-NetworkDrive K "\\ghzo-fs-001p\ghzo-fs-001p$\90MSG"
}

If("FE_90LRS" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\90MSG\90LRS"
}

If("373TRS_Det21" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\373TRS"
}

If("FE_583MMXS" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\583MMXS"
}

If("FE_90CPTS" -in $groups)
{
Map-NetworkDrive Q "\\ghzo-fs-001p\ghzo-fs-001p$\90MW\90CPTS"
}

If("GLS_20 AF_582 HG" -in $groups)
{
Map-NetworkDrive W "\\ghzo-fs-001p\ghzo-fs-001p$\20AF\20AF-Helicopters"
}

If("FE_Legal All" -in $groups)
{
Map-NetworkDrive L "\\ghzo-fs-001p\ghzo-fs-001p$\OSI"
}

If("FE_90MW" -in $groups)
{
Map-NetworkDrive M "\\ghzo-fs-001p\ghzo-fs-001p$\90MW"
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