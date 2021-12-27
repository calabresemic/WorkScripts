<#
 AllUsersLogonScript.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 #>

<# Revision History
 #11 Dec 2020 - Michael Calabrese (1468714589) - Edited error handling for unit logon scripts. Added groups to this part of the script, added all functions to this script.
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

$adobjComputer = ([adsisearcher]"Samaccountname=$($env:COMPUTERNAME)$").findone()
$adobjComputer.Properties.distinguishedname
If ($objComputer.DistinguishedName -match 'Virtual Computers'){$isvirtual=$true}
else{$isvirtual=$false}

#Use this section for all base users
#================================

$workingdir=$PSScriptRoot
#$workingdir="\\area52.afnoapps.usaf.mil\hq_afrc_afb\Logon_Scripts"

$Form4394 = "$workingdir\BaseScript\FORM4394\form4394.ps1"
$Form4433 = "$workingdir\BaseScript\Form4433\HQForm4433.ps1"
$LogLogin = "$workingdir\BaseScript\Custom\Log-Login.ps1"
$VDIOvercommitted = "$workingdir\BaseScript\custom\VDIOvercommitted.ps1"
$5_Message = "$workingdir\BaseScript\Custom\5_Message.ps1"
$userdesktop=[Environment]::GetFolderPath("Desktop")

# Network Dashboard Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$UserDesktop\Network Dashboard.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-Nop -Executionpolicy bypass ""$workingdir\Network-Dashboard\Get-Dashboard.ps1"""
$shortcut.IconLocation = "c:\windows\system32\shell32.dll,21"
$Shortcut.Save()

# Tier 0 Shortcut
Create-Shortcut -Name 'AFRC Tier 0.lnk' -Icon "$currentdir\Icons\tier0_logo.ico" -target 'https://afrc.eim.us.af.mil/sites/Tier0/BaseSites/Robins/SitePages/Home.aspx'

#Team Robins Splash
Create-Shortcut -Name 'Team Robins Splash Page.lnk' -Icon "$currentdir\Icons\TeamRobinsSplash.ico" -Target 'https://splash.robins.af.mil'

if(!(Test-Path "$UserDesktop\CHES_enduserguide.pdf" -ErrorAction SilentlyContinue)){Copy-Item '\\area52.afnoapps.usaf.mil\hq_afrc_afb\Logon_Scripts\BaseScript\Icons\CHES_enduserguide.pdf' -Destination "$UserDesktop" -Force -ErrorAction SilentlyContinue}

#Service Now Shortcut to SDC
.  "$workingdir\BaseScript\Shortcuts\AddLogonShortcutFatClient.ps1"


###########################################
########  Running outside scripts  ########
###########################################

If (!($isvirtual)){
    If($groups -notcontains 'GLS_HQ AFRC_4394 Exempt'){
    
    #cscript.exe $Form4394
    . $Form4394
    }
}

If (!($isvirtual)){
    IF($groups -contains 'GLS_AFRC_CHES Mobile Users_AF4433'){
        
       . $Form4433   
    }
 }

 If (!($isvirtual)){

    . $5_Message
 }

If (!($isvirtual)){
    if (($groups -notcontains 'HQ AFRC VMAdmins') -and ($groups -notcontains 'HQ AFRC VMAdmin Users')){ # virtualization exception with custom storage
       Start-Job -FilePath $VDIOvercommitted
    }
}

If (!($env:COMPUTERNAME -eq 'UHHZ-TS-004V'))
{
    Start-Process powershell "$workingdir\Network-Dashboard\Get-Dashboard.ps1"
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