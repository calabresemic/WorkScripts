<#
 PetersonLoginKicker.ps1
 Written by Andrew Metzger, 21 CS
 23 Sep 2020
 Implimented by NOTAM 2020-259-002, Base Login Script Best Practices
 Version 2
 #Change Log
 #11 Dec 2020 - SSgt Calabrese - Edited error handling for unit logon scripts
#>

#Load Functions
Function Show-Popup($WindowTitle,$Message)
{
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("$message","$windowTitle",'ok','Error')
}

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

Function Show-Powerpoint($filepath)
{
if(Test-Path $filepath){
    $application = New-Object -ComObject powerpoint.application
    $presentation = $application.Presentations.open($filepath)
    $application.visible = "msoTrue"
    $presentation.SlideShowSettings.Run()
    }
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

#This will open the 355 WG priorities at login
start \\area52.afnoapps.usaf.mil\davis_monthan_afb\Logon_Scripts\Popups\355WG_Mission.jpg

#Set Favorites
#================================
#Replace $Name with the display Name for the shortcut, $Url with the full URL for the shortcut, and $location with the folder path where the shortcut will be saved.
#Call the Set-Favorites function as many times as needed to create multiple shortcuts
#Set favorites by calling the function with the Name, URL, and Folder path for the shortcut.  All shortcuts are stored in the Favorites folder by default

Set-Favorites "Air Force LeaveWeb" "https://www.my.af.mil/leavewebprod/login" "DLT Links"
Set-Favorites "Outlook Web Mail(.mil Only)" "https://webmail.apps.mil/owa/us.af.mil" "DLT Links"
Set-Favorites "Outlook Web Mail(External Only)" "https://owa.us.af.mil" "DLT Links"
Set-Favorites "355 Wing - Writing Guide" "https://usaf.dps.mil/sites/Davis-Monthan/355FW/correspondencetracker/SitePages/Home.aspx" "DLT Links"
Set-Favorites "355 Wing - Strategic Plan" "https://usaf.dps.mil/sites/Davis-Monthan/355FW/strategicplan/default.aspx" "DLT Links"
Set-Favorites "355 Wing - Manpower and Organization" "https://usaf.dps.mil/sites/Davis-Monthan/355MSG/355FSS/ManPow/MPS/SitePages/Home.aspx" "DLT Links"
Set-Favorites "Microsoft Office 365" "https://www.ohome.apps.mil/" "DLT Links"
Set-Favorites "Air Force Publications" "https://www.e-publishing.af.mil" "DLT Links"
Set-Favorites "Defense Travel System (DTS)" "https://dtsproweb.defensetravel.osd.mil/" "DLT Links"

$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

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