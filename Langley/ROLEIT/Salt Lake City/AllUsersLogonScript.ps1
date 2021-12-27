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
$Name = $adobj.Properties.cn

#Gather Computer Information
$SN=(Get-WmiObject win32_bios).SerialNumber

#Gather nested groups
#================================
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#Use this section for all base users
#================================
#Login Logs
$ULogFile = "\\USCG-WS-001V\Logon\Users\$Name.txt"
$CLogFile = "\\USCG-WS-001V\Logon\Computers\$env:COMPUTERNAME.txt"
$SNLogFile = "\\USCG-WS-001V\Logon\Serial Number\$SN.txt"

"$Name, $env:COMPUTERNAME, $SN, $(Get-Date)" >> $ULogFile
"`n" >> $ULogFile
"$Name, $env:COMPUTERNAME, $SN, $(Get-Date)" >> $CLogFile
"`n" >> $CLogFile
"$Name, $env:COMPUTERNAME, $SN, $(Get-Date)" >> $SNLogFile
"`n" >> $SNLogFile

#All User Drives
Map-NetworkDrive K "\\USCG-FS-001v\Forms"
Map-NetworkDrive S "\\USCG-FS-001v\Base Shared"
Map-NetworkDrive F "\\USCG-FS-001v\Official Files"
Map-NetworkDrive M "\\USCG-FS-001v\M Drive"
Map-NetworkDrive Q "\\USCG-FS-001v\HOME$\$env:Username"

#Prompt User to Update Account Information
Add-Type -AssemblyName Microsoft.VisualBasic
$result=[Microsoft.VisualBasic.Interaction]::Msgbox("Keep Professional Information Current. It is prudent that users periodically review their information to ensure their information is accurate. This is what will display in the GAL.  Select Authentication certificate when logging into AFDS and MilConnect.`n`nWould you like to update this information now?",'systemmodal,YesNo,Question',"Update User Information")
if($result -eq "Yes"){
    Start "https://milconnect.dmdc.osd.mil/milconnect/"
    Start "https://imp.afds.af.mil/Default.aspx"
}

#Run FBCA Removal Tool
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -WindowStyle Hidden -File '\\AREA52.AFNOAPPS.USAF.MIL\Salt_Lake_City\Logon_Scripts\RemoveFBCAv2.ps1'

#Filtering by groups also enabled here, though it should only be done if groups exist outside one specific unit
#================================
#*** Comm Flight BNCC Group ***
If("151 cf bncc" -in $groups)
{
Map-NetworkDrive N "\\USCG-FS-001v\NCC"
}

#*** Comm Flight Share ***
If("151 CF All Members" -in $groups)
{
Map-NetworkDrive O "\\USCG-FS-001v\CFT Administration"
}

#*** FalconView Users ***
If( ("151 og falconview users" -in $groups) -or ("151 ops" -in $groups) )
{
Map-NetworkDrive J "\\USCG-FS-001v\falconview map data"
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