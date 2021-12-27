#================================
#Generic Powershell AFNET Unit Login Script
#Written By Andrew Metzger, 21 CS

#All Scripts need to match the folder name they are contained within
#Example: 21_CS folder, 21_CS.PS1 for the script name
#
#BASE:  Langley AFB

<# Revision History
9 Nov 2020 - Andrew Metzger (1034133855) - fixed drive mapping logic
10 Dec 2020 - Michael Calabrese (1468714589) - fixed drive unmapping logic
11 Dec 2020 - Michael Calabrese (1468714589) - added functions for IE favorites, Desktop shortcuts, Powerpoint presentations, desktop background changes
17 Dec 2020 - Michael Calabrese (1468714589) - fixed onedrive detection for shortcuts
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

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$office = $adobj.Properties.physicaldeliveryofficename
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#MAP DRIVES
#================================
# Replace the H in the example with the share drive letter your base uses
# Call the Map-NetworkDrive function as many times as needed to map multiple drives
# Map drives by calling the function with its parameters drive letter and UNC share path

#Map-NetworkDrive H "\\fileserver\sharename"

Switch($office){
    'CYOD' {Map-NetworkDrive O "\\ZHTX-BS-013v\CYOD"}
    'DOT'  {Map-NetworkDrive O "\\zhtx-bs-013v\Shared\DO\DOT"}
}

#MAP PRINTERS
#================================
# Map printers by calling the function with its parameter for UNC printer path
# Call the Map-Printers function as many times as needed to map multiple printers
# Replace printserver and printermapping with your base information

#Map-Printer "\\PrintServer\Printermapping"


#POP-UPS
#================================
# Call the pop-up function as many times as needed for multiple messages
# Replace "Popup Window title" and "Message" with your popup message information
# Display a popup by calling the function with its parameters window title and message

#Show-popup "Window title in quotes" "Message in quotes"


#SHOW POWERPOINT
#================================
# Display a powerpoint presentation
# Save the file in .ppsm format for best results

#Show-Powerpoint "\\pathtofile.ppsm"


#SET BACKGROUND
#================================
# Change the user's desktop background. This will add quite a bit of time to the logon script especially if you are not using a .bmp file.
# Recommend that you convery to .bmp if possible (use paint and then resave as .bmp)
# Read info in function above but there is an optional parameter for attempts it will take to refresh the background. Not required but useful if you are having issues with it not applying.

#Set-Background "\\pathtoimage.bmp" 
#Set-Background "\\pathtoimage.bmp" -attempts 15


#CREATE SHORTCUT
#================================
# Create a shortcut on the user's desktop
# Optional icon image can be specified if necessary or desired.
# Supports OneDrive desktops

#Create-Shortcut "shortcutname.lnk" "targetlocation" "iconfile"


#SET IE FAVORITES
#================================
# Replace $Name with the display Name for the shortcut, $Url with the full URL for the shortcut, and $location with the folder path where the shortcut will be saved.
# Call the Set-Favorites function as many times as needed to create multiple shortcuts
# Set favorites by calling the function with the Name, URL, and Folder path for the shortcut.  All shortcuts are stored in the Favorites folder by default

#Set-Favorites "Favorite Name" "URL address" "Favorites Folder"


#GROUP MEMBERSHIP SPECIFIC ACTIONS
#================================
# Add more groups by copying the information below
# Replace Groupname with security group name to target specific users
# Replace the H in the example with the share drive letter your base uses
# Replace printserver and printermapping with your base information
# Replace "Popup Window title" and "Message" with your popup message information

#If("Groupname" -in $groups)
#{
#Map-NetworkDrive H "\\fileserver\sharename"
#Map-Printer "\\PrintServer\Printermapping"
#Show-popup "Popup Window title" "Message"
#Show-Powerpoint "\\pathtofile.ppsm"
#Set-Background "\\pathtoimage.bmp"
#Create-Shortcut "shortcutname.lnk" "targetlocation" "iconfile"
#Set-Favorites "Favorite Name" "URL address" "Favorites Folder"
#}

If("GLS_83_NOS_CYOD_SHARE" -in $groups)
{
Map-NetworkDrive H "\\ZHTX-BS-013v\CYOD"
}
If("GLS_83_NOS_DOT_SHARE" -in $groups)
{
Map-NetworkDrive T "\\zhtx-bs-013v\Shared\DO\DOT"
}