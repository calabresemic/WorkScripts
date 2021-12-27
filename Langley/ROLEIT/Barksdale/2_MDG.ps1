#================================
#Generic Powershell AFNET Unit Login Script
#Written By Andrew Metzger, 21 CS

#All Scripts need to match the folder name they are contained within
#Example: 21_CS folder, 21_CS.PS1 for the script name
#
#BASE:  Replace with Base Name

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
$groups = ((([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.AccountDomainSid -ne $null}).Translate([System.Security.Principal.NTAccount])).value | Select-Object -Unique).replace('AREA52\','')

#MAP DRIVES
#================================
# Replace the H in the example with the share drive letter your base uses
# Call the Map-NetworkDrive function as many times as needed to map multiple drives
# Map drives by calling the function with its parameters drive letter and UNC share path

#Map-NetworkDrive H "\\fileserver\sharename"
Map-NetworkDrive G '\\AWUBFS01.med.ds.osd.mil\Dept$\2MDG_2MDG'
Map-NetworkDrive O '\\AWUBFS01.med.ds.osd.mil\Dept$\2MDG_Public'


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
Show-Popup -WindowTitle "Map Drives" -Message "Drive Mapping Complete"

#SHOW POWERPOINT
#================================
# Display a powerpoint presentation
# Save the file in .ppsm format for best results

#Show-Powerpoint "\\pathtofile.ppsm"

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