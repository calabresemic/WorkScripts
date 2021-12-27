#================================
#Generic Powershell AFNET Unit Login Script
#Written By Andrew Metzger, 21 CS

#All Scripts need to match the folder name they are contained within
#Example: 21_CS folder, 21_CS.PS1 for the script name
#
#BASE:  Replace with Base Name
#
#9 Nov 2020 - fixed drive mapping logic
#10 Dec 2020 - fixed drive unmapping logic


#SET VARIABLES
#================================

$adobj = ([adsisearcher]"Samaccountname=$env:username").findone()
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}


#LOAD FUNCTIONS
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
    $application = New-Object -ComObject powerpoint.application
    $presentation = $application.Presentations.open($filepath)
    $application.visible = "msoTrue"
    $presentation.SlideShowSettings.Run()
    }
}


#MAP DRIVES
#================================
# Replace the H in the example with the share drive letter your base uses
# Call the Map-NetworkDrive function as many times as needed to map multiple drives
# Map drives by calling the function with its parameters drive letter and UNC share path

#Map-NetworkDrive H "\\fileserver\sharename"

Map-NetworkDrive H "\\aggn-fs-001p\97CS"
Map-NetworkDrive I "\\aggn-fs-001p\97CS\Flights\SCO"
Map-NetworkDrive J "\\aggn-fs-001p\97CS\Flights\SCX"

#MAP PRINTERS
#================================
#map printers by calling the function with its parameter for UNC printer path
# Call the Map-Printers function as many times as needed to map multiple printers
# Replace printserver and printermapping with your base information


#Map-Printer "\\PrintServer\Printermapping"



#POP-UPS
#================================
# Call the pop-up function as many times as needed for multiple messages
# Replace "Popup Window title" and "Message" with your popup message information
# Display a popup by calling the function with its parameters window title and message


#Show-popup "Window title in quotes" "Message in quotes"



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




