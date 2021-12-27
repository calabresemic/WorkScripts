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

Function Run-Slides($File){
#Made for Holloman
    if(Test-Path $File){
        if(!(Test-Path "$env:APPDATA\Holloman")){New-Item -ItemType Directory -Path "$env:APPDATA\Holloman"}
        Copy-Item $File -Destination "$env:APPDATA\Holloman" -Force
        start powerpnt "/s `"$env:APPDATA\Holloman\$($File.Split('\')[-1])`""}
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

If("USG_49 MDG_All Personnel" -in $groups)
{
    Add-Type -AssemblyName Microsoft.VisualBasic
    $result=[Microsoft.VisualBasic.Interaction]::Msgbox("Have you accomplished your DMHRSI time card for the current period?",'systemmodal,YesNo,Question',"Defense Medical Human Resources System")
    if($result -eq "Yes"){
        #Open DMHRSi website
        start "https://dmhrsi.csd.disa.mil"

        #If it must be IE
        #$IE=new-object -com internetexplorer.application
        #$IE.navigate2("https://dmhrsi.csd.disa.mil")
        #$IE.visible=$true
    }
}