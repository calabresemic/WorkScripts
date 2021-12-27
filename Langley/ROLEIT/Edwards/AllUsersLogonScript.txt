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

$stopwatch=[system.diagnostics.stopwatch]::StartNew()

#region Functions
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

#endregion Functions

#Revision History
<#
========================================================================================
========================================================================================
========================================================================================

Version
2.0.0  (14 Jan 21)     -Converted to Powershell
1.1.46 (29 Apr 20)     -Changed the variable strShortSAM from SamAccountName to objUser.EmployeeID for mapping Home Drives.
1.1.45 (14 Feb 20)     -Removed mappings for \\AFFTC-ABW\CE$ per ticket INC000025493466
1.1.44 (12 Jun 19)	   -Added a mapping for the Stingray share
1.1.43 (29 Oct 18)	   -Modified the ERM section to properly loop through the right number of groups.
1.1.42 (11 Sep 18)     -Added 812 AITS so the users will quit getting an error while logging in. No special mapping requirements were noted.
1.1.41 (19 Dec 17)	   -Removed the excess ERM lines since they have been commented out since 28 Jul 16.
			           -Searching for the new ERM groups ("E_" and "ER_") by adding an -or- to the compare statement
1.1.40 (13 Jun 17)     -Removed the group membership checking and started mapping drive V: to all users for access to the new share folder locations.
1.1.30 (26 Apr 17)     -Removed mapping for Civilian Personnel Office to the MssApps folder.
1.1.29 (24 Oct 16)	   -Added section to map to new TW server for COMM.
1.1.28 (12 Sep 16)	   -Fixed an issue where if a user wasnt in any groups, the script wouldnt finish.
1.1.27 (25 Aug 16)	   -Removed code for mapping to the old home drive server.
			           -The script is now creating a shortcut on the desktop to the home drive (experimental).
			           -Added more aggressive drive H: deletion before mapping to the new location.
1.1.26 (28 Jul 16)	   -Modified the ERM section to deal with the new way ERM shortcuts have to be created.
			           -Removed the check to see if "foldername.txt" exists in the ERM section. With so many problems about that file, it is no longer incorperated.
1.1.25 (25 Jul 16)	   -Mapping the home drives now checks to see if the home drive exists in the new location and maps it there. If not, it still maps it to the old location
			           -Updated some troubleshooting log file information.
1.1.24 (18 Jul 16)	   -The logon script now checks the new home drive location and if the folder is there, maps to it. If not, it maps to the old location.
1.1.23 (8 Jul 16)	   -Added a routine to map the to the new home drive location using EDIPI instead of the user name.
1.1.22 (4 Mar 16)	   -Change PK mappings from FPFSPM200 to FSPM-AS-007v due to a server migration.
1.1.21 (11 Fev 16)	   -Removed the legacy ERM logic.
			           -Optimized the home drive logic to break out of the loop when it maps the home drive.
			           -The logon script completes 9 seconds faster.	
1.1.20 (10 Dec 15)	   -Added section 6a to turn email encryption on by default.
1.1.19 (23 Mar 15)	   -Made requested changes for 416 FLTS at line 624.
1.1.18	(10 Dec 14)	   -Modified some of the locations for mapping drives to the BFTF users.
				       -Corrected a folder location that was named "Excellis" to "Exelis"
				       -Added mapping drive P: for the "pdat" folder
1.1.17	(9 Sep 14)	   -Changed drive mappings for BFTF due to afftc-0145-s2 server being decommissioned. Shares are now on AFFTC-BFTF.
1.1.16		-Added strUserLast and strUserFirst Variable to fix minor bug with mapping Home Drives.
			-Enabled Home drive mapping for Logon-PK (6/20/2014)
			-Placed testing of Adobe PDF Project 84 request on hold
			-Re-enabled ERM Mapping to new server. All ERM mapping will now go to \\52fspm-fs-001v\ERM$\
			-Added Notification for executing org scripts (this does not show if the org script was executed from the kicker script)
1.1.15		-Project 84 has requested that at logon the default printer should be set to Adobe PDF.
1.1.14		-Added 31 TES File Migration to call the migration .vbs
			-This needs to be removed in few months (added on 12/2/2013)
			-Added Output for ARFL home drive users to notify no action was taken.
			-Added Section 5b AtHoc Info Update.exe Requested per Sgt Zamzow (12/2/2013)
1.1.13		-Increased Home Drive looping from 7 to 9. Now we can create up to 9 home drives for same named users. (Usable Numbers: <Blank>,2,3,4,5,6,7,8,9)
			-Revamped Mapping Sub/Functions:	Removed and Updated Sub		MapDrive(strLetter, strUNC) 2.0
												Added Supporting Function	Verify_Mapping(strLetter, strUNC)
												Added Supporting Sub		Change_strLetter(strLetter)
			-Mapping will now alternate letters to map drives instead of just over mapping them.
			-Mapping will no longer map if there is an existing map. Even if the mapping is on different letter.
			-Added loop stopper if user has a full map. This will stop script from infinite loop for those users.
1.1.12		-Restructured naming convention for writing logs. it will now be from "<Last> <First>.txt" to "<Last> <First> <EDI>.log" (Affects User logs and Troubleshoot Logs)
			-Removed G drive mapping form the group "AFFTC-History" (HILL Remedy INC000001017219)
			-Modified Mapping for Group "LOGON-MXG" from "G:\\AFFTC-TW\MXG$" to "G:\\AFFTC-TW\MOS$"
			-Created section 8e: Mapping DLS_412 CS_LOGON-EDWTest. For 412CS Dev Testing
			-Added persistently map to all objNetwork.MapNetworkDrive commands. Due to VPN Login does not hit this Logon Script.
1.1.11		-Fixed minor bug with org script when they are in multiple orgs. Never cleared the strScriptPath variable
			-Modified Mapping for Group "LOGON-MXG" from "L:\\AFFTC-TW\MOS$" to "L:\\AFFTC-TW\MXG$" per Stephen Shapiro (EITSM Remedy INC000003957622)
			-Modified Mapping for Group "AFFTC_SPS_BLOTTERS" from "M: \\AFFTC-ABW\SFS_Blotters$" to "M: \\AFFTC-ABW\SFS_Blotters2$" Research shows on AFFTC-ABW Share is incorrectly named.
			-Modified Mapping for Group "703AESG-Det3-ALL" from "S: \\AFFTC-DET\703AESG-DET3" to "S: \\AFFTC-DET\AFLCMC-DET3" Re-Enabled because Research shows on AFFTC-DET Share is incorrectly named.
			-Added Mapping for Group "LOGON-416FLTS" to "N: \\rcp-sb01\F16_projects"
			-Removed Mapping for Group "AFFTC_SPS_SPR" 			to	G: Drive "\\AFFTC-ABW\SFS_SFR$"			-Location does not Exist
			-Removed Mapping for Group "AFFTC_SPS_SPAS" 			to	G: Drive "\\AFFTC-ABW\SFS_SFA$"			-Location does not Exist
			-Removed Mapping for Group "USERS_BFTF_HD" 			to	J: Drive "\\afftc-0145-f3\adminvol$"		-Location does not Exist
			-Removed Mapping for Group "USERS_BFTF_HWMNT" 			to	J: Drive "\\afftc-0145-f3\adminvol$"		-Location does not Exist
			-Removed Mapping for Group "USERS_BFTF_SYSTEMS" 		to	J: Drive "\\afftc-0145-f3\adminvol$"		-Location does not Exist
1.1.10		-Turned off Notification on Mapping
			-Recreated Home Drive Mapping Section with a Loop and Local Drive If/Then to avoid errors. (Will no longer pushes out errors for every attempt)(Will no longer use MapDrive Function)
			-Added If statement to strUserID for org accounts due to log names being blank
			-Added Fix to local drives conflicting when mapping in MapDrives Function
			-Added If/Then to ERM section to change the group CNTR-ERM-RW to CNTR-ERM--RW for parsing issues.
			-Added LCase() to force CScript section to avoid case sensitive calling of the script
			-Moved mapping for "LOGON-412TW" after "LOGON-TESTOPS" due to mapping order
			-Removed Duplicate Mapping for HRD_Students to "\\dpcnt95\Instructor$"
			-Removed Duplicate Mapping for 95SFS-SFA to "\\afftc-abw\SFA$"
			-Modified Mapping for Group "LOGON-MXMD" from "G:\\AFFTC-TW\CMS$" to "G:\\afftc-tw\mxg$\MXMD\MXMD" per Caleb Hill (EITSM Remedy INC0000003964213)
			-Modified Mapping for Group "LOGON-CMS" From "G:\\AFFTC-TW\CMS$" to "G:\\afftc-tw\mxg$\MXMD\MXMD"	per Caleb Hill (EITSM Remedy INC0000003964213)
			-Removed Mapping for Group "LOGON-TRENTECH4"			to	T: Drive "\\badgeserver\Trentech4"	-No longer supported
			-Removed Mapping for Group "AFFTC-IT-611-LSO"			to	X: Drive "\\AFFTC-CENTER\611_Data"	-Location does not Exist
			-Removed Mapping for Group "Child Development Center" 	to	F: Drive "\\edw93977\c.procare"		-Location does not Exist
			-Removed Mapping for Group "703AESG-Det3-ALL"			to	S: Drive "\\AFFTC-DET\703AESG-DET3"	-Location does not Exist
			-Removed Mapping for Group "UG-AFFTC-FM-TRAVEL"			to	I: Drive "\\MISFM01\IATS50"			-Location does not Exist
			-Removed Mapping for Group "DMOMPF"						to	R: Drive "\\leave\dmoinput"			-Location does not Exist
			-Removed Mapping for Group "DMOMPF"						to	S: Drive "\\leave\dmodata"			-Location does not Exist
			-Removed Mapping for Group "LOGON-FM-DMO"				to	R: Drive "\\leave\dmoinput"			-Location does not Exist
			-Removed Mapping for Group "LOGON-FM-DMO"				to	S: Drive "\\leave\dmodata"			-Location does not Exist
1.1.09		-Temp Removed ERM due to Migration Issues
			-Fixed Enumerate Groups per David Daniel with "dc=edwards" to "dc=area52"
			-Removed "C:\Logon Script\Logon Script.log" loggin in the pre-Script section
			-Removed "Logon-TPS" mapping for Z drive "\\afftc-tps\scripts$" per Lewis Daffron
			-Temp Added On Error Resume Next to test diag
1.1.08		-Moved Group list Above the script to make diagnosing easier because when script fails that information is not there.
			-Added Possible fix for EDW home page link from objFSO.CopyFile to Wscript Shell to create shortcut due to unknown failure. (Fix LOGON-418FLTS objFSO.CopyFile if this fixes edw copy file)
			-Fixed Final Message to display something when Blank
			-Added Delayed User Mappings in Troubleshoot log to show Mapping for this script and org script
			-Edited out some of 416FLTS requests per Ed Skochinski/Greg Moss
			-Fixed Minor issue with ERM
1.1.07		-Added Wksta and User logs to Troubleshoot log to make it easier to diagnose
			-Fixed Minor Issue with Home Drive Mapping to users such as "Van Lastname Firstname" being mapped as "Van2 Lastname Firstname" to "Van Lastname2 Firstname"
1.1.06		-Updated Cleanup Function
			-HOME DRIVE MAPPING: EDI <- Lastname Firstname issue Temp fix
			-Added more delay to mapping of drives (from 1 mSec to 5mSec)
1.1.05		-Added Logging to ERM in Troubleshooting.logs
			-Changed shortcut name to have Long File Name instead of Short File Name
			-Added If... Then... to mapping drives to check if UNC exists
			-Removed mapping for Group "AFFTC-ITCA-MMT" -> "I:\\FPFSPM14\AudioVisual" Path does not exist
			-Removed mapping for Group "Logon-EM" and moved to Org Script	per Timothy Ferrill
			-Created "Logon -EM" in Section 8d for Org Script Calling
			-Fixed Org Script Calling from wrong varriables to fixed org script location
1.1.04		-Added Log feature to debug problems
			-Added End of Script Notification
1.1.03		-Fixed username issue where AFNet has changed it to numbers.
			-Removed objWSH. Dupilcate Wscript.Shell object
			-Add Log File Locations in Table of contents
1.1.02		-Added section to make sure org scripts are called. If they are in ORG Logon Group but not in ORG by "o" attribute.
			412CE, 412MED, TPS, AFRL
1.1.01		-Moved Logs to end of the script
			-Added script to \\area52.afnoapps.us.af.mil\edwards_afb\logon_scripts\edwardsalluserlogonscript.vbs
1.1.00		-Added EnumerateGroups to open Active Directory once instead of many time in Mapping of Home Drive Section
1.0.00	


========================================================================================
========================================================================================
========================================================================================
 TABLE OF CONTENT
	 1		Variable Declaration/Definition
	 2		Initialize System Objects
	 3		Enumerate Groups
	 4		Collect User Account Information
	 5a		Runs BGInfo.exe
	 5b		Runs Requested Popups
	 6		Enable HTTP 1.1 On Proxy and Override Local HTTP Addresses and Add Title
	 7		Write Jinitiator Registry Keys
	 8a		Mapping of Home Drive
	 8b		Mapping of ERM
	 8c		Mapping Drives
	 8d		Mapping Drives for LOGON-ORG groups
	 8e		Mapping DLS_412 CS_LOGON-EDWTest
	 9		Desktop Shortcut for Concerto Users
	10		Desktop Shortcut for Edwards.Af.Mil
	11		Logs User Logon History
	12		Logs Workstation Logon History
	13		Cleanup and End of Script

 LOG FILE LOCATIONS
 Logon Output(User)			\\AFFTC-LOGON\NETLOGON\queues\last\logon\history\USErs\<Lastname> <Firstname>(<sAMAccountName>).log
 Logon Output(WKSTA)			\\AFFTC-LOGON\NETLOGON\queues\last\logon\history\computers\<strWKSTA>.txt
 Logon Diagnostic(User)		\\AFFTC-LOGON\NETLOGON\queues\last\logon\history\Troubleshooting\<Lastname> <Firstname>(<sAMAccountName>).log
#>

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$Userfirst = $Adobj.properties.givenname
$Userlast = $Adobj.properties.sn
$UserID = "$Userlast $Userfirst"
$sAMAccountName = $env:Username
[string]$ShortSam = $sAMAccountName.Substring(0,10)
[int]$LastTwo = $ShortSam.Substring(8,2)
$EmpType = $Adobj.properties.employeetype
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$cn = $Adobj.properties.cn
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

$HomeServer  = "fspm-fs-017v"
#$HomeServer  = "129.198.203.74"
$ERMServer   = "fspm-fs-016v"
#$ERMServer   = "129.198.203.75"
$LogonServer = "fspm-fs-035v"
#$LogonServer = "129.198.204.161"
$TWServer    = "fspm-fs-020v"
#$TWServer    = "129.198.203.238"

if($sAMAccountName -like "*.adm"){$EmpType = ".adm"}
if($sAMAccountName -like "*.adf"){$EmpType = ".adf"}
if($sAMAccountName -like "*.adw"){$EmpType = ".adw"}

$logpath="\\$LogonServer\NETLOGON$\Logs\Troubleshooting\$UserID($ShortSam$EmpType).log"
New-Item -Path $logpath -ItemType File -Force

"=========================================================================" >> $logpath
" Edwards AFB BASEAllUserLoginScript.ps1		$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")" >> $logpath
" 				$UserID($sAMAccountName)" >> $logpath
"=========================================================================" >> $logpath
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]00  Starting Edwards AFB BASEAllUserLoginScript.ps1" >> $logpath
#========================================================================================
# 1		Variable Declaration/Definition
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]01  Variable Declaration/Definition COMPLETE!" >> $logpath
#========================================================================================
# 2		Initialize System Objects
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]02  Initialize System Objects COMPLETE!" >> $logpath
#========================================================================================
# 3		Enumerate Groups
#========================================================================================
foreach($group in $groups){"		$group" >> $logpath}
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]03  Enumerate Groups COMPLETE!" >> $logpath
#========================================================================================
# 4		Collect User Account Information
#========================================================================================
#Gets IP, MAC, Subnet of User's Workstation
$NetAdapter=Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.MACAddress -ne $null}
$IP = $NetAdapter.IPAddress -join ","
$MAC = $NetAdapter.MACAddress  -join ","
$Subnet = $IP.Split(".")[2]

#Gets Date/Time, UserID, WkstaName, OSver, User's Drives
$DateTime=Get-Date -Format "M/d/yyyy HH:mm:ss tt"
$WKSTA = $env:COMPUTERNAME
$ProductName=Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName" | select -ExpandProperty ProductName
$CurrentVersion=Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentVersion" | select -ExpandProperty CurrentVersion
$CurrentBuild=Get-ItemProperty "Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild" | select -ExpandProperty CurrentBuild
$OSVer = "$ProductName $CurrentVersion Build $CurrentBuild"
$Drives = Get-CimInstance Win32_LogicalDisk
$DrivesInfo=@()
    Foreach($Drive in $Drives){
        Switch ($Drive.DriveType){
            0 {$DriveValue = "Unknown Drive"}
            1 {$DriveValue = "No Root Directory"}
			2 {$DriveValue = "Removable Drive"}
			3 {$DriveValue = "Fixed Drive"}
			4 {$DriveValue = $Drive.ProviderName}
			5 {$DriveValue = "Optical Drive"}
			6 {$DriveValue = "RAM Drive"}
            }
    
    $DrivesInfo+="$($Drive.DeviceID.trim(':'))=$($DriveValue)"
    }
$Drives=$DrivesInfo -join ","
$Desktop = [Environment]::GetFolderPath("Desktop")

"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]04  Collect User Account Information COMPLETE!" >> $logpath
#========================================================================================
# 5a		Runs BGInfo.exe
#========================================================================================

#Notes: This hasn't worked since AFNET Migration

"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]05a Runs BGInfo.exe COMPLETE!" >> $logpath
#========================================================================================
# 5b		Runs Requested Popups
#========================================================================================

#Notes: These are commented out

"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]05b Runs Requested Popups COMPLETE!" >> $logpath
#========================================================================================
# 6		Enable HTTP 1.1 On Proxy and Override Local HTTP Addresses and Add Title
#========================================================================================
Set-RegistryValue -Path "HKCU:\SOFTWARE\MICROSOFT\WINDOWS\CurrentVersion\Internet Settings" -Name "ProxyHttp1.1" -Value 1 -PropertyType DWORD
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "Window Title" -Value "You can reach the Support Center at 7-3444!" -PropertyType String

"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]06  Enable HTTP 1.1 On Proxy and Override Local HTTP Addresses and Add Title COMPLETE!" >> $logpath
#========================================================================================
# 7		Write Jinitiator Registry Keys
#========================================================================================
#$path1="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\af.mil"
#$path2="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"

#Set-RegistryValue -Path $path1 -Name "jocas2.edwards" -Value 2 -PropertyType DWORD
#Set-RegistryValue -Path $path1 -Name "jocas2b.edwards" -Value 2 -PropertyType DWORD
#Set-RegistryValue -Path $path1 -Name "jocas2p.edwards" -Value 2 -PropertyType DWORD
#Set-RegistryValue -Path $path1 -Name "misjapps01.edwards" -Value 2 -PropertyType DWORD
#Set-RegistryValue -Path $path1 -Name "misjapps02.edwards" -Value 2 -PropertyType DWORD
#Set-RegistryValue -Path $path2 -Name "21004" -Value 1 -PropertyType DWORD
#Set-RegistryValue -Path $path2 -Name "21A04" -Value 3 -PropertyType DWORD

#"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]07  Write Jinitiator Registry Keys COMPLETE!" >> $logpath
#========================================================================================
# 8a	Mapping of Home Drive
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08a Begin Home Drive Mapping" >> $logpath

# Build Home Folder Mapping to NetAPP storage.
"		Short SAM Name = $ShortSam" >> $logpath
"		LastTwo = $LastTwo" >> $logpath

if($LastTwo -ge 0 -and $LastTwo -le 9){$HomeFolderName = "00"}
elseif($LastTwo -ge 10 -and $LastTwo -le 19){$HomeFolderName = "10"}
elseif($LastTwo -ge 20 -and $LastTwo -le 29){$HomeFolderName = "20"}
elseif($LastTwo -ge 30 -and $LastTwo -le 39){$HomeFolderName = "30"}
elseif($LastTwo -ge 40 -and $LastTwo -le 49){$HomeFolderName = "40"}
elseif($LastTwo -ge 50 -and $LastTwo -le 59){$HomeFolderName = "50"}
elseif($LastTwo -ge 60 -and $LastTwo -le 69){$HomeFolderName = "60"}
elseif($LastTwo -ge 70 -and $LastTwo -le 79){$HomeFolderName = "70"}
elseif($LastTwo -ge 80 -and $LastTwo -le 89){$HomeFolderName = "80"}
elseif($LastTwo -ge 90 -and $LastTwo -le 99){$HomeFolderName = "90"}

"		[$HomeFolderName] Is the folder name" >> $logpath
"		[\\$HomeServer\Home$\$HomeFolderName\$ShortSam] Is the home folder" >> $logpath
"		Mapping [H:] \\$HomeServer\Home$\$HomeFolderName\$ShortSam" >> $logpath

Map-NetworkDrive H "\\$HomeServer\Home$\$HomeFolderName\$ShortSam"

if((Get-PSDrive H).Root -ne "\\$HomeServer\Home$\$HomeFolderName\$ShortSam"){"		 ERROR Path Not Found [H:] Home Drive Folder NOT Found" >> $logpath}
	
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08a Mapping of Home Drive COMPLETE!" >> $logpath
#========================================================================================
# 8b	Mapping of ERM
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08b Begin ERM Mapping" >> $logpath
"		Checking for Existing Desktop ERM Folder" >> $logpath
Remove-Item "$Desktop\ERM" -Force -ErrorAction SilentlyContinue
"		Building a list of groups" >> $logpath
"		User is in $($groups.count) Security Groups" >> $logpath
"		Checking for ERM groups" >> $logpath

foreach($group in $groups){
    if( ($group -like "DLS_412 CS_E_*") -or ($group -like "E_*") -or ($group -like "ER_*") ){

        if(!(Test-Path "$Desktop\ERM")){New-Item "$Desktop\ERM" -ItemType Directory}
        $groupobj = ([adsisearcher]"Samaccountname=$group").findone()
        $description = $groupobj.properties.description

        if($description -match 'inbox'){ 
            #Check to see if this is the inbox folder, and change "inbox" to "00-ELE~1"
            $ERMPath00 = "\\$ERMServer\ERM$"+$description -replace "inbox","00-ELE~1"
            $ERMName00 = "$($group)0"

            #For 01 folder. (All mapping with \inbox as last folder path will also get \01 folder.)
            $ERMPath01 = "\\$ERMServer\ERM$"+$description -replace "inbox","01-FIL~1"
            $ERMName01 = "$($group)1"

            "		Creating ERM Shortcut for [$group] $ERMPath00" >> $logpath
            Create-Shortcut -name "\ERM\$($ERMName00).lnk" -target $ERMPath00
            "		Creating ERM Shortcut for [$group] $ERMPath01" >> $logpath
            Create-Shortcut -name "\ERM\$($ERMName01).lnk" -target $ERMPath01
            }
        else{
            $ERMPath = "\\$ERMServer\ERM$"+$description
            $ERMName = $group
            "		Creating ERM Shortcut for [$group] $ERMPath" >> $logpath
            Create-Shortcut -name "\ERM\$($ERMName).lnk" -target $ERMPath
            }
        }
    }
        
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08b Mapping of ERM COMPLETE!" >> $logpath
#========================================================================================
# 8c	Mapping Drives
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08c Begin Drive Mapping" >> $logpath

If("UG-DET1-ALL" -in $groups)
{
Map-NetworkDrive V "\\fspm-fs-031v\PL42$\Index"
}
If("LOGON_412FLTS" -in $groups)
{
Map-NetworkDrive G "\\AFFTC-TW\412OSS$"
Map-NetworkDrive I "\\AFFTC-TW\412FLTS$"
}
If("LOGON-416FLTS" -in $groups)
{
Map-NetworkDrive M "\\fspm-fs-edc4pv\F16_Engineering"
Map-NetworkDrive N "\\fspm-fs-edc4pv\F16_projects"
Map-NetworkDrive S "\\fspm-fs-015v\416flts$"
    If("UG-416FLTS-F15SA-RW" -in $groups)
    {
    Map-NetworkDrive T "\\52FSPM-FS-ED01P\DATA"
    Map-NetworkDrive U "\\52FSPM-FS-ED01P\ENGINEERING"
    Map-NetworkDrive V "\\52FSPM-FS-ED01P\ADMIN"
    }
}


"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08c Mapping Drives COMPLETE!" >> $logpath
#========================================================================================
# 8d	Mapping Drives for LOGON-ORG groups
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08d Begin Mapping Drives for LOGON-ORG groups" >> $logpath
#This part of the script will call the user's ORG scripts if it exist.
#This part specifically for Matrixed Users who do not hold the organization value on their account but are in the organization’s Logon Group.
$scriptpath="\\area52.afnoapps.usaf.mil\$l\logon_scripts"
"		Org Logon Script [$scriptpath\$o\$o.ps1] " >> $logpath

    #GROUP: LOGON-CE, LOGON-EM Logon Script
	#ORG:	412_TW
	#POC:	Timothy Ferrill
If( ("LOGON-CE" -in $groups) -or ("LOGON-EM" -in $groups) -and ($o -ne "412_tw"))
{
"		Executing 412CE Script" >> $logpath
Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file "$scriptpath\412_tw\412_tw.ps1"
}

    #GROUP: LOGON-TPS
	#ORG:	USAF_TPS
	#POC:	Lewis Daffron
If( ("LOGON-TPS" -in $groups) -and ($o -ne "usaf_tps"))
{
"		Executing TPS Org Script" >> $logpath
Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file "$scriptpath\usaf_tps\usaf_tps.ps1"
}

"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08d Mapping Drives for LOGON-ORG groups COMPLETE!"
#========================================================================================
# 8e	Mapping DLS_412 CS_LOGON-EDWTest
#========================================================================================
	#Deticated Test Group for logon script modifications
If("DLS_412 CS_LOGON-EDWTest" -in $groups)
{
"     User is part of the LOGON-EDWTest Group. Running Test Script" >> $logpath
}
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]08e Mapping DLS_412 CS_LOGON-EDWTest groups COMPLETE!" >> $logpath
#========================================================================================
# 9		Desktop Shortcut for Concerto Users
#========================================================================================
If("Concerto_Share_Users" -in $groups)
{	
Create-Shortcut -name "Concerto Share.lnk" -target "\\afftc-tw\concerto\concerto share"
}
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]09  Desktop Shortcut for Concerto Users COMPLETE!" >> $logpath
#========================================================================================
# 10	Desktop Shortcut for Edwards.Af.Mil
#========================================================================================
#Create-Shortcut -name "Edwards Home Page.lnk" -target "http://www.edwards.af.mil/" -icon "\\$LogonServer\netlogon$\link_related\EAFB.ico"
	
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]10  Desktop Shortcut for Edwards.Af.Mil SKIPPED!"  >> $logpath
#========================================================================================
# 11	Logs User Logon History
#========================================================================================
$userlog="\\$LogonServer\NETLOGON$\Logs\Users\$UserID($ShortSam$EmpType).txt"
"$DateTime|$UserID|$WKSTA|$OSVer|$IP|$MAC|$Drives" >> $userlog
"		$DateTime|$UserID|$WKSTA|$OSVer|$IP|$MAC|$Drives" >> $logpath
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]11  Logs User Logon History COMPLETE!" >> $logpath
#========================================================================================
# 12	Logs Workstation Logon History
#========================================================================================
$workstationlog="\\$LogonServer\NETLOGON$\Logs\Computers\$WKSTA.txt"
"$DateTime|$UserID|$WKSTA|$OSVer|$IP|$MAC|$Drives" >> $workstationlog
"		$DateTime|$UserID|$WKSTA|$OSVer|$IP|$MAC|$Drives" >> $logpath
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]12  Logs Workstation Logon History COMPLETE!" >> $logpath
#========================================================================================
# 13	Cleanup and End of Script
#========================================================================================
"[$(Get-Date -Format "M/d/yyyy HH:mm:ss tt")]XX  BASEAllUserLoginScript.vbs COMPLETE!" >> $logpath
"" >> $logpath
"" >> $logpath
"" >> $logpath
"" >> $logpath
	
#End of Script Notification
	
#ScriptTimer to display Run-time in the Log
$Miliseconds = $stopwatch.Elapsed.Milliseconds
$Seconds = $stopwatch.Elapsed.Seconds
$Minutes = $stopwatch.Elapsed.Minutes
"=========================================================================" >> $logpath
" BASEAllUserLoginScript.ps1 Run-Time: $($Minutes):$($Seconds):$($Miliseconds)" >> $logpath
"=========================================================================" >> $logpath
" $Minutes Minutes" >> $logpath
" $Seconds Seconds" >> $logpath
" $Miliseconds Miliseconds" >> $logpath
"" >> $logpath
"=========================================================================" >> $logpath
"FINISHED LOGON SCRIPT" >> $logpath

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