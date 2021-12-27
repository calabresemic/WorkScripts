<#
--------
McChord Logon Script
Author: A1C Daniel Scheiter 627 CS/SCOO 
--------
Edit Log
You MUST write here the date, and your full name as well as a detailed descript of what you changed
Jan 27 2021 | Removed all nested drive mappings, Fixed bug with print server popup, Fixed bug with logging
Jan 28 2012 | Michael Calabrese | cleaned up some functions


--------
#Popup tutorial

#!IMPORTANT! The Popups need to be put at the very end of the script or it will interrupt the rest of script.

#It's pretty simple to make a popup, all you need is to define the title of the popup then the text necessary then run popup. The text inputted will be formatted the same in the popup as you see it written.

#An example is this:

$title = 
"Title goes here"

$text = "text goes here"

popup
#>

#--------
#Define Functions


#Check if the group given is inside of the list of groups that the user is in
function IsMemberOf ($group) {
    $return = $UserGroups -contains $Group
    return $return
}

#takes input of drive letter and share name and maps it unless it is already mapped then it unmaps the current one and remaps it
Function Map-NetworkDrive($driveletter,$path,$sharename)
{
	if($driveletter -in (get-psdrive).name)
	{
		if((Get-PSDrive $driveletter).Root -ne $path){
            Remove-PSDrive -name $driveletter
            net use "$($driveletter):" /DELETE
            Remove-SmbMapping "$($driveletter):" -Force -UpdateProfile -ErrorAction SilentlyContinue
		    New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
            }
        else{"Drive already mapped correctly"}
	}
	Else
	{
		New-PSDrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global
	}
}

#takes input at the end of the script and puts a popup 
function popup($title,$text) {
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup(($text -join "`r`n"),0,$title,0)
}

function set-shortcut ( [string]$shortCutPath, [string]$targetPath ) {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortCutPath)
    $Shortcut.TargetPath = $targetPath
    $Shortcut.Save()
}

#--------
#Gather info and log it

#Get User Info about the current user
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$UserInfo = $adobj.Properties
#Parse UserInfo to get the user's groups
$UserGroups = $UserInfo.memberof | %{$_.split("=")[1].split(",")[0]}


#Create object with all the information that needs to be logged
$NetAdapter=Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true -and $_.MACAddress -ne $null}
$IP = $NetAdapter.IPAddress -join ","
$MAC = $NetAdapter.MACAddress  -join ","

$LoginInfo = [pscustomobject]@{
    Date = Get-Date
    Time = Get-Date -Format "HH:mm" -DisplayHint Time
    UserID = $userInfo.gigid
    DisplayName = $UserInfo.displayname
    Email = $UserInfo.mail
    Base = $UserInfo.l
    DSN = $UserInfo.telephonenumber
    Squadron = $UserInfo.o
    IPAddress = $IP
    MacAddress = $MAC
}

$LoginInfo | Export-Csv -Path "\\pqwy-cl01-02v\popups`$\UserLog\$env:computername.csv" -NoTypeInformation -Append

#Getting oldest date that logs should be kept by
$maxage = (Get-Date).AddDays(-30)
#Checking the logs to make sure there isn't any older than 30 days
$csvinfo = Import-Csv "\\pqwy-cl01-02v\popups`$\UserLog\$env:computername.csv" | Where-Object { [DateTime]$_.'Date' -ge $maxage }
$csvinfo | Export-Csv -Path "\\pqwy-cl01-02v\popups`$\UserLog\$env:computername.csv" -NoType


#add Skype to startup folder if it doesn't exist yet
if (-not [System.IO.File]::Exists("$($env:USERPROFILE)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Skype for Business 2016.lnk")) {
    set-shortcut "$($env:USERPROFILE)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Skype for Business 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Skype for Business 2016.lnk"
}
#if OneDrive is not setup, run it
if (-not $env:OneDrive) { Start-Process -FilePath ("$env:USERPROFILE\AppData\Local\Microsoft\OneDrive\OneDrive.exe")}

#--------
#Drive Mappings

#627 CS
If ((IsMemberOf("627 CS_USERS")) -or (IsMemberOf("627CS_USERS"))) {
#	Map-NetworkDrive "G" "\\pqwy-cl01-02v\msg"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\McChord\627 ABG\627 CS\627 CS Dropbox"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\627 cs"

}

#627 CES
If ((IsMemberOf("GLS_627 CES_Users")) -or (IsMemberOf("627 CES_USERS"))) {
	Map-NetworkDrive "H" "\\pqwy-cl01-02v\627 CES\CES Apps"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\627 CES\common"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\627 CES"
	#Map-NetworkDrive "L" "\\pqyyw3ce01\ENGINEERS\CADDRAW"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\McChord\627 ABG\627 CES"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Computer Support"

}


#62 CONS
If ((IsMemberOf("62cons users")) -or (IsMemberOf("62CONS_USERS"))) {
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\627 ABG\627 cons"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\CONS"
	#Map-NetworkDrive "Q" "\\CONS-SPS3-0324T\SPSBOOKS"
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\msg"
}


#62 FSS
If ((IsMemberOf("62FSS USERS")) -or (IsMemberOf("627 FSS USERS")) -or (IsMemberOf("627FSS USERS")) -or (IsMemberOf("627FSS_USERS"))){
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\627 FSS"
	#Map-NetworkDrive "K" "\\pqwy-cl01-02v\mss"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\common"
	#Map-NetworkDrive "M" "\\pqwy-cl01-02v\msg"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\McChord\627 ABG\627 FSS\627 FSS Dropbox"
	#Map-NetworkDrive "S" "\\pqwy-cl01-02v\svs"
}	

If ((IsMemberOf("627 FSS IT Admins SG"))) {
	Map-NetworkDrive "W" "\\pqwy-cl01-02v\Administration"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Applications"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Patch Management"
}
	
If ((IsMemberOf("627 FSS CPO Users"))) {
	#Map-NetworkDrive "T" "\\pqwy-cl01-02v\mss\cpo"
}
	

#627 LRS
If ((IsMemberOf("GLS_627 LRS_USERS")) -or (IsMemberOf("627LRS_USERS"))) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\msg"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\common"
	#Map-NetworkDrive "N" "\\lg_cdtower\epl"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\McChord\627 ABG\627 LRS\627 LRS Dropbox"
	#Map-NetworkDrive "Q" "\\pqyy3lgnts03\sats"
	#Map-NetworkDrive "R" "\\mxgcd1\fedlog"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\627 LRS"
	Map-NetworkDrive "V" "\\pqwy-cl01-02v\627 LRS\Norcom"
}


#627 ABG
If ((IsMemberOf("627abg_cc")) -or (IsMemberOf("627abg_leadership")) -or (IsMemberOf("627abg_ccea")) -or (IsMemberOf("627abg_igi"))) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\msg"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\McChord\627 ABG\627 ABG\627 ABG Dropbox"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\627 ABG"
}


#627 SFS
If ((IsMemberOf("627SFS_Users")) -or (IsMemberOf("GLS_627 SFS_Users")) -or (IsMemberOf("627 SFS USERS"))) {
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\627 ABG\627 SFS\627 SFS Dropbox"
	Map-NetworkDrive "H" "\\pqwy-cl01-02v\COMMON"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\627 SFS"
	#Map-NetworkDrive "G" "\\pqwy-cl01-02v\msg"
} 


#OG
If ((IsMemberOf("62 OG Users")) -or (IsMemberOf("62OG_USERS"))) { 
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\COMMON"
	Map-NetworkDrive "V" "\\pqwy-cl01-02v\OG-Common\Shared"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 og"
}
If ((IsMemberOf("62OSS CCL USERS")) -or (IsMemberOf("62OSS.CCL_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OG-Common\OG-IT"
}

If ((IsMemberOf("62OSS USERS")) -or (IsMemberOf("62OSS_USERS"))) { 
	Map-NetworkDrive "P" "\\pqwy-cl01-02v\OSS Common"
}

If ((IsMemberOf("62OG STAFF USERS")) -or (IsMemberOf("62OG.Staff_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OG-Staff"
}

If ((IsMemberOf("62OSS STAFF USERS")) -or (IsMemberOf("62OSS.Staff_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\Staff"
}

If ((IsMemberOf("62OG OGV USERS")) -or (IsMemberOf("62OG.OGV_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OGV"
}

If ((IsMemberOf("62OSA USERS")) -or (IsMemberOf("62OSA_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSA"
}

If ((IsMemberOf("62OSL USERS")) -or (IsMemberOf("62OSL_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSL"
}

If ((IsMemberOf("62IN USERS")) -or (IsMemberOf("62IN_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\IN"
}

If ((IsMemberOf("62OSO USERS")) -or (IsMemberOf("62OSO_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSO"
}

If ((IsMemberOf("62OST USERS")) -or (IsMemberOf("62OST_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OST"
}

If ((IsMemberOf("62OSW USERS")) -or (IsMemberOf("62OSW_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSW"
}

If ((IsMemberOf("62OSX USERS")) -or (IsMemberOf("62OSX_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSX"
}

If ((IsMemberOf("62OSK USERS")) -or (IsMemberOf("62OSK_USERS"))) { 
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\OSK"
}

If ((IsMemberOf("4AS USERS")) -or (IsMemberOf("4AS_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\4AS-COMMON"
}

If ((IsMemberOf("7AS USERS")) -or (IsMemberOf("7AS_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\7as-Common"
}

If ((IsMemberOf("8AS USERS")) -or (IsMemberOf("8AS_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\8as-Common"
}

If ((IsMemberOf("10AS USERS")) -or (IsMemberOf("10AS_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\10AS-Common"		
}

#627 MDG
If ((IsMemberOf("62 MDG Users -S"))) {
	Map-NetworkDrive "H" "\\pqwy-cl01-02v\mdg\mdg"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 MDG"
    Map-NetworkDrive "W" "\\pqwy-cl01-02v\COMMON"
}

#S Drive access f-or users in the security group ("62MDSS Users -S"))).

If ((IsMemberOf("62 MDSS OIC -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS Exec Staff -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS NCOIC -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS PAD -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSAL -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSAP -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSAR -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSF -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSI -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSL -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSLE -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSLF -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSO -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGSR -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}
If ((IsMemberOf("62MDSS SGST -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDSS"
}


#S Drive access f-or users in the security group ("62MDOS Users -S"))).

If ((IsMemberOf("62 MDOS/EXEC STAFF"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62 MDOS/SGOAM HEARING"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOA -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAB -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAE -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAF -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAM -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAMI -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAP -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAR -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOAZ -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOD -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOH -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOHA-S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOL -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOLI -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}
If ((IsMemberOf("62MDOS SGOPP -S"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\MDG\mdg\MDOS"
}


#627 MXG
If ((IsMemberOf("62MXG_Users"))) {
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\MXG\MXGShared"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 MXG"
}

If ((IsMemberOf("62 AMXS Users")) -or (IsMemberOf("62AMXS_USERS"))) { 
    Map-NetworkDrive "L" "\\pqwy-cl01-02v\62 AMXS"
}

If ((IsMemberOf("62MOS Users")) -or (IsMemberOf("62MOS_USERS"))) {
    Map-NetworkDrive "L" "\\pqwy-cl01-02v\MOS"
}

If ((IsMemberOf("62MXS Users")) -or (IsMemberOf("62MXS_USERS"))) {
    Map-NetworkDrive "L" "\\pqwy-cl01-02v\MXS"
}

If ((IsMemberOf("62 MXG QA")) -or (IsMemberOf("62MXG_QA"))) {
    Map-NetworkDrive "K" "\\pqwy-cl01-02v\MXG\MXGStaff\QA"
}

If ((IsMemberOf("62APS USERS")) -or (IsMemberOf("62APS_USERS"))) {
    Map-NetworkDrive "S" "\\pqwy-cl01-02v\62 APS"
    Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 MXG\62 APS"
}


#62 AW ALS
If ((IsMemberOf("62 AW ALS SG")) -or (IsMemberOf("62AW.ALS_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\als"
}


#62 AW CPO
If ((IsMemberOf("GLS_62 AW_CPO_USERS")) -or (IsMemberOf("62AW.CPO_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\cpo"
}


#62 AW FSD
If ((IsMemberOf("UDG_62 AW_FSD"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\DPE"
}


#FTAC
If ((IsMemberOf("62 FSS FTAC ALL SG")) -or (IsMemberOf("GLS_62 AW_CAA FTAC"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\ftac"
}


#62 MOF
If ((IsMemberOf("GLS_62 AW_MOF_USERS")) -or (IsMemberOf("62AW.MOF_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\mof"
}


#62 AW Testing
If ((IsMemberOf("GLS_62 AW_TESTING_USERS")) -or (IsMemberOf("62AW.TESTING_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\testing"
}


#62 AW Staff
If ((IsMemberOf("62AW STAFF USERS")) -or (IsMemberOf("62AW.STAFF_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\aw_staff"
}

If ((IsMemberOf("GLS_62 AW_HO BASE_HIST-orIAN"))) {
	Map-NetworkDrive "H" "\\pqwy-cl01-02v\Historian"
}


#62 AW CP
If ((IsMemberOf("62CP Users")) -or (IsMemberOf("62 AW CP ALL")) -or (IsMemberOf("62CP_USERS"))) { 
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox" 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\cp"
}


#62 EO
If ((IsMemberOf("62EO Users")) -or (IsMemberOf("62EO_USERS"))) { 
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\627 ABG\627 ABG\627 ABG Dropbox" 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\EO$"
}


#62 CPTS
If ((IsMemberOf("62CPTS_Users2")) -or (IsMemberOf("62CPTS_USERS"))) {
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\mcchord\62 aw\CPTS"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\62 CPTS"
	#Map-NetworkDrive "T" "\\131.30.242.171\dmoinput"
	#Map-NetworkDrive "V" "\\131.30.242.171\dmodata"
}


#62 AW HC
If ((IsMemberOf("62HC Users")) -or (IsMemberOf("62HC_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\627 ABG\627 ABG\627 ABG Dropbox"  
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\62 HC"
}


#62 IP
If ((IsMemberOf("62IP Users")) -or (IsMemberOf("62IP_USERS"))) { 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\IP$"
}


#62 AW IG
If ((IsMemberOf("62IG Users")) -or (IsMemberOf("62IG_USERS"))) {
#	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox" 
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\IG$"
}


#62 AW JA
If ((IsMemberOf("62JA Users")) -or (IsMemberOf("62JA_USERS"))) {
#	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox"	
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\ja"
	Map-NetworkDrive "T" "\\pqwy-cl01-02v\workfile"
	Map-NetworkDrive "V" "\\pqwy-cl01-02v\jagmail"
	Map-NetworkDrive "W" "\\pqwy-cl01-02v\allusers"
}

If ((IsMemberOf("Legal Assistance Office"))) {
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\awja"
}


#62 AW PA
If ((IsMemberOf("62AW PA Users")) -or (IsMemberOf("62AW.PA_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\627 ABG\627 ABG\627 ABG Dropbox"   
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\PA"
}


#62 AW SE
If ((IsMemberOf("62SE Users")) -or (IsMemberOf("62SE_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox"  
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\SE"
}


#62 AW XP
If ((IsMemberOf("62 XP Users")) -or (IsMemberOf("62XP_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\XP"
}

If ((IsMemberOf("62AT Users")) -or (IsMemberOf("62AT_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\62 aw\62 AW Dropbox"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\XP"
}


#62 AW AFLOA
If ((IsMemberOf("GLS_62 AW_AFLOA")) -or (IsMemberOf("62AW_AFLOA"))) {
	
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\AFLOA"
}


#62 AW DCS
If ((IsMemberOf("62AW.DCS_Users"))) {
	
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\62 DCS"
}


#62 ADC
If ((IsMemberOf("62ADC USERS")) -or (IsMemberOf("62ADC_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\adc"
}


#AFAA
If ((IsMemberOf("AFAA_Users")) -or (IsMemberOf("62AFAA USERS")) -or (IsMemberOf("AFAA_USERS"))) {
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\afaa"	
}


#361 RCS
If ((IsMemberOf("361RCS Users")) -or (IsMemberOf("361RCS_USERS"))) {
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\common"
#	Map-NetworkDrive "Q" "\\pqwy-cl01-02v\361RCS\361APPS"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\361rcs"
}


#22 STS
If ((IsMemberOf("22sts Users")) -or (IsMemberOf("22sts_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\22 sts"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\common"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\Tenants\22 STS"
	Map-NetworkDrive "P" "\\pqwy-cl01-02v\PFPS"
}


#262 NWS (COS)
If ((IsMemberOf("262NWS USERS")))  {
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\262 iwas" 
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\194 WG\252 COG\262 NWS"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\OFFREC\194 WG\252 COG\252 COG"
}


#373 TRS
If ((IsMemberOf("373TRS USERS")) -or (IsMemberOf("373TRS Students")) -or (IsMemberOf("373TRS_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\373 TRS"
	Map-NetworkDrive "Q" "\\pqwy-cl01-02v\MTD Schedule"
}


#WADS
If ((IsMemberOf("PQYY WADS USER"))) {
	#Map-NetworkDrive "S" "\\131.30.234.150\HOME"
	#Map-NetworkDrive "O" "\\131.30.234.150\ERM\ERM"
}


#5 ASOS
If ((IsMemberOf("GLS_5 ASOS_")) -or (IsMemberOf("GLS_5 ASOS_ALL")) -or (IsMemberOf("UDG_5 ASOS_ALL USERS")) -or (IsMemberOf("5ASOS_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\5 ASOS"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\McChord\Tenants\5 ASOS\5 ASOG Dropbox"
}


#252 COG
If ((IsMemberOf("GLS_252COG_USERS")) -or (IsMemberOf("252COG_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\252 COG"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\OFFREC\194 WG\252 COG\262 NWS"
}


#1 ASOG
If ((IsMemberOf("1ASOG_STAFF"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\1 ASOG"
}


#116 WF
If ((IsMemberOf("GLS_116WF_USERS")) -or (IsMemberOf("116WF_USERS"))) {
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\116WF$"
}

#57 WPS
If ((IsMemberOf("GLS_57 WPS_USERS")) -or (IsMemberOf("57WPS_USERS"))) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\57 WPS"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\57 WPS Students"
}

If ((IsMemberOf("GLS_57 WPS_STUDENTS"))) {
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\pfps"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\57 WPS Students"
}

#446 PA
if (IsMemberOf("446 PA Users")) {
    Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446AW_Shared\PA"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 SE
if (IsMemberOf("446 SE Users")) {
    Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446AW_Shared\SE"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 HC
if (IsMemberOf("446 HC Users")) {
    Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446AW_Shared\PA"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 ASTS
if (IsMemberOf("446 ASTS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_ASTS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_ASTS_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"	
}


#446 SJA
if (IsMemberOf("446 JA Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_SJA"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 AMDS
if (IsMemberOf("446 AMDS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"
	#Map-NetworkDrive "I" "\\PQYYW3PR801\ASIMS"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_AMDS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_AMDS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 RS
if (IsMemberOf("446 RS")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\RS_APPS"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 FM
if (IsMemberOf("446 FM Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"
	#Map-NetworkDrive "H" "\\fspqyy09\iats50" 	
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "N" "\\mxg-svr\aw_fm" 
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446AW_Shared\FM"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 AW Staff
if (IsMemberOf("446 AW Staff")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_AW_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#36 APS
if (IsMemberOf("36 APS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\36_APS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\36_APS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#86 APS
if (IsMemberOf("86 APS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\86_APS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\86_APS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 CES
if (IsMemberOf("446 CES Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	#Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_CES_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_CES_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 SFS
if (IsMemberOf("446 SFS ALL")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_SFS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_SFS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 FSS
if (IsMemberOf("GLS_446_FSS_Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_FSS_Restricted"	
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_FSS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 LRF
if (IsMemberOf("446 LRF Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_LRF_Restricted"		
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_LRF_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 MSG
if (IsMemberOf("446 MSG Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MSG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_MSG_Restricted"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 MSG time cards
if (IsMemberOf("446 MSG Time Keep")) {
	Map-NetworkDrive "T" "\\pqwy-cl01-02v\446_MSG_Restricted\Time_Keep"
}


#446 MXG
if (IsMemberOf("446 MXG Staff")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MXG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_MXG_Restricted"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 MOF
if (IsMemberOf("446 MXG Staff Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MXG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "N" "\\pqyyw8fs802\mos"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_MXG_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_MOF_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 AMXS
if (IsMemberOf("446 AMXS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MXG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "N" "\\pqyyw8fs802\amxs"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_AMXS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_AMXS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 MXS
if (IsMemberOf("446 MXS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_MXG_Shared"
	Map-NetworkDrive "L" "\\pqwy-cl01-02v\446_AW_Common"	
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	#Map-NetworkDrive "N" "\\pqyyw8fs802\mxs"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_MXS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_MXS_Shared"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}

#446 MXG QA
if (IsMemberOf("446 MXG Quality Assurance")) {
	#Map-NetworkDrive "K", "\\PQYYW8FS802\mxgstaff\QA"
	#Map-NetworkDrive "Q", "\\PQYYW8FS802\mxg\mxgshared"
}


#313 AS
if (IsMemberOf("313 AS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\313_AS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\313_AS_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#97 as
if (IsMemberOf("97 AS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\97_AS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\97_AS_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#728 AS
if (IsMemberOf("728 AS Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\728_AS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\728_AS_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 AES
if (IsMemberOf("446 AES Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_AES_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_AES_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 OSS
if (IsMemberOf("USG_446 OSS_Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_OSS_Restricted"
	Map-NetworkDrive "S" "\\pqwy-cl01-02v\446_OSS_Shared"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 OG Staff
if (IsMemberOf("446 OG Staff")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_OG_Restricted"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 OG
if (IsMemberOf("446 OG Users")) {
	Map-NetworkDrive "G" "\\pqwy-cl01-02v\446_OG_Shared"
	Map-NetworkDrive "K" "\\pqwy-cl01-02v\446_AW_Common"
	Map-NetworkDrive "J" "\\pqwy-cl01-02v\Pub_og"
	Map-NetworkDrive "M" "\\pqwy-cl01-02v\446_MCP_Program"	
	Map-NetworkDrive "O" "\\pqwy-cl01-02v\offREC\446 AW"
	#Map-NetworkDrive "P" "\\52pqwy-qs-004v"
	Map-NetworkDrive "R" "\\pqwy-cl01-02v\446_OG_Restricted"
	Map-NetworkDrive "X" "\\pqwy-cl01-02v\Airdrop"
	Map-NetworkDrive "Y" "\\pqwy-cl01-02v\Infobase"
}


#446 WOC
if (IsMemberOf("USG_446 OSF_WOC")) {
    Map-NetworkDrive "W" "\\pqwy-cl01-02v\446_WOC_Restricted"
}


#446 AW CST
if (IsMemberOf("USG_446 AW_CST")) {
   	#Map-NetworkDrive "Q" "\\pqwy-cl01-02v\TempProfileBackup"
	Map-NetworkDrive "V" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\01-DD2875 (PA)"
    Map-NetworkDrive "W" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\02-AF4394 (PA)"
	Map-NetworkDrive "Z" "\\pqwy-cl01-02v\Sharapps"
}


#446 IAO
if (IsMemberOf("USG_446 AW_IAOS")) {

	Map-NetworkDrive "V" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\01-DD2875 (PA)"
    Map-NetworkDrive "W" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\02-AF4394 (PA)"
}


#446 NCC
if (IsMemberOf("446 NCC")) {
    Map-NetworkDrive "V" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\01-DD2875 (PA)"
   	Map-NetworkDrive "W" "\\pqwy-cl01-02v\offREC\446 AW\446 FSS SCOO\05 - Precedent Files\02-AF4394 (PA)"
	Map-NetworkDrive "Z" "\\pqwy-cl01-02v\Sharapps"
}

#446 AW UTMS
if (IsMemberOf("UDG_446AW_UTMS")) {
  Map-NetworkDrive "T" "\\pqwy-cl01-02v\Wing_training"
}

#--------
#Popups

if (-not [System.IO.File]::Exists("$([Environment]::GetFolderPath("Desktop"))\Print Server.lnk")) {
    set-shortcut "$([Environment]::GetFolderPath("Desktop"))\Print Server.lnk" "\\PQWY-qs-001v\"
    popup "Did you know McChord Has a Print Server?" "To access it, use the shortcut on your desktop`n`nPrint Server"
}