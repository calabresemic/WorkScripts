$ErrorActionPreference = "SilentlyContinue"

#Gather user information
#================================
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$o = $Adobj.properties.o.replace(" ","_")
$l = $Adobj.properties.l.replace(" ","_")
$unitScript = "\\area52.afnoapps.usaf.mil\$l\logon_scripts\$o\$o.ps1"

if ($groups["UDG_30 SCS_All FSAs at VAFB"]) {
	New-Favorite "Links\DISA STIGs" "http://IASE.disa.mil"
	New-Favorite "DISA STIGs" "http://IASE.disa.mil" 
}

$msg = @"
Current INFOCON Level: 3
Current FPCON Level: BRAVO


Operations Security (OPSEC) applies To unclassified information.
Remember good OPSEC In all you Do.  Know the AFSPC Critical Information
List And protect it.  Be careful what you write, say And throw away.
Use STUs, Red Switch And SIPRNet To the maximum extent possible And DON'T
talk around classified information.
Operational Security Is EVERYBODY'S business.
"@
$null = [System.Windows.Forms.MessageBox]::Show($msg, "Welcome to VULCAN")

$Group = "VA_CSA"
if (IsInGroup($Group) -or $groups["VA_ALL CSA_SG"]) {
	Map-Drive "W:" "\\xumu-fs-001v\csasoftware" $Group
}

New-Favorite "Wing Bulletin Board" "https://usaf.dps.mil/sites/afspc-30sw/wvbb/SitePages/Home.aspx"
New-Shortcut (Join-Path $env:userprofile "Desktop\Wing Bulletin Board.lnk") "https://usaf.dps.mil/sites/afspc-30sw/wvbb/SitePages/Home.aspx" "\\132.1.209.18\LogonScripts\Clipboard.ico"

#Launch Org Script
Powershell.exe -noninteractive -noprofile -executionpolicy bypass -file $unitScript