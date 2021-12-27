#Requires -Version 5.0
#Original developed by Chris Steele (1456084571)
#Refined by SSgt Michael Calabrese (1468714589)
#This script will automate STIG checking, No changes will be made
#This script will take the baseline checklist file, edit it, and export a new one
#Each STIG check is based on the Rule_ID of the listed vulnerability (Since the same vuln ID is reused across OS's and when DISA updated the STIG details)
#If any items are still marked as Not reviewed, then its possible a new version of the STIG is being checked than what was coded

<# Revision History
9/17/18 : Chris Steele (1456084571) - Script development started
9/27/18 : Chris Steele (1456084571) - Initial version complete; includes STIGs for 2012 R2 MS, DC, IE 11, and .NET
11/9/18 : Chris Steele (1456084571) - Started naming script by file version, 1.3
1/23/19 : Chris Steele (1456084571) - V1.3.03, Added lastest DISA Rules
3/27/19 : Chris Steele (1456084571) - Started Revision History
3/28/19 : Chris Steele (1456084571) - Added Oct 2018 Revisions, and 2008 R2 MS stigs
11/15/19 : Chris Steele (1456084571) - Changed how we parse the ckl file (actually process it as an xml, instead of working through it like a text file)
    This will allow us to add comments and finding details into the checklist as well
12/5/19 : Michael Calabrese (1468714589) - Added POAM entries to script using the comment block
12/16/19 : Michael Calabrese (1468714589) - Added DNS Not_Applicable rules, added IIS checks
1/2/20 : Michael Calabrese (1468714589) - Enhanced SIPR support, changed the way default domain policy is checked. Adding requirement to use powershell V5, yea, get over it.
V3.0
1/2/20 : Michael Calabrese (1468714589) - Removed 3721 lines of code for 2008R2 STIGs. We're finally done with those damn things! Completely redoing the organization of the script.
    This allowed me to remove 648 lines of code and have things more organized. Removed duplicates for old rules.
1/6/20 : Michael Calabrese (1468714589) - AudiPol...
5/29/20 : Michael Calabrese (1468714589) - Post-Apocalypse script repairs
6/18/20 : Michael Calabrese (1468714589) - Fixed all false negatives. Added all POAM/MFR STIGs to a list to verify they are still needed when the new STIGs drop.
7/8/20 : Michael Calabrese (1468714589) - Lots of cross domain fixes.Changed hard coded DNs to cmdlt based results. Added some new REQ updates.
7/13/20 : Michael Calabrese (1468714589) - v4.0 Rewriting to make future support easier. Making comments into variables based on the status of MFR/POAM and standardized locations. Reorganized all sections. Added manual entries section.
    Redesigned the initial .net drive scan to include soft certs and anything else really so we don't have to scan the machine more than once.
8/7/2020 : Michael Calabrese (1468714589) - Added Server 2019 STIGs, IIS STIGS
11/3/2020 : Michael Calabrese (1468714589) - Re-wrote the DNS STIGs because they completely changed...
11/13/2020 : Michael Calabrese (1468714589) - Some process improvements , mostly with group policy processing.
12/2/2020 : Michael Calabrese (1468714589) - Automation testing, added logging to the C:\Windows\Logs\Software folder to monitor automated scripting
#>

<# STIG VERSIONS
Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide :: Version 2, Release: 19 Benchmark Date: 17 Jun 2020
Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 21 Benchmark Date: 17 Jun 2020
Windows Server 2019 Security Technical Implementation Guide :: Version 1, Release: 5 Benchmark Date: 17 Jun 2020
Microsoft Windows 2012 Server Domain Name System Security Technical Implementation Guide :: Version 2, Release: 1 Benchmark Date: 23 Oct 2020
Microsoft Internet Explorer 11 Security Technical Implementation Guide :: Version 1, Release: 19 Benchmark Date: 24 Jul 2020

Deprecated (This was the last version I added support for)
Microsoft DotNet Framework 4.0 STIG :: Version 1, Release: 9 Benchmark Date: 25 Oct 2019
IIS 8.5 Server Security Technical Implementation Guide :: Version 1, Release: 10 Benchmark Date: 24 Apr 2020
IIS 8.5 Site Security Technical Implementation Guide :: Version 1, Release: 10 Benchmark Date: 24 Apr 2020
#>

param([bool]$automate)
    
#Control if we want to check the STIGs on the machine, or find what Rule_ID's are missing from our script.
$SCAP = $true 

#Set the comment for MFRs and POAMS
$auditpolrepair="Run the audit policy repair script on the server \\zhtx-bs-013v\cyod\07--Cyber 365\08--Scripts\audit policy repair.ps1"
$NIPRMFR="There is an MFR for this vulnerability located on NIPR: \\zhtx-bs-013v\cyod\07--Cyber 365\04--Supporting Documents\MFRs"
$SIPRMFR="There is an MFR for this vulnerability located on SIPR: \\muhj-fs-001\CYOD\07--Cyber 365\04--Supporting Documents\MFRs"
$POAM="This vulnerability is currently POAMed. A copy of the POAM is located on SIPR in the following location: \\muhj-fs-001\CYOD\07--Cyber 365\04--Supporting Documents\POA&Ms"
#When adding a request number to the script use '+ "request number:"' Ex: $REQ + "CRQ000001234"
$REQ="There is currently a CRQ, REQ or SRM submitted for this vulnerability in Remedy: "

if ($automate -eq $true){
    #Clean up old logs and start a new log
    Get-ChildItem C:\Windows\Logs\Software | where name -like "SCAPer*" | Remove-Item -Force
    Start-Transcript -Path "C:\Windows\Logs\Software\$($MyInvocation.MyCommand.Name).log"
    #These variables are needed for output automation
    $Quarter="$(Get-date -f yyyy) Q$((Get-date -f MM)/3)"
    $GeoCode= $env:computername.Split('-')[0]
    xcopy "\\muhj-fs-001.acc.accroot.ds.af.smil.mil\SCAPTest\Domain Controller Checklist ($($Quarter)).ckl" C:\Windows\Temp /Y /I /D
    }

#If we're going to be check STIGs, then make sure we're elevated to admin creds
#If not, initialize the array to hold our text to copy
elseif ($SCAP -eq $true) {
        $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
        $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
        if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
            $scriptpath = "'" + $MyInvocation.MyCommand.Definition + "'"
            Start-Process -FilePath PowerShell.exe -Verb runAs -ArgumentList "& $scriptPath"
            exit
            }
        }
else {
    #cls
    $script = Get-Content $MyInvocation.MyCommand.Definition #Load the contents of the current script
    $CopyToClip = @()
    }

#This is here to check the speed of the script
$stopwatch=[system.diagnostics.stopwatch]::StartNew()
"Initializing..."

#This function returns the requested Registry Value at the provided Registry Key path
#I made this after doing all the IE checks.  I'm not bothering to go and replace all that code.  Sue me.
function Check-RegKeyValue {
    #$regPath example: HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria
    #$regValue is the value of the provided Registry Key in $regPath
    #$EA is erroraction, and defaults to Continue (so you can provide SilentlyContinue in case you know it will error out)
    param ($regPath,$regValueName,$EA = "Continue")
    #Return the value of the specified Registry key's $regValueName

    #if ($EA -eq "Continue") {$EA = "STOP"}
    #try {
    $EA = "SilentlyContinue"
    return (Get-ItemProperty ("Registry::" + $regPath) -Name $regValueName -ErrorAction $EA | select -ExpandProperty $regValueName)
    #} catch {write-host ($regpath + " - " + $regValueName + "`n" + $_)}
    }

#Grab the last made .ckl file and use it to SCAP against
if($automate -eq $true){$cklFile = Get-ChildItem C:\Windows\Temp -Filter *.ckl | sort whencreated -Descending | select -First 1}
else{$cklFile = Get-ChildItem $env:USERPROFILE\desktop -Filter *.ckl | sort whencreated -Descending | select -First 1}
$cklFileName = $cklFile.name.split(".")[0]
$cklFilePath = $cklFile.fullname
[xml]$checklist = Get-Content $cklFilePath

if ($SCAP -eq $true) {

    #These checks are for all machines
    "Loading universal variables..."
    $ServerRole = Get-WmiObject Win32_OperatingSystem | select -ExpandProperty ProductType #1 is Workstation, 2 is Domain Controller, 3 is Member Server
    $DC = Get-ADDomainController | select -ExpandProperty hostname
    $auditpol = auditpol /get /category:*
    $IsServerCore = (Check-RegKeyValue "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" "InstallationType") -match "Core"
    $OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $OSArch = 32
    if ([Environment]::Is64BitOperatingSystem) {$OSArch = 64}
    $currDate = Get-Date
    $PartOfDomain = (gwmi win32_computersystem).partofdomain -eq $true
    $Domain = Get-ADDomain
    $IsNIPR = $Domain.DNSRoot -match "afnoapps.usaf.mil"
    $DomainName = $Domain.Name
    $PDC = $Domain.PDCEmulator
    $installedprograms=Get-WmiObject -class Win32Reg_AddRemovePrograms64
    $installedFeatures=Get-WindowsFeature | Where-Object {$_.InstallState -like "Installed"}
    $NotChecked = @() #An array to hold the Rule ID's we don't have checks for
    $passwordpolicy=Get-ADDefaultDomainPasswordPolicy
    $UserRights=Get-WMIObject RSOP_UserPrivilegeRight -namespace root\rsop\computer | where precedence -eq 1
    $SecSettings=Get-WMIObject RSOP_SecuritySettings -namespace root\rsop\computer | where precedence -eq 1
    $Adminlevelcodes=@('adm','ada','adc','add','ade','adf','adw','adx')
    if($ServerRole -ne 2){
    $Guest=Get-LocalUser | where SID -like "*501" -ErrorAction SilentlyContinue
    $Admin=Get-LocalUser | where SID -like "*500" -ErrorAction SilentlyContinue}

    #Fills in Target Data section of the STIG checklist. This is used to sort data from all checklists.
    "Generating checklist variables..."
    if($ServerRole -eq 2){$checklist.checklist.ASSET.ROLE = "Domain Controller"}
    else{$checklist.checklist.ASSET.ROLE = "Member Server"}
    $checklist.checklist.ASSET.HOST_NAME = "$env:computername"
    $checklist.checklist.ASSET.HOST_FQDN = "$env:computername.$($Domain.DNSRoot)"
    $comment=$checklist.'#comment'
    $checklist.'#comment' = $comment + "`n" + $cklfile.Name

    #This scans all drives for certain files: Soft Certs, Java, 2019 OS STIGs
    #edited to use cmd /c because the old way was causing issues
    "Scanning Drives..."
    $allfiles=@()
    $drives=(Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne 0}).name

    foreach($drive in $drives){
        Start-Job -Name $drive -ScriptBlock {$drive=$args[0..($args.count -1)];cmd /c dir "${drive}:\" /B /S /A-D | Where-Object {($_ -like "*Acrobat.exe") -or ($_ -like "*AcroRd32.exe") -or ($_ -like "*chrome.exe") -or ($_ -like "*EXCEL.EXE") -or ($_ -like "*firefox.exe") -or ($_ -like "*FLTLDR.EXE") -or ($_ -like "*GROOVE.EXE") -or ($_ -like "*iexplore.exe") -or ($_ -like "*INFOPATH.EXE") -or ($_ -like "*lync.exe") -or ($_ -like "*MSACCESS.EXE") -or ($_ -like "*MSPUB.EXE") -or ($_ -like "*OIS.EXE") -or ($_ -like "*OneDrive.exe") -or ($_ -like "*OUTLOOK.EXE") -or ($_ -like "*plugin-container.exe") -or ($_ -like "*POWERPNT.EXE") -or ($_ -like "*PPTVIEW.EXE") -or ($_ -like "*VISIO.EXE") -or ($_ -like "*VPREVIEW.EXE") -or ($_ -like "*WINWORD.EXE") -or ($_ -like "*wmplayer.exe") -or ($_ -like "*wordpad.exe") -or ($_ -like "*.p12") -or ($_ -like "*.pfx") -or ($_ -like "*.java") -or ($_ -like "*.jpp")}} -ArgumentList $drive | Out-Null
        }

    $runningjobs = (Get-Job -State Running).Count
    $total=$drives.count
    while($runningjobs -gt 0){
        $percent=[math]::Round((($total-$runningjobs)/$total *100))
        $scanningdrives=(Get-Job -State Running).Name -join ","
        Write-Progress -Activity "Scanning the drives for the OS STIGS" -Status "Scanning the following drives: $scanningdrives" -PercentComplete $percent
        $runningjobs = (Get-Job -State Running).Count
        }

    Write-Progress -Activity "Scanning the drives for the OS STIGS" -Status "Ready" -Completed
    foreach($job in Get-Job){
        $temp=Receive-Job $job
        $allfiles+=$temp}
    Get-Job | Remove-Job

    "Scanning drives complete"

    $ProcessMitigationList=$allfiles | Where-Object {($_ -like "*Acrobat.exe") -or ($_ -like "*AcroRd32.exe") -or ($_ -like "*chrome.exe") -or ($_ -like "*EXCEL.EXE") -or ($_ -like "*firefox.exe") -or ($_ -like "*FLTLDR.EXE") -or ($_ -like "*GROOVE.EXE") -or ($_ -like "*iexplore.exe") -or ($_ -like "*INFOPATH.EXE") -or ($_ -like "*lync.exe") -or ($_ -like "*MSACCESS.EXE") -or ($_ -like "*MSPUB.EXE") -or ($_ -like "*OIS.EXE") -or ($_ -like "*OneDrive.exe") -or ($_ -like "*OUTLOOK.EXE") -or ($_ -like "*plugin-container.exe") -or ($_ -like "*POWERPNT.EXE") -or ($_ -like "*PPTVIEW.EXE") -or ($_ -like "*VISIO.EXE") -or ($_ -like "*VPREVIEW.EXE") -or ($_ -like "*WINWORD.EXE") -or ($_ -like "*wmplayer.exe") -or ($_ -like "*wordpad.exe")}
    $softcerts=$allfiles | where {($_ -like "*.p12") -or ($_ -like "*.pfx")}
    $javalist=$allfiles | where {($_ -like "*.java") -or ($_ -like "*.jpp")}
    
    #Server 2019 only checks
    if($OS -like "Microsoft Windows Server 2019*"){
    "Loading Server 2019 variables..."
        $SysProcessMitigation=Get-ProcessMitigation -System
        $ProcessMitigation=@()
        $ProcessMitigation += Get-ProcessMitigation -Name Acrobat.exe; $ProcessMitigation += Get-ProcessMitigation -name AcroRd32.exe; $ProcessMitigation += Get-ProcessMitigation -name chrome.exe; $ProcessMitigation += Get-ProcessMitigation -name EXCEL.EXE
        $ProcessMitigation += Get-ProcessMitigation -name firefox.exe; $ProcessMitigation += Get-ProcessMitigation -name FLTLDR.EXE; $ProcessMitigation += Get-ProcessMitigation -name GROOVE.EXE; $ProcessMitigation += Get-ProcessMitigation -name iexplore.exe
        $ProcessMitigation += Get-ProcessMitigation -name INFOPATH.EXE; $ProcessMitigation += Get-ProcessMitigation -name java.exe; $ProcessMitigation += Get-ProcessMitigation -name javaw.exe; $ProcessMitigation += Get-ProcessMitigation -name javaws.exe
        $ProcessMitigation += Get-ProcessMitigation -name lync.exe; $ProcessMitigation += Get-ProcessMitigation -name MSACCESS.EXE; $ProcessMitigation += Get-ProcessMitigation -name MSPUB.EXE; $ProcessMitigation += Get-ProcessMitigation -name OIS.EXE
        $ProcessMitigation += Get-ProcessMitigation -name OneDrive.exe; $ProcessMitigation += Get-ProcessMitigation -name OUTLOOK.EXE; $ProcessMitigation += Get-ProcessMitigation -name plugin-container.exe; $ProcessMitigation += Get-ProcessMitigation -name POWERPNT.EXE
        $ProcessMitigation += Get-ProcessMitigation -name PPTVIEW.EXE; $ProcessMitigation += Get-ProcessMitigation -name VISIO.EXE; $ProcessMitigation += Get-ProcessMitigation -name VPREVIEW.EXE; $ProcessMitigation += Get-ProcessMitigation -name WINWORD.EXE
        $ProcessMitigation += Get-ProcessMitigation -name wmplayer.exe; $ProcessMitigation += Get-ProcessMitigation -name wordpad.exe
        }

    #IIS only checks
    if($installedFeatures.name -contains "Web-Server"){
    "Loading IIS variables..."
        $serverlogfile=Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -Name logfile
        $sitelogfile=Get-ItemProperty "IIS:\Sites\Default Web Site" -Name logfile
        $serversessionstate=Get-WebConfiguration system.web/sessionstate
        $appPool=(Get-Website -Name 'default web site').applicationpool
        }

    #DNS only checks
    if($installedFeatures.name -contains "DNS"){
    "Loading DNS variables..."
        $dnsdiag = Get-DnsServerDiagnostics
        $ALLDNSZones=Get-DnsServerZone | where {$_.ZoneName -ne "TrustAnchors"}
        $NonDSZones=($ALLDNSZones | where {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).IsDsIntegrated -contains $false
        $Analyticlog=(Get-LogProperties "Microsoft-Windows-DNSServer/Analytical").Enabled #The Analytic log cannot be read while it is enabled so if the check fails the log is enabled
        }

    #DC only checks
    if($ServerRole -eq 2){
    "Loading DC variables..."
        #Using this searchbase makes it faster to find it. Builtin accounts could be moved so this might need to be adjusted if you run into error.
        $Guest=Get-ADUser -Filter * -SearchBase (Get-ADDomain).UsersContainer | where SID -like "*501"
        $Admin=Get-ADUser -Filter * -SearchBase (Get-ADDomain).UsersContainer  -Properties PasswordLastSet| where SID -like "*500"

        #This is for 2012R2 (V6840 and V7002)/2019 (V93475 and V93439)
        #Could be modified for anything that needs to check the whole domain. Moved to the top to avoid scanning twice.
        $ous = (Get-ADOrganizationalUnit -filter *).distinguishedname
        $users = @()
        [int]$totalscriptcount=4 #I experienced errors when going over this number
        [int]$ousearch = [math]::Truncate($ous.Count/$totalscriptcount)
        for ($i = 1; $i -le $totalscriptcount; $i++)
            {
            [int]$beginarray = $($ousearch*($i-1))
            [int]$endarray = $($ousearch*$i)
            if($i -eq 1){$argument = @($ous[$beginarray..$endarray])}
            else{$argument = @($ous[($beginarray+1)..$endarray])}
            Start-Job -ScriptBlock {$ous= $args[0..($args.count -1)]; foreach($ou in $ous){Get-ADUser -Filter {(Enabled -eq $true -and PasswordNeverExpires -eq $true -and smartcardlogonrequired -eq $false) -or (Enabled -eq $true -and PasswordNotRequired -eq $true -and smartcardlogonrequired -eq $false)} -properties PasswordNeverExpires,smartcardlogonrequired,PasswordNotRequired,extensionAttribute3 -SearchBase $ou -SearchScope OneLevel -EA Stop}} -ArgumentList $argument | Out-Null
            }

        $runningjobs = (Get-Job -State Running).Count
        $total=$runningjobs
        while($runningjobs -gt 0){
            $percent=[math]::Round((($total-$runningjobs)/$total *100))
            Write-Progress -Activity "Scanning AD for user account password settings" -Status "Progress: $percent%" -PercentComplete $percent
            $runningjobs = (Get-Job -State Running).Count
            }

        Write-Progress -Activity "Scanning AD for user account password settings" -Status "Scanning AD completed" -Completed
        foreach($job in Get-Job){
            $temp=Receive-Job $job
            $users+=$temp}
        Get-Job | Remove-Job
    }

"`nBeginning STIG checks"
}

#Output variables
$ManuallyVerify = @()

####
#$STIGs = $checklist.GetElementsByTagName("VULN")
$STIGS = $checklist.CHECKLIST.stigs.iSTIG.vuln

#What items of each vulnerability we want to keep track of
#This will create a variable names <item>_index, which we will use to access the data we want.
@"
Vuln_Num
Group_Title
Rule_ID
Rule_Title
Rule_Ver
Weight
Fix_Text
STIGRef
"@.split("`n") | foreach {
    New-Variable -Name ($_.trim() + "_index") -Value $STIGs[0].STIG_DATA.VULN_ATTRIBUTE.IndexOf($_.trim()) -Force
    }

#Main loop to parse checklist
#When trying to edit back into the Checklist, do not use $STIGs; use $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index]
:main for ($STIG_index = 0; $STIG_index -lt $STIGs.count; $STIG_index++) {
    <#
    Possible statuses:
    Open
    NotAFinding
    Not_Applicable
    Not_Reviewed
    #>

    #Lets only bother checking ones that are marked Not_Reviewed, just in case our checks aren't accurate and to speed up script time
    if ($STIGs[$STIG_index].STATUS -ne "Not_Reviewed") {continue}

    #This section is actually easy to add to.
    #Use the following format for each check:
    <#
            #Vuln ID
            #STIG Collection Name
            #Rule_Title
            "Rule_ID" { 
                #Comments detailing the GPO setting path
                #Comments describing the setting to configure and what to set it to
                if (<stigSettingsDontApply>) {$ActualStatus = "Not_Applicable"}
                elseif (<SettingAreConfiguredAsDesired>) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "this is a comment"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "this is a finding detail"
                }
    #>

    Write-Host ("Checking Vuln " + $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index])
    if ($SCAP -eq $true) {
        #See which vuln we are checking, based on the Rule ID
        :rulecheck switch ($STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_index]) {
           
            #V-1073
            #Windows Server 2012/2012 R2 MS STIG
            #Systems must be maintained at a supported service pack level.
            "SV-53189r2_rule" {
                #Running with a literal interpretation here. Version greater than or equal to the version 6.2 build 9200.
                if ((Get-WmiObject -Class win32_operatingsystem).version -ge 6.2.9200) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1074
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows 2012 / 2012 R2 system must use an anti-virus program.
            "SV-52103r4_rule" {
                if ($installedprograms.displayname -contains "mcafee agent") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1075
            #Windows Server 2012/2012 R2 MS STIG
            #The shutdown option must not be available from the logon dialog box.
            "SV-52840r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Shutdown: Allow system to be shutdown without having to log on" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ShutdownWithoutLogon"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1081
            #Windows Server 2012/2012 R2 MS STIG
            #Local volumes must use a format that supports NTFS attributes.
            "SV-52843r4_rule" {
                #All local volumes must be NTFS or ReFS
                #Check to see if there's any local volumes that AREN'T compliant
                #if (Get-WMIObject -Class Win32_Volume | Where {$_.DriveType -eq 3 -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {$ActualStatus = "Open"}
                if (Get-Volume | Where {$_.DriveType -eq "Fixed" -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-1089
            #Windows Server 2012/2012 R2 MS STIG
            #The required legal notice must be configured to display before console logon.
            "SV-52845r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #“Interactive Logon: Message text for users attempting to log on” as outlined in the check. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeText"
                $LegalNotice = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details.
"@
                if ($Value -eq $LegalNotice) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1090
            #Windows Server 2012/2012 R2 MS STIG
            #Caching of logon credentials must be limited.
            "SV-52846r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "4" logons or less. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "CachedLogonsCount"
                if ($Value -le 4) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1093
            #Windows Server 2012/2012 R2 MS STIG
            #Anonymous enumeration of shares must be restricted.
            "SV-52847r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "RestrictAnonymous"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1097
            #Windows Server 2012/2012 R2 MS STIG
            #The number of allowed bad logon attempts must meet minimum requirements.
            "SV-52848r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
                #"Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable). 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutThreshold -le 3 -and $passwordpolicy.LockoutThreshold -gt 0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }


            #V-1098
            #Windows Server 2012/2012 R2 MS STIG
            #The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2012.
            "SV-52849r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
                #"Reset account lockout counter after" to at least "60" minutes. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutObservationWindow -ge [timespan]"1:00"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1099
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012 account lockout duration must be configured to 15 minutes or greater.
            "SV-52850r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy
                #"Account lockout duration" to "15" minutes or greater, or 0.
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutDuration -ge [timespan]"00:15" -or $passwordpolicy.LockoutDuration -eq [timespan]0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1102
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Act as part of the operating system user right.
            "SV-52108r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Act as part of the operating system" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeTcbPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeTcbPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-1104
            #Windows Server 2012/2012 R2 MS STIG
            #The maximum password age must meet requirements.
            "SV-52851r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Maximum password age" to "60" days or less (excluding "0" which is unacceptable). 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.MaxPasswordAge -le [timespan]"60.00:00:00"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1105
            #Windows Server 2012/2012 R2 MS STIG
            #The minimum password age must meet requirements.
            "SV-52852r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Minimum password age" to at least "1" day. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.MinPasswordAge -ge [timespan]"1.00:00:00"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1107
            #Windows Server 2012/2012 R2 MS STIG
            #The password history must be configured to 24 passwords remembered.
            "SV-52853r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy
                #"Enforce password history" to "24" passwords remembered. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.PasswordHistoryCount -ge 24){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1112
            #Windows Server 2012/2012 R2 MS STIG
            #Outdated or unused accounts must be removed from the system or disabled.
            "SV-52854r4_rule" { 
                #Can't be checked
                if($ServerRole -eq 2){
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "AFMAN 17-1301 para 4.6.1 lists the ISSM/ISSO's responsability for disabling accounts."}
                else{
                    if((Get-LocalUser).count -gt 2){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-1113
            #Windows Server 2012/2012 R2 MS STIG
            #The built-in guest account must be disabled.
            "SV-52855r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Guest account status" to "Disabled".
                if(($Guest).Enabled -eq $false){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-1114
            #Windows Server 2012/2012 R2 MS STIG
            #The built-in guest account must be renamed.
            "SV-52856r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Rename guest account" to a name other than "Guest".
                if(($Guest).Name -eq "Guest"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-1115
            #Windows Server 2012/2012 R2 MS STIG
            #The built-in administrator account must be renamed.
            "SV-52857r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Rename administrator account" to a name other than "Administrator". 
                if(($Admin).Name -match "Administrator"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-1119
            #Windows Server 2012/2012 R2 MS STIG
            #The system must not boot into multiple operating systems (dual-boot).
            "SV-52858r1_rule" {
                $BootableDisks = @()
                $BootableDisks += Get-Disk | Where {$_.bootfromdisk -eq $true}
                if ($BootableDisks.count -eq 1) {$ActualStatus = "NotAFinding"}
                else {$ManuallyVerify += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]}
                }

            #V-1120
            #Windows Server 2012/2012 R2 MS STIG
            #File Transfer Protocol (FTP) servers must be configured to prevent anonymous logons.
            "SV-52106r2_rule" {
                if($installedFeatures.name -notcontains "web-ftp-server"){$ActualStatus = "Not_Applicable"}
                else {$ManuallyVerify += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]}
                }

            #V-1121
            #Windows Server 2012/2012 R2 MS STIG
            #File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive.
            "SV-52212r2_rule" {
                if($installedFeatures.name -notcontains "web-ftp-server"){$ActualStatus = "Not_Applicable"}
                else {$ManuallyVerify += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]}
                }

            #V-1135
            #Windows Server 2012/2012 R2 MS STIG
            #Nonadministrative user accounts or groups must only have print permissions on printer shares.
            "SV-52213r2_rule" {
                $printShares = get-printer * -full -EA SilentlyContinue | Where {$_.shared -eq $true}
                if ($printShares.count -eq 0) {$ActualStatus = "Not_Applicable"}
                else {$ActualStatus = "Open"}
                }

            #V-1136
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be forcibly disconnected when their logon hours expire.
            "SV-52860r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Disconnect clients when logon hours expire" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableForcedLogoff"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1141
            #Windows Server 2012/2012 R2 MS STIG
            #Unencrypted passwords must not be sent to third-party SMB Servers.
            "SV-52861r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled". 
                $Value = Check-RegKeyValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1145
            #Windows Server 2012/2012 R2 MS STIG
            #Automatic logons must be disabled.
            "SV-52107r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "AutoAdminLogon"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1150
            #Windows Server 2012/2012 R2 MS STIG
            #The built-in Windows password complexity policy must be enabled.
            "SV-52863r2_rule" {
                #Computer Configuration >> Windows Settings -> Security Settings >> Account Policies >> Password Policy 
                #"Password must meet complexity requirements" to "Enabled". 
                if($passwordpolicy.ComplexityEnabled -eq $true){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1151
            #Windows Server 2012/2012 R2 MS STIG
            #The print driver installation privilege must be restricted to administrators.
            "SV-52214r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Devices: Prevent users from installing printer drivers" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\" "AddPrinterDrivers"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1152
            #Windows Server 2012/2012 R2 MS STIG
            #Anonymous access to the registry must be restricted.
            "SV-52864r3_rule" {
                $regpath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\"
                $reg = Get-Item $regpath
                if ($reg -eq $null) {$ActualStatus = "Open"}
                else {
                    $FCIR=@(
                    'BUILTIN\Administrators')

                    $RIR=@(
                    'NT AUTHORITY\LOCAL SERVICE',
                    'BUILTIN\Backup Operators')

                    $regAcl = (Get-Acl $regpath).Access
                    if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000385464"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-1153
            #Windows Server 2012/2012 R2 MS STIG
            #The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
            "SV-52865r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "LmCompatibilityLevel"
                if ($Value -eq "5") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1154
            #Windows Server 2012/2012 R2 MS STIG
            #The Ctrl+Alt+Del security attention sequence for logons must be enabled.
            "SV-52866r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive Logon: Do not require CTRL+ALT+DEL" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableCAD"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1155
            #Windows Server 2012/2012 R2 MS STIG
            #The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems.
            "SV-51501r6_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
                #"Deny access to this computer from the network" to include the following:
                #Domain Systems Only:
                #Enterprise Admins group
                #Domain Admins group
                #"Local account and member of Administrators group" or "Local account" (see Note below)
                #
                #All Systems:
                #Guests group
                #
                #Note: Windows Server 2012 R2 added new built-in security groups, "Local account" and "Local account and member of Administrators group". "Local account" is more restrictive but may cause issues on servers such as systems that provide Failover Clustering.
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
                if($PartOfDomain){
                    if($value -contains "Local account and member of Administrators group" -and $Value -match "\\Enterprise Admins" -and $Value -match "\\Domain Admins"){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-1155
            #Windows Server 2012/2012 R2 DC STIG
            #The Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-51144r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny access to this computer from the network" to include the following: Guests Group
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
                if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1157
            #Windows Server 2012/2012 R2 MS STIG
            #The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
            "SV-52867r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive logon: Smart card removal behavior" to "Lock Workstation" or "Force Logoff". 
                #Documentable Explanation: This can be left not configured or set to “No action” on workstations with the following conditions. This will be documented with the IAO.
                #    •The setting can't be configured due to mission needs, interferes with applications.
                #    •Policy must be in place that users manually lock workstations when leaving them unattended.
                #    •Screen saver requirement is properly configured to lock as required in V0001122. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "SCRemoveOption"
                if ($Value -eq "1" -or $Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1162
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows SMB server must perform SMB packet signing when possible.
            "SV-52870r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1163
            #Windows Server 2012/2012 R2 MS STIG
            #Outgoing secure channel traffic must be encrypted when possible.
            "SV-52871r3_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Domain member: Digitally encrypt secure channel data (when possible)" to "SealSecureChannel". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SealSecureChannel"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1164
            #Windows Server 2012/2012 R2 MS STIG
            #Outgoing secure channel traffic must be signed when possible.
            "SV-52872r3_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Domain member: Digitally sign secure channel data (when possible)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SignSecureChannel"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1165
            #Windows Server 2012/2012 R2 MS STIG
            #The computer account password must not be prevented from being reset.
            "SV-52873r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Disable machine account password changes" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "DisablePasswordChange"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1166
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows SMB client must be enabled to perform SMB packet signing when possible.
            "SV-52874r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters\" "EnableSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1171
            #Windows Server 2012/2012 R2 MS STIG
            #Ejection of removable NTFS media must be restricted to Administrators.
            "SV-52875r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Devices: Allowed to format and eject removable media" to "Administrators". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1172
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be warned in advance of their passwords expiring.
            "SV-52876r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive Logon: Prompt user to change password before expiration" to "14" days or more. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "PasswordExpiryWarning"
                if ($Value -eq "14") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1173
            #Windows Server 2012/2012 R2 MS STIG
            #The default permissions of global system objects must be increased.
            "SV-52877r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-1174
            #Windows Server 2012/2012 R2 MS STIG
            #The amount of idle time required before suspending a session must be properly set.
            "SV-52878r3_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Microsoft Network Server: Amount of idle time required before suspending session" to "15" minutes or less. 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "autodisconnect"
                if ($Value -le 15) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2907
            #Windows Server 2012/2012 R2 MS STIG
            #System files must be monitored for unauthorized changes.
            "SV-52215r2_rule" { 
                if($installedprograms.displayname -contains "McAfee Agent"){$ActualStatus = "NotAFinding"}
                }

            #V-2372
            #Windows Server 2012/2012 R2 MS STIG
            #Reversible password encryption must be disabled.
            "SV-52880r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Store passwords using reversible encryption" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2374
            #Windows Server 2012/2012 R2 MS STIG
            #Autoplay must be disabled for all drives.
            "SV-52879r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies 
                #"Turn off AutoPlay" to "Enabled:All Drives". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" "NoDriveTypeAutoRun"
                if ($Value -eq "255") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2376
            #Windows Server 2012/2012 R2 DC STIG
            #Kerberos user logon restrictions must be enforced.
            "SV-51160r2_rule" {
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Enforce user logon restrictions" to "Enabled".
                $value = $secsettings | Where-Object {$_.KeyName -eq "TicketValidateClient"} | select -ExpandProperty Setting
                if ($Value -eq $true) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2377
            #Windows Server 2012/2012 R2 DC STIG
            #The Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.
            "SV-51162r2_rule" {
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for service ticket" to a maximum of 600 minutes, but not 0 which equates to "Ticket doesn't expire". 
                $value = $secsettings | Where-Object {$_.KeyName -eq "MaxServiceAge"} | select -ExpandProperty Setting
                if ($value -le "600"-and $value -gt 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2378
            #Windows Server 2012/2012 R2 DC STIG
            #The Kerberos user ticket lifetime must be limited to 10 hours or less.
            "SV-51164r2_rule" {
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for user ticket" to a maximum of 10 hours, but not 0 which equates to "Ticket doesn't expire".
                $value = $secsettings | Where-Object {$_.KeyName -eq "MaxTicketAge"} | select -ExpandProperty Setting
                if ($value -le "10"-and $value -gt 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2379
            #Windows Server 2012/2012 R2 DC STIG
            #The Kerberos policy user ticket renewal maximum lifetime must be limited to 7 days or less.
            "SV-51166r2_rule" {
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for user ticket renewal" to a maximum of 7 days or less. 
                $value = $secsettings | Where-Object {$_.KeyName -eq "MaxRenewAge"} | select -ExpandProperty Setting
                if ($value -le "7") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-2380
            #Windows Server 2012/2012 R2 DC STIG
            #The computer clock synchronization tolerance must be limited to 5 minutes or less.
            "SV-51168r3_rule" {
                #Default Domain Policy
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum tolerance for computer clock synchronization" to a maximum of 5 minutes or less.
                $value = $secsettings | Where-Object {$_.KeyName -eq "MaxClockSkew"} | select -ExpandProperty Setting
                if ($value -le "5") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3245
            #Windows Server 2012/2012 R2 MS STIG
            #Non system-created file shares on a system must limit access to groups that require it.
            "SV-52881r3_rule" {
                #Check all non system shares to see if theres Everyone permission with allow.  If not, it's sure constrained permissions
                $allowedshares=@(
                 "ADMIN$",
                 "C$",
                 "IPC$",
                 "D$",
                 "E$",
                 "F$",
                 "S$",
                 "NETLOGON",
                 "SYSVOL"
                )

                $ActualStatus = "Not_Applicable"
                $NonDefaultShares = (Get-SmbShare).Name | Where-Object {$allowedshares -NotContains $_}
                
                if($NonDefaultShares.count -gt 0){
                    $ActualStatus = "Not_Reviewed"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Review the following shares:`nExample of allowed shares: BaseName, LogonScripts, StartupScripts, Scripts, emie`n`n" + ($NonDefaultShares -join "`n")
                    }
                }

            #V-3289
            #Windows Server 2012/2012 R2 MS STIG
            #Servers must have a host-based Intrusion Detection System.
            "SV-52105r3_rule" {
                if ($installedprograms.displayname -contains "McAfee Host Intrusion Prevention") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3337
            #Windows Server 2012/2012 R2 MS STIG
            #Anonymous SID/Name translation must not be allowed.
            "SV-52882r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Allow anonymous SID/Name translation" to "Disabled".
                $value = $secsettings | Where-Object {$_.KeyName -eq "LSAAnonymousNameLookup"} | select -ExpandProperty Setting
                if ($Value -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3338
            #Windows Server 2012/2012 R2 MS STIG
            #Named pipes that can be accessed anonymously must be configured to contain no values on member servers.
            "SV-51497r2_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Named pipes that can be accessed anonymously" to be defined but containing no entries (blank). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionPipes"
                if ($value -eq "") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3338
            #Windows Server 2012/2012 R2 DC STIG
            #Named pipes that can be accessed anonymously must be configured with limited values on domain controllers.
            "SV-51138r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Named pipes that can be accessed anonymously" to only include "netlogon, samr, lsarpc". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionPipes" | Where {$_ -ne ""} #Stig says it could contain a blank entry
                if($Value.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif ($value -contains "netlogon" -and $value -contains "samr" -and $value -contains "lsarpc" -and $value.count -eq 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}                 
                }

            #V-3339
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized remotely accessible registry paths must not be configured.
            "SV-52883r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Remotely accessible registry paths" with the following entries:
                #System\CurrentControlSet\Control\ProductOptions
                #System\CurrentControlSet\Control\Server Applications
                #Software\Microsoft\Windows NT\CurrentVersion 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" "Machine"
                if ($Value.count -eq 3 -and $value -contains "System\CurrentControlSet\Control\ProductOptions" -and $value -contains "System\CurrentControlSet\Control\Server Applications" -and $value -contains "Software\Microsoft\Windows NT\CurrentVersion") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3340
            #Windows Server 2012/2012 R2 MS STIG
            #Network shares that can be accessed anonymously must not be allowed.
            "SV-52884r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Shares that can be accessed anonymously" contains no entries (blank). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionShares"
                if ($Value -eq "") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3343
            #Windows Server 2012/2012 R2 MS STIG
            #Solicited Remote Assistance must not be allowed.
            "SV-52885r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
                #"Configure Solicited Remote Assistance" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fAllowToGetHelp"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3344
            #Windows Server 2012/2012 R2 MS STIG
            #Local accounts with blank passwords must be restricted to prevent access from the network.
            "SV-52886r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Limit local account use of blank passwords to console logon only" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3373
            #Windows Server 2012/2012 R2 MS STIG
            #The maximum age for machine account passwords must be set to requirements.
            "SV-52887r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "MaximumPasswordAge"
                if ($Value -gt 0 -and $value -le 30) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3374
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to require a strong session key.
            "SV-52888r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireStrongKey"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3376
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent the storage of passwords and credentials.
            "SV-52889r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Do not allow storage of passwords and credentials for network authentication" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "DisableDomainCreds"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3377
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
            "SV-52890r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options 
                #"Network access: Let everyone permissions apply to anonymous users" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3378
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to use the Classic security model.
            "SV-52891r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "ForceGuest"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3379
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent the storage of the LAN Manager hash of passwords.
            "SV-52892r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Do not store LAN Manager hash value on next password change" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "NoLMHash"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3380
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to force users to log off when their allowed logon hours expire.
            "SV-52893r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Force logoff when logon hours expire" to "Enabled".
                if($ServerRole -eq 2){$Value = (Get-GPOReport -Name "$DomainName Default Domain Policy" -ReportType html -Server $env:COMPUTERNAME) -match "<tr><td>Network security: Force logoff when logon hours expire</td><td>Enabled</td></tr>"}
                else{$value = $secsettings | Where-Object {$_.KeyName -eq "ForceLogoffWhenHourExpire"} | select -ExpandProperty Setting}
                    if($value -eq $true){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                }

            #V-3381
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to the required LDAP client signing level.
            "SV-52894r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum. 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LDAP\" "LDAPClientIntegrity"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3382
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.
            "SV-52895r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinClientSec"
                if ($Value -eq "537395200") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3383
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
            "SV-52896r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" "Enabled"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3385
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to require case insensitivity for non-Windows subsystems.
            "SV-52897r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"System objects: Require case insensitivity for non-Windows subsystems" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" "ObCaseInsensitive"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3449
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Desktop Services must limit users to one remote session.
            "SV-52216r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Connections
                #"Restrict Remote Desktop Services users to a single Remote Desktop Services Session" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fSingleSessionPerUser"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3453
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Desktop Services must always prompt a client for passwords upon connection.
            "SV-52898r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security 
                #"Always prompt for password upon connection" to "Enabled". 
                $Value = Check-RegKeyValue "hklm\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3454
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Desktop Services must be configured with the client connection encryption set to the required level.
            "SV-52899r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
                #"Set client connection encryption level" to "Enabled" and "High Level". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "MinEncryptionLevel"
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3455
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Desktop Services must be configured to use session-specific temporary folders.
            "SV-52900r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders
                #"Do not use temporary folders per session" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "PerSessionTempDir"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3456
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Desktop Services must delete temporary folders when a session is terminated.
            "SV-52901r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders
                #"Do not delete temp folder upon exit" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "DeleteTempDirsOnExit"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3469
            #Windows Server 2012/2012 R2 MS STIG
            #Group Policies must be refreshed in the background if the user is logged on.
            "SV-52906r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Group Policy
                #"Turn off background refresh of Group Policy" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableBkGndGroupPolicy"
                if ($Value -eq "1") {$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-3470
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent unsolicited remote assistance offers.
            "SV-52917r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
                #"Configure Offer Remote Assistance" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fAllowUnsolicited"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3472
            #Windows Server 2012/2012 R2 MS STIG
            #The time service must synchronize with an appropriate DoD time source.
            "SV-52919r3_rule" {
                #Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers
                #"Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.
                #If PDC and time set to NTP this assumes that the source is correct. If anything else, it should be NT5DS.
                $timeSettings = W32tm /query /configuration
                $type = ($timeSettings -match "Type: ").trim().split(":")[1].trim().split(" ")[0].trim()
                if($env:computername+'.'+$env:USERDNSDOMAIN -eq $PDC){
                    if($type -eq "NTP"){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"}
                    }
                elseif($type -eq "NT5DS") {$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-3479
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to use Safe DLL Search Mode.
            "SV-52920r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "SafeDllSearchMode"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-3480
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Media Player must be configured to prevent automatic checking for updates.
            "SV-53130r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player
                #"Prevent Automatic Updates" to "Enabled". 
                #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {$ActualStatus = "Not_Applicable"} #Get-WindowsOptionalFeature is PSv4+
                if ((Get-WmiObject Win32_OptionalFeature -Filter "name = 'WindowsMediaPlayer'").InstallState -ne 1) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" "DisableAutoupdate"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-3481
            #Windows Server 2012/2012 R2 MS STIG
            #Media Player must be configured to prevent automatic Codec downloads.
            "SV-52921r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback
                #"Prevent Codec Download" to "Enabled". 
                #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {$ActualStatus = "Not_Applicable"} #Get-WindowsOptionalFeature is PSv4+
                if ((Get-WmiObject Win32_OptionalFeature -Filter "name = 'WindowsMediaPlayer'").InstallState -ne 1) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer\" "PreventCodecDownload"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-3666
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers.
            "SV-52922r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinServerSec"
                if ($Value -eq "537395200") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4108
            #Windows Server 2012/2012 R2 MS STIG
            #The system must generate an audit event when the audit log reaches a percentage of full threshold.
            "SV-52923r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90" or less.
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Eventlog\Security\" "WarningLevel"
                if ($Value -eq "90") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4110
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent IP source routing.
            "SV-52924r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "DisableIPSourceRouting"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4111
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.
            "SV-52925r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnableICMPRedirect"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4112
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to disable the Internet Router Discovery Protocol (IRDP).
            "SV-52926r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "PerformRouterDiscovery"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4113
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to limit how often keep-alive packets are sent.
            "SV-52927r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "KeepAliveTime"
                if ($Value -eq "300000") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4116
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to ignore NetBIOS name release requests except from WINS servers.
            "SV-52928r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" "NoNameReleaseOnDemand"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4407
            #Windows Server 2012/2012 R2 DC STIG
            #Domain controllers must require LDAP access signing.
            "SV-51140r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain controller: LDAP server signing requirements" to "Require signing". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\NTDS\Parameters\" "LDAPServerIntegrity"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-4408
            #Windows Server 2012/2012 R2 DC STIG
            #Domain controllers must be configured to allow reset of machine account passwords.
            "SV-51141r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain controller: Refuse machine account password changes" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RefusePasswordChange"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4438
            #Windows Server 2012/2012 R2 MS STIG
            #The system must limit how many times unacknowledged TCP data is retransmitted.
            "SV-52929r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less. 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "TcpMaxDataRetransmissions"
                if ($Value -le 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4442
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.
            "SV-52930r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "ScreenSaverGracePeriod"
                if ($Value -le 5) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4443
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized remotely accessible registry paths and sub-paths must not be configured.
            "SV-52931r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Remotely accessible registry paths and sub-paths" with the following entries:
                $paths = @"
Software\Microsoft\OLAP Server
Software\Microsoft\Windows NT\CurrentVersion\Perflib
Software\Microsoft\Windows NT\CurrentVersion\Print
Software\Microsoft\Windows NT\CurrentVersion\Windows
System\CurrentControlSet\Control\ContentIndex
System\CurrentControlSet\Control\Print\Printers
System\CurrentControlSet\Control\Terminal Server
System\CurrentControlSet\Control\Terminal Server\UserConfig
System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
System\CurrentControlSet\Services\Eventlog
System\CurrentControlSet\Services\Sysmonlog 
"@.split("`n") | Foreach {$_.trim()}
                
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\" "Machine"
                foreach ($item in $paths) {
                    if ($value -notcontains $item) {$ActualStatus = "Open"}
                    }
                if ($ActualStatus -ne "Open" -and $Value.count -eq 11) {$ActualStatus = "NotAFinding"}
                elseif ($ActualStatus -ne "Open" -and $Value.count -gt 11) {
                    $title = "ISSO documented?"
                    $message = "Do we have documentation with the ISSO for the following paths (per V-226320)?`n" + ($value | Where {$paths -notcontains $_} -join "`n")
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    
                    if ($result -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-4445
            #Windows Server 2012/2012 R2 MS STIG
            #Optional Subsystems must not be permitted to operate on the system.
            "SV-52219r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"System settings: Optional subsystems" to "Blank" (Configured with no entries). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems\" "Optional"
                if ($Value -eq "") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4447
            #Windows Server 2012/2012 R2 MS STIG
            #The Remote Desktop Session Host must require secure RPC communications.
            "SV-52932r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
                #"Require secure RPC communication" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fEncryptRPCTraffic"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-4448
            #Windows Server 2012/2012 R2 MS STIG
            #Group Policy objects must be reprocessed even if they have not changed.
            "SV-52933r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Group Policy
                #"Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" "NoGPOListChanges"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6831
            #Windows Server 2012/2012 R2 MS STIG
            #Outgoing secure channel traffic must be encrypted or signed.
            "SV-52934r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireSignOrSeal"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6832
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows SMB client must be configured to always perform SMB packet signing.
            "SV-52935r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network client: Digitally sign communications (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "RequireSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6833
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows SMB server must be configured to always perform SMB packet signing.
            "SV-52936r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Digitally sign communications (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "RequireSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6834
            #Windows Server 2012/2012 R2 MS STIG
            #Anonymous access to Named Pipes and Shares must be restricted.
            "SV-52937r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "RestrictNullSessAccess"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6836
            #Windows Server 2012/2012 R2 MS STIG
            #Passwords must, at a minimum, be 14 characters.
            "SV-52938r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Minimum password length" to "14" characters. 
                #This is set in default domain policy
                if($passwordpolicy.MinPasswordLength -eq 14){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-6840
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012/2012 R2 passwords must be configured to expire.
            "SV-52939r4_rule" {
                if($ServerRole -eq 2){
                    $V6840=$users | where {$_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true -and $_.smartcardlogonrequired -eq $false -and $_.extensionAttribute3 -ne "SVC"}
                    if($V6840.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following accounts were found: `n$v6840"}
                    }
                else{
                    if(((Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' and PasswordExpires='False'").Name).count -eq 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                }

            #V-7002
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012/2012 R2 accounts must be configured to require passwords.
            "SV-52940r3_rule" {
                if($ServerRole -eq 2){
                    $V7002=$users | where {$_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true -and $_.smartcardlogonrequired -eq $false}
                    if($V7002.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following accounts were found: `n$V7002"}
                }
                else{
                    $nopwd = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount
                    if($nopwd.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus -ne "Open"}
                    }
                }

            #V-7055
            #Microsoft DotNet Framework 4.0 STIG
            #Digital signatures assigned to strongly named assemblies must be verified.
            "SV-7438r3_rule" { 
                $reg = Get-ItemProperty "Registry::HKLM\Software\Microsoft\StrongName\Verification" -EA SilentlyContinue
                if ($reg -ne $null) {
                    $values = $reg  | Get-Member -MemberType NoteProperty | where {$_.name -ne "(default)" -and $_.Name -cnotlike "PS*"}
                    $subkeys = Get-ChildItem "Registry::HKLM\Software\Microsoft\StrongName\Verification" -EA SilentlyContinue
                    if ($subkeys -eq $null -and $values -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000382981"}
                    }
                else {$ActualStatus = "NotAFinding"}
                }

            #V-7061
            #Microsoft DotNet Framework 4.0 STIG
            #The Trust Providers Software Publishing State must be set to 0x23C00.
            "SV-7444r3_rule" {
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus=$null
                    $SIDs = @()
                    $SIDs += Get-ChildItem -Path "Registry::HKEY_USERS" -EA SilentlyContinue | Where {$_.Name.Length -gt 20 -and $_.Name -notlike "*_Classes"} | select -ExpandProperty name | foreach {$_.split("\")[1]}
                    foreach ($SID in $SIDs) {
                        $value = Check-RegKeyValue "HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" "State"
                        if ($value -ne 146432) {$ActualStatus = "Open"}
                        }
                    if ($ActualStatus -eq $null) {$ActualStatus = "NotAFinding"}
                    }
                }

            #V-7070
            #Microsoft DotNet Framework 4.0 STIG
            #Remoting Services HTTP channels must utilize authentication and encryption.
            "SV-7453r3_rule" {
                #TODO
                $files=@()
                foreach($file in $execonfiglist | Where-Object {$_.length -ge 1}){
                    $files+=Select-String -Path $file -Pattern '<channel ref=“http server” port=“80”/>' -SimpleMatch}
                foreach($file in $machineConfig | Where-Object {$_.length -ge 1}){
                    $files+=Select-String -Path $file -Pattern '<channel ref=“http server” port=“80”/>' -SimpleMatch}
                if($files.count -eq 0){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"
                foreach($thing in $files.path){$output+="$thing`n"}
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Manually check the following files: `n$output"}
                }

            #V-8316
            #Windows Server 2012/2012 R2 DC STIG
            #Active Directory data files must have proper access control permissions.
            "SV-51175r3_rule" { 
                #Since anyone that opens the NTDS folder gets added with full control, this check makes sure that any extra accounts are admin accounts based on the level codes in the naming convention TO.
                $NTDSacl=(Get-Acl E:\Windows\NTDS).Access
                $accounts=($NTDSacl | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }
                
            #V-8322
            #Windows Server 2012/2012 R2 DC STIG
            #Time synchronization must be enabled on the domain controller.
            "SV-51181r2_rule" {
                $Value1 = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient\" "Enabled"
                $Value2 = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\W32Time\Parameters\" "Type"
                if ($Value1 -eq "1") {
                    if ($Value2 -eq "NT5DS" -or $Value2 -eq "NTP" -or $Value2 -eq "Allsync") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {
                    $title = "Alt timesource?"
                    $message = "Is this server configured to use an alternate time source?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-8324
            #Windows Server 2012/2012 R2 DC STIG
            #The time synchronization tool must be configured to enable logging of time source switching.
            "SV-51182r3_rule" {
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\W32Time\Config\" "EventLogFlags"
                if ($Value -eq "2" -or $Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-8327
            #Windows Server 2012/2012 R2 DC STIG
            #Windows services that are critical for directory server operation must be configured for automatic startup.
            "SV-51184r2_rule" {
                $RequiredServices = @"
Active Directory Domain Services
DFS Replication
DNS Client
DNS server
Group Policy Client
Intersite Messaging
Kerberos Key Distribution Center
NetLogon 
"@.split("`n") | foreach {$_.trim()}
                foreach ($service in $RequiredServices) {
                    if ((Get-Service -DisplayName $service).StartType -ne "Automatic") {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "$service is not set to start automatically"}
                    }
                if ($ActualStatus -ne "Open" -and (Get-Service -DisplayName "Windows Time").StartType -ne "Automatic") {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Windows Time is not set to start automatically"}
                if ($ActualStatus -ne "Open") {$ActualStatus = "NotAFinding"}
                }

            #V-11806
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to prevent the display of the last username on the logon screen.
            "SV-52941r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive logon: Do not display last user name" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DontDisplayLastUserName"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-12780
            #Windows Server 2012/2012 R2 MS STIG
            #The Synchronize directory service data user right must be configured to include no accounts or groups (blank).
            "SV-51150r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Synchronize directory service data" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeSyncAgentPrivilege"){
                    $value = $UserRights | Where-Object {$_.UserRight -eq "SeSyncAgentPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-14225
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012/2012 R2 password for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.
            "SV-52942r3_rule" {
                #Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet
                if($ServerRole -eq 3){
                    if($Admin.PasswordLastSet -gt (Get-Date).AddYears(-1)){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should change the local admin password."}
                    }
                elseif($ServerRole -eq 2){
                    if($Admin.PasswordLastSet -gt (get-date).AddYears(-1)) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The password was last set: $($Admin.PasswordLastSet)"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                }

            #V-14228
            #Windows Server 2012/2012 R2 MS STIG
            #Auditing the Access of Global System Objects must be turned off.
            "SV-53129r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Audit: Audit the access of global system objects" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "AuditBaseObjects"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14229
            #Windows Server 2012/2012 R2 DC STIG
            #Auditing of Backup and Restore Privileges must be turned off.
            "SV-52943r2_rule" {
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "FullPrivilegeAuditing"
                if ($Value -eq "00") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14230
            #Windows Server 2012/2012 R2 MS STIG
            #Audit policy using subcategories must be enabled.
            "SV-52944r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "SCENoApplyLegacyAuditPolicy"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14232
            #Windows Server 2012/2012 R2 MS STIG
            #IPSec Exemptions must be limited.
            "SV-52945r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Only ISAKMP is exempt (recommended for Windows Server 2003)".
                #See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\IPSEC\" "NoDefaultExempt"
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14234
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control approval mode for the built-in Administrator must be enabled.
            "SV-52946r1_rule" {
                #Not Applicable if Server Core
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "FilterAdministratorToken"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14235
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must, at minimum, prompt administrators for consent.
            "SV-52947r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".
                #More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop). 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorAdmin"
                    if ($Value -le 4 -and $Value -gt 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14236
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must automatically deny standard user requests for elevation.
            "SV-52948r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorUser"
                    if ($Value -eq 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14237
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must be configured to detect application installations and prompt for elevation.
            "SV-52949r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Detect application installations and prompt for elevation" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableInstallerDetection"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14239
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must only elevate UIAccess applications that are installed in secure locations.
            "SV-52950r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableSecureUIAPaths"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14240
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
            "SV-52951r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Run all administrators in Admin Approval Mode" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableLUA"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14241
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must switch to the secure desktop when prompting for elevation.
            "SV-52952r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Switch to the secure desktop when prompting for elevation" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "PromptOnSecureDesktop"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14242
            #Windows Server 2012/2012 R2 MS STIG
            #User Account Control must virtualize file and registry write failures to per-user locations.
            "SV-52953r1_rule" {
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableVirtualization"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14243
            #Windows Server 2012/2012 R2 MS STIG
            #Administrator accounts must not be enumerated during elevation.
            "SV-52955r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface
                #"Enumerate administrator accounts on elevation" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" "EnumerateAdministrators"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14247
            #Windows Server 2012/2012 R2 MS STIG
            #Passwords must not be saved in the Remote Desktop Client.
            "SV-52958r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client
                #"Do not allow passwords to be saved" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "DisablePasswordSaving"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14249
            #Windows Server 2012/2012 R2 MS STIG
            #Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).
            "SV-52959r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow drive redirection" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCdm"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14253
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthenticated RPC clients must be restricted from connecting to the RPC server.
            "SV-52988r2_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call
                #"Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" "RestrictRemoteClients"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14259
            #Windows Server 2012/2012 R2 MS STIG
            #Printing over HTTP must be prevented.
            "SV-52997r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off printing over HTTP" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableHTTPPrinting"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14260
            #Windows Server 2012/2012 R2 MS STIG
            #Downloading print driver packages over HTTP must be prevented.
            "SV-52998r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off downloading of print drivers over HTTP" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableWebPnPDownload"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14261
            #Windows Server 2012/2012 R2 MS STIG
            #Windows must be prevented from using Windows Update to search for drivers.
            "SV-53000r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off Windows Update device driver searching" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" "DontSearchWindowsUpdate"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14268
            #Windows Server 2012/2012 R2 MS STIG
            #Zone information must be preserved when saving attachments.
            "SV-53002r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
                #"Do not preserve zone information in file attachments" to "Disabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "SaveZoneInformation"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14269
            #Windows Server 2012/2012 R2 MS STIG
            #Mechanisms for removing zone information from file attachments must be hidden.
            "SV-53004r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
                #"Hide mechanisms to remove zone information" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "HideZoneInfoOnProperties"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14270
            #Windows Server 2012/2012 R2 MS STIG
            #The system must notify antivirus when file attachments are opened.
            "SV-53006r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
                #"Notify antivirus programs when opening attachments" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "ScanWithAntiVirus"
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-14797
            #Windows Server 2012/2012 R2 DC STIG
            #Anonymous access to the root DSE of a non-public directory must be disabled.
            "SV-51186r2_rule" {
                #STIG says theres literally no way to close this vuln
                if($IsNIPR){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $SIPRMFR}
                }

            #V-14820
            #Windows Server 2012/2012 R2 DC STIG
            #Domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA).
            "SV-51190r2_rule" {
                $cert = Get-ChildItem Cert:\Localmachine\My
                $issuer = $cert.Issuer.split(",")[0].Split("=")[1]
                #Our list of trusted CA
                $DoDorECA = @"
AFNOAPPS LTMA CA-1
AFNOAPPS LTMA CA-2
NSS SW CA-2
NSS SW CA-4
NSS SW-CA-4
NSS SW-CA-7
"@.Split("`n") | foreach {$_.trim()}
                if ($DoDorECA -contains $issuer) {$ActualStatus = "NotAFinding"}
                else {
                    #Prompt user to see if we trust it.  If we do, add it to the script
                    $title = "Trusted CA?"
                    $message = "Is $issuer a trusted DoD CA or ECA?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
                    $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    if ($result -eq 1) {
                        [System.Collections.ArrayList]$SelfScript = Get-Content $MyInvocation.MyCommand.Definition
                        for ($i = 0;$i -lt $SelfScript.count -and $SelfScript[$i] -notlike "*DoDorECA = @*";$i++) {;}
                        $SelfScript.Insert($i + 1,$issuer)
                        Out-File -InputObject $SelfScript -Encoding default -LiteralPath $MyInvocation.MyCommand.Definition
                        $ActualStatus = "NotAFinding"
                        }
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-14831
            #Windows Server 2012/2012 R2 DC STIG
            #The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.
            "SV-51188r2_rule" {
                #I figured it out - Calabrese
                $ForestName=(Get-ADForest).name.split(".") -join ",DC="
                $LDAPAdminLimits=dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,DC=$ForestName" -attr LDAPAdminLimits
                $MaxConnIdleTime=($LDAPAdminLimits.Split(";") | Select-String -Pattern MaxConnIdleTime).ToString().TrimStart(" MaxConnIdleTime=")
                if([int]$MaxConnIdleTime -le 300){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "This is set to $MaxConnIdleTime"}
                }

            #V-15505
            #Windows Server 2012/2012 R2 MS STIG
            #The HBSS McAfee Agent must be installed.
            "SV-53010r3_rule" {
                if ($installedprograms.displayname -contains "McAfee Agent") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15666
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Peer-to-Peer networking services must be turned off.
            "SV-53012r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services
                #"Turn off Microsoft Peer-to-Peer Networking Services" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Peernet\" "Disabled"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15667
            #Windows Server 2012/2012 R2 MS STIG
            #Network Bridges must be prohibited in Windows.
            "SV-53014r2_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Network Connections
                #"Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" "NC_AllowNetBridge_NLA"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15672
            #Windows Server 2012/2012 R2 MS STIG
            #Event Viewer Events.asp links must be turned off.
            "SV-53017r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off Event Viewer "Events.asp" links" to "Enabled"
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\EventViewer\" "MicrosoftEventVwrDisableLinks"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15674
            #Windows Server 2012/2012 R2 MS STIG
            #The Internet File Association service must be turned off.
            "SV-53021r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off Internet File Association service" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoInternetOpenWith"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15680
            #Windows Server 2012/2012 R2 MS STIG
            #The classic logon screen must be required for user logons.
            "SV-53036r2_rule" { 
                #If the system is a member of a domain, this is NA.
                #Computer Configuration >> Administrative Templates >> System >> Logon
                #"Always use classic logon" to "Enabled". 
                if ($PartOfDomain) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LogonType"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-15682
            #Windows Server 2012/2012 R2 MS STIG
            #Attachments must be prevented from being downloaded from RSS feeds.
            "SV-53040r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
                #"Prevent downloading of enclosures" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "DisableEnclosureDownload"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15683
            #Windows Server 2012/2012 R2 MS STIG
            #File Explorer shell protocol must run in protected mode.
            "SV-53045r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off shell protocol protected mode" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "PreXPSP2ShellProtocolBehavior"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15684
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be notified if a web-based program attempts to install software.
            "SV-53056r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "SafeForScripting"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15685
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prevented from changing installation options.
            "SV-53061r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Allow user control over installs" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "EnableUserControl"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15686
            #Windows Server 2012/2012 R2 MS STIG
            #Nonadministrators must be prevented from applying vendor-signed updates.
            "SV-53065r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Prohibit non-administrators from applying vendor signed updates" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "DisableLUAPatching"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15687
            #Windows Server 2012/2012 R2 MS STIG
            #Users must not be presented with Privacy and Installation options on first use of Windows Media Player.
            "SV-53069r1_rule" {
                #If no Windows Media Player, NA
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player
                #"Do Not Show First Use Dialog Boxes" to "Enabled".
                #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {$ActualStatus = "Not_Applicable"} #Get-WindowsOptionalFeature is PSv4+
                if ((Get-WmiObject Win32_OptionalFeature -Filter "name = 'WindowsMediaPlayer'").InstallState -ne 1) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" "GroupPrivacyAcceptance"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-15696
            #Windows Server 2012/2012 R2 MS STIG
            #The Mapper I/O network protocol (LLTDIO) driver must be disabled.
            "SV-53072r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery
                #"Turn on Mapper I/O (LLTDIO) driver" to "Disabled". 
                $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowLLTDIOOndomain"
                $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowLLTDIOOnPublicNet"
                $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "EnableLLTDIO"
                $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "ProhibitLLTDIOOnPrivateNet"
                if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15697
            #Windows Server 2012/2012 R2 MS STIG
            #The Responder network protocol driver must be disabled.
            "SV-53081r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery
                #"Turn on Responder (RSPNDR) driver" to "Disabled". 
                $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowRspndrOndomain"
                $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowRspndrOnPublicNet"
                $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "EnableRspndr"
                $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "ProhibitRspndrOnPrivateNet"
                if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15698
            #Windows Server 2012/2012 R2 MS STIG
            #The configuration of wireless devices using Windows Connect Now must be disabled.
            "SV-53085r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now
                #"Configuration of wireless settings using Windows Connect Now" to "Disabled". 
                $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableFlashConfigRegistrar"
                $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableInBand802DOT11Registrar"
                $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableUPnPRegistrar"
                $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableWPDRegistrar"
                $Value5 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "EnableRegistrars"
                if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0" -and $Value5 -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15699
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Connect Now wizards must be disabled.
            "SV-53089r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now
                #"Prohibit access of the Windows Connect Now wizards" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\UI\" "DisableWcnUi"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15700
            #Windows Server 2012/2012 R2 MS STIG
            #Remote access to the Plug and Play interface must be disabled for device installation.
            "SV-53094r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation 
                #"Allow remote access to the Plug and Play interface" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "AllowRemoteRPC"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15701
            #Windows Server 2012/2012 R2 MS STIG
            #A system restore point must be created when a new device driver is installed.
            "SV-53099r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation
                #"Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSystemRestore"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15702
            #Windows Server 2012/2012 R2 MS STIG
            #An Error Report must not be sent when a generic device driver is installed.
            "SV-53105r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation
                #"Do not send a Windows error report when a generic driver is installed on a device" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSendGenericDriverNotFoundToWER"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15703
            #Windows Server 2012/2012 R2 MS STIG
            #Users must not be prompted to search Windows Update for device drivers.
            "SV-53115r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Driver Installation
                #"Turn off Windows Update device driver search prompt" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "DontPromptForWindowsUpdate"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15704
            #Windows Server 2012/2012 R2 MS STIG
            #Errors in handwriting recognition on tablet PCs must not be reported to Microsoft.
            "SV-53116r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off handwriting recognition error reporting" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports\" "PreventHandwritingErrorReports"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15705
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prompted to authenticate on resume from sleep (on battery).
            "SV-53131r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
                #"Require a password when a computer wakes (on battery)" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "DCSettingIndex"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15706
            #Windows Server 2012/2012 R2 MS STIG
            #The user must be prompted to authenticate on resume from sleep (plugged in).
            "SV-53132r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
                #"Require a password when a computer wakes (plugged in)" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "ACSettingIndex"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15707
            #Windows Server 2012/2012 R2 MS STIG
            #Remote Assistance log files must be generated.
            "SV-53133r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
                #"Turn on session logging" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "LoggingEnabled"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15713
            #Windows Server 2012/2012 R2 MS STIG
            #Microsoft Active Protection Service membership must be disabled.
            "SV-53134r2_rule" {
                #We only have 2012 R2 servers, not 2012
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender -> MAPS
                #"Join Microsoft MAPS" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\" "SpyNetReporting" "SilentlyContinue"
                if ($Value -eq "1" -or $Value -eq "2") {$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-15718
            #Windows Server 2012/2012 R2 MS STIG
            #Turning off File Explorer heap termination on corruption must be disabled.
            "SV-53137r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off heap termination on corruption" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoHeapTerminationOnCorruption"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15722
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet.
            "SV-53139r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management
                #"Prevent Windows Media DRM Internet Access" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WMDRM\" "DisableOnline"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15727
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prevented from sharing files in their profiles.
            "SV-53140r2_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Network Sharing
                #"Prevent users from sharing files within their profile" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoInPlaceSharing"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15823
            #Windows Server 2012/2012 R2 MS STIG
            #Software certificate installation files must be removed from Windows 2012/2012 R2.
            "SV-53141r4_rule" {
                if($softcerts.count -eq 0){$ActualStatus = "NotAFinding"}
                else{
                    $badcerts=@()
                    foreach($cert in $softcerts){
                        if($cert -ne "C:\Program Files\Quest\Recovery Manager for Active Directory Forest Edition\RecoveryAgent.pfx"){$badcerts+=$cert}
                        }
                    if($badcerts.count -eq 0){$ActualStatus="NotAFinding"}
                    else {
                        $ActualStatus = "Open"
                        $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following files caused this to be a finding: $badcerts"
                        }
                    }
                }

            #V-15991
            #Windows Server 2012/2012 R2 MS STIG
            #UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.
            "SV-52223r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableUIADesktopToggle"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15997
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop Services Role).
            "SV-52224r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow COM port redirection" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCcm"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15998
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prevented from mapping local LPT ports and redirecting data from the Remote Desktop Session Host to local LPT ports.  (Remote Desktop Services Role).
            "SV-52226r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow LPT port redirection" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableLPT"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-15999
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host.  (Remote Desktop Services Role).
            "SV-52229r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow supported Plug and Play device redirection" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisablePNPRedir"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-16000
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session.  (Remote Desktop Services Role).
            "SV-52230r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow smart card device redirection" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fEnableSmartCard"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-16008
            #Windows Server 2012/2012 R2 MS STIG
            #Windows must elevate all applications in User Account Control, not just signed ones.
            "SV-53142r1_rule" {
                #NA if server core
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Only elevate executables that are signed and validated" to "Disabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ValidateAdminCodeSignatures"
                    if ($Value -eq 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-16020
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Customer Experience Improvement Program must be disabled.
            "SV-53143r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings 
                #"Turn off Windows Customer Experience Improvement Program" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\SQMClient\Windows" "CEIPEnable"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-16021
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Help Experience Improvement Program must be disabled.
            "SV-53144r1_rule" {
                #User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings
                #"Turn off Help Experience Improvement Program" to "Enabled".
                $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0\" "NoImplicitFeedback" "SilentlyContinue"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-16048
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Help Ratings feedback must be turned off.
            "SV-53145r1_rule" {
                #User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings
                #"Turn off Help Ratings" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0\" "NoExplicitFeedback" "SilentlyContinue"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-18010
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Debug programs user right.
            "SV-52115r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Debug programs" to only include the following accounts or groups:
                #Administrators 
                $value = $UserRights | Where-Object {$_.UserRight -eq "SeDebugPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators" -or $value -eq $null) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26070
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-53123r4_rule" { 
                $FCIR=@('BUILTIN\Administrators','NT AUTHORITY\SYSTEM','NT SERVICE\TrustedInstaller')
                $RIR=@('BUILTIN\Users','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES')
                $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
                
                if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000385464"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-21950
            #Windows Server 2012/2012 R2 MS STIG
            #The service principal name (SPN) target name validation level must be turned off.
            "SV-53175r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Server SPN target name validation level" to "Off". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\" "SmbServerNameHardeningLevel"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21951
            #Windows Server 2012/2012 R2 MS STIG
            #Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.
            "SV-53176r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow Local System to use computer identity for NTLM" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\" "UseMachineId"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21952
            #Windows Server 2012/2012 R2 MS STIG
            #NTLM must be prevented from falling back to a Null session.
            "SV-53177r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow LocalSystem NULL session fallback" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\MSV1_0\" "allownullsessionfallback"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21953
            #Windows Server 2012/2012 R2 MS STIG
            #PKU2U authentication using online identities must be prevented.
            "SV-53178r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" "AllowOnlineID"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21954
            #Windows Server 2012/2012 R2 MS STIG
            #Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
            "SV-53179r4_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Network security: Configure encryption types allowed for Kerberos" is configured, only the following selections are allowed:
                #AES128_HMAC_SHA1
                #AES256_HMAC_SHA1
                #Future encryption types 

                #This value is stored in bits.  The 1 bit is DES_CBC_CRC, the 2 bit is DES_CBC_MD5, the 4 bit is RC4_HMAC_MD5, the 8 bit is AES128_HMAC_SHA1, the 16 bit is AES256_HMAC_SHA1, and for "Future encryption types" they just turn on every other bit.
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes"
                #if (!($Value -band 1) -and !($value -band 2) -and !($value -band 4) -and $value -band 8 -and $value -band 16) {$ActualStatus = "NotAFinding"} #These checks make sure each bit flag is set properly.  I'm an idiot in trying to be smart by doing this complicated, because checking for every other bit is stupid
                if ($value -eq "2147483640") {$ActualStatus = "NotAFinding"}
                else {
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR + ". This finding is covered by the USAF STIG Deviation Memo."}
                }

            #V-21955
            #Windows Server 2012/2012 R2 MS STIG
            #IPv6 source routing must be configured to the highest protection level.
            "SV-53180r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\" "DisableIpSourceRouting"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21956
            #Windows Server 2012/2012 R2 MS STIG
            #IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.
            "SV-53181r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" "TcpMaxDataRetransmissions"
                if ($Value -le 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21960
            #Windows Server 2012/2012 R2 MS STIG
            #Domain users must be required to elevate when setting a networks location.
            "SV-53182r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Network Connections
                #"Require domain users to elevate when setting a network's location" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" "NC_StdDomainUserSetLocation"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21961
            #Windows Server 2012/2012 R2 MS STIG
            #All Direct Access traffic must be routed through the internal network.
            "SV-53183r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> Network Connections
                #"Route all traffic through the internal network" to "Enabled: Enabled State". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "Force_Tunneling"
                if ($Value -eq "Enabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21963
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Update must be prevented from searching for point and print drivers.
            "SV-53184r1_rule" {
                #Computer Configuration -> Administrative Templates -> Printers
                #"Extend Point and Print connection to search Windows Update" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DoNotInstallCompatibleDriverFromWindowsUpdate"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21964
            #Windows Server 2012/2012 R2 MS STIG
            #Device metadata retrieval from the Internet must be prevented.
            "SV-53185r2_rule" {
                #Computer Configuration >> Administrative Templates >> System >> Device Installation
                #"Prevent device metadata retrieval from the Internet" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Device Metadata\" "PreventDeviceMetadataFromNetwork"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21965
            #Windows Server 2012/2012 R2 MS STIG
            #Device driver searches using Windows Update must be prevented.
            "SV-53186r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation
                #"Specify search order for device driver source locations" to "Enabled: Do not search Windows Update".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "SearchOrderConfig"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21967
            #Windows Server 2012/2012 R2 MS STIG
            #Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft must be prevented.
            "SV-53187r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Microsoft Support Diagnostic Tool
                #"Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" "DisableQueryRemoteServer"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21969
            #Windows Server 2012/2012 R2 MS STIG
            #Access to Windows Online Troubleshooting Service (WOTS) must be prevented.
            "SV-53188r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics
                #"Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via the Windows Online Troubleshooting Service - WOTS)" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" "EnableQueryRemoteServer"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21970
            #Windows Server 2012/2012 R2 MS STIG
            #Responsiveness events must be prevented from being aggregated and sent to Microsoft.
            "SV-53128r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Windows Performance PerfTrack
                #"Enable/Disable PerfTrack" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" "ScenarioExecutionEnabled"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21971
            #Windows Server 2012/2012 R2 MS STIG
            #The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
            "SV-53127r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility
                #"Turn off Inventory Collector" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" "DisableInventory"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21973
            #Windows Server 2012/2012 R2 MS STIG
            #Autoplay must be turned off for non-volume devices.
            "SV-53126r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
                #"Disallow Autoplay for non-volume devices" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoAutoplayfornonVolume"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-21980
            #Windows Server 2012/2012 R2 MS STIG
            #Explorer Data Execution Prevention must be enabled.
            "SV-53125r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off Data Execution Prevention for Explorer" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoDataExecutionPrevention"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-22692
            #Windows Server 2012/2012 R2 MS STIG
            #The default Autorun behavior must be configured to prevent Autorun commands.
            "SV-53124r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
                #"Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoAutorun"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26283
            #Windows Server 2012/2012 R2 MS STIG
            #Anonymous enumeration of SAM accounts must not be allowed.
            "SV-53122r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictAnonymousSAM"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26359
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows dialog box title for the legal banner must be configured.
            "SV-53121r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive Logon: Message title for users attempting to log on" one of the following:
                #"DoD Notice and Consent Banner"
                #"US Department of Defense Warning Statement"
                #A site-defined equivalent.
                #    If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-226288. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeCaption"
                if ($Value -eq "DoD Notice and Consent Banner" -or $Value -eq "US Department of Defense Warning Statement") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26469
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Access Credential Manager as a trusted caller user right.
            "SV-53120r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Access Credential Manager as a trusted caller" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeTrustedCredManAccessPrivilege"){
                    $value = $UserRights | Where-Object {$_.UserRight -eq "SeTrustedCredManAccessPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26470
            #Windows Server 2012/2012 R2 DC STIG
            #Unauthorized accounts must not have the Access this computer from the network user right on domain controllers.
            "SV-51142r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Access this computer from the network" to only include the following accounts or groups:
                #Administrators
                #Authenticated Users
                #Enterprise Domain Controllers 
                $value = $UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
                if ($value.count -eq 3 -and $value -contains "Administrators" -and $value -contains "Authenticated Users" -and $value -contains "Enterprise Domain Controllers") {$ActualStatus = "NotAFinding"}
                elseif ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26470
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Access this computer from the network user right on domain controllers.
            "SV-51499r4_rule" {
            #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Access this computer from the network" to only include the following accounts or groups:
                #Administrators
                #Authenticated Users
                $value = $UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
                if ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26472
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Allow log on locally user right.
            "SV-52110r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Allow log on locally" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26473
            #Windows Server 2012/2012 R2 DC STIG
            #The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.
            "SV-53119r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Allow log on through Remote Desktop Services" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-26473
            #Windows Server 2012/2012 R2 MS STIG
            #The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.
            "SV-83319r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Allow log on through Remote Desktop Services" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }          

            #V-26474
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the back up files and directories user right.
            "SV-52111r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Back up files and directories" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeBackupPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26476
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Change the system time user right.
            "SV-53118r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Change the system time" to only include the following accounts or groups:
                #Administrators 
                #Local Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeSystemTimePrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 2 -and $value -contains "Administrators" -and $value -contains "Local Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26478
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Create a pagefile user right.
            "SV-53063r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create a pagefile" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreatePagefilePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26479
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Create a token object user right.
            "SV-52113r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create a token object" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeCreateTokenPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateTokenPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26480
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Create global objects user right.
            "SV-52114r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create global objects" to only include the following accounts or groups:
                #Administrators
                #Service
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateGlobalPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26481
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Create permanent shared objects user right.
            "SV-53059r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create permanent shared objects" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeCreatePermanentPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreatePermanentPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26482
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Create symbolic links user right.
            "SV-53054r3_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
                #"Create symbolic links" to only include the following accounts or groups:
                #Administrators
                #Systems that have the Hyper-V role will also have "Virtual Machines" given this user right. If this needs to be added manually, enter it as "NT Virtual Machine\Virtual Machines". 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateSymbolicLinkPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 1 -and $value -contains "Administrators") {$ActualStatus = "NotAFinding"}
                elseif ($value.Count -eq 2 -and $value -contains "Administrators" -and $value -contains "NT Virtual Machine\\Virtual Machines" -and ($installedFeatures.Name -contains "Hyper-V")) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26483
            #Windows Server 2012/2012 R2 MS STIG
            #The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.
            "SV-51502r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a batch job" to include the following:
                #Domain Systems Only:
                #Enterprise Admins Group
                #Domain Admins Group
                #
                #All Systems:
                #Guests Group 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
                if ($PartOfDomain) {
                        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                else {
                    if ($value -eq "Guests"){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-26483
            #Windows Server 2012/2012 R2 DC STIG
            #The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-51145r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a batch job" to include the following:
                #Guests Group 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
                if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26484
            #Windows Server 2012/2012 R2 MS STIG
            #The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.
            "SV-51504r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a service" to include the following for domain-joined systems:
                #Enterprise Admins Group
                #Domain Admins Group
                #
                #Configure the "Deny log on as a service" for nondomain systems to include no entries (blank). 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
                if ($PartOfDomain) {
                    if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {
                    if ($value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-26484
            #Windows Server 2012/2012 R2 DC STIG
            #The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.
            "SV-51146r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a service" to include no entries (blank). 
                if($UserRights.UserRight -contains "SeDenyServiceLogonRight"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26485
            #Windows Server 2012/2012 R2 MS STIG
            #The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.
            "SV-51508r3_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on locally" to include the following:
                #Domain Systems Only:
                #Enterprise Admins Group
                #Domain Admins Group
                #
                #All Systems:
                #Guests Group 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($PartOfDomain) {
                    if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-26485
            #Windows Server 2012/2012 R2 DC STIG
            #The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-51147r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on locally" to include the following:
                #Guests Group 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($value -contains "Guests") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26486
            #Windows Server 2012/2012 R2 MS STIG
            #The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems, and from unauthenticated access on all systems.
            "SV-51509r5_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
                #"Deny log on through Remote Desktop Services" to include the following:
                #Domain Systems Only:
                #Enterprise Admins group
                #Domain Admins group
                #Local account (see Note below)
                #
                #All Systems:
                #Guests group
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($PartOfDomain) {
                    if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Local account" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-26486
            #Windows Server 2012/2012 R2 DC STIG
            #The Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-51148r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on through Remote Desktop Services" to include the following:
                #Guests Group 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($value -contains "Guests") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26487
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.
            "SV-51500r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeEnableDelegationPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26487
            #Windows Server 2012/2012 R2 DC STIG
            #Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on domain controllers.
            "SV-51149r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Enable computer and user accounts to be trusted for delegation" to include the following:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
                if ($value -contains "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26488
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Force shutdown from a remote system user right.
            "SV-53050r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Force shutdown from a remote system" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRemoteShutdownPrivilege"} | select -ExpandProperty AccountList
                if ($value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26489
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Generate security audits user right.
            "SV-52116r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Generate security audits" to only include the following accounts or groups:
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeAuditPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 2 -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26490
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Impersonate a client after authentication user right.
            "SV-52117r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Impersonate a client after authentication" to only include the following accounts or groups:
                #Administrators
                #Service
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeImpersonatePrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26492
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Increase scheduling priority user right.
            "SV-52118r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Increase scheduling priority" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeIncreaseBasePriorityPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26493
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Load and unload device drivers user right.
            "SV-53043r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Load and unload device drivers" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeLoadDriverPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26494
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Lock pages in memory user right.
            "SV-52119r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Lock pages in memory" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeLockMemoryPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeLockMemoryPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26496
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Manage auditing and security log user right.
            "SV-53039r4_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment 
                #"Manage auditing and security log" to only include the following accounts or groups:
                #Administrators 
                #Auditors groups is allowed
                #Applications can have this right, but only with documentation
                if($ServerRole -eq 2){
                    $value=($UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList) -join (",")
                    if($DomainName -eq "AREA52"){if ($Value -eq "Administrators,AFNOAPPS\Exchange Servers,AREA52\Exchange Enterprise Servers,LOCAL SERVICE") {$ActualStatus = "NotAFinding"}}
                    elseif($DomainName -eq "AFNOAPPS"){if ($Value -eq "AFNOAPPS\Exchange Servers,Administrators") {$ActualStatus = "NotAFinding"}}
                    elseif($DomainName -eq "ACC"){if ($Value -eq "ACC\Exchange Enterprise Servers,ACCROOT\Exchange Servers,Administrators") {$ActualStatus = "NotAFinding"}}
                    elseif($DomainName -eq "AFMC" -or $DomainName -eq "ACCROOT"){if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}}
                    else{$ActualStatus = "Open"}

                    if($ActualStatus -eq "NotAFinding"){$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
                    }
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-26497
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Modify an object label user right.
            "SV-53033r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Modify an object label" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeRelabelPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeRelabelPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-26498
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Modify firmware environment values user right.
            "SV-53029r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Modify firmware environment values" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeSystemEnvironmentPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26499
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Perform volume maintenance tasks user right.
            "SV-53025r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Perform volume maintenance tasks" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeManageVolumePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26500
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Profile single process user right.
            "SV-53022r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Profile single process" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeProfileSingleProcessPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26501
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Profile system performance user right.
            "SV-53019r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Profile system performance" to only include the following accounts or groups:
                #Administrators
                #NT Service\WdiServiceHost 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeSystemProfilePrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 2 -and $value -contains "Administrators" -and $value -contains "NT Service\WdiServiceHost") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26503
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Replace a process level token user right.
            "SV-52121r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Replace a process level token" to only include the following accounts or groups:
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeAssignPrimaryTokenPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 2 -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26504
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Restore files and directories user right.
            "SV-52122r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Restore files and directories" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRestorePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26506
            #Windows Server 2012/2012 R2 MS STIG
            #Unauthorized accounts must not have the Take ownership of files or other objects user right.
            "SV-52123r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Take ownership of files or other objects" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeTakeOwnershipPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26529
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Logon - Credential Validation successes.
            "SV-53013r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
                #"Audit Credential Validation" with "Success" selected. 
                if (($auditpol -match "Credential Validation") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Credential Validation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26530
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Logon - Credential Validation failures.
            "SV-53011r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
                #"Audit Credential Validation" with "Failure" selected. 
                if (($auditpol -match "Credential Validation") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Credential Validation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26531
            #Windows Server 2012/2012 R2 DC STIG
            #Windows Server 2012/2012 R2 domain controllers must be configured to audit Account Management - Computer Account Management successes.
            "SV-52234r4_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Computer Account Management" with "Success" selected.  
                if (($auditpol -match "Computer Account Management") -match "Success") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $auditpolrepair}
                }

            #V-26533
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Management - Other Account Management Events successes.
            "SV-53009r1_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Other Account Management Events" with "Success" selected.  
                if (($auditpol -match "Other Account Management Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other Account Management Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26535
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Management - Security Group Management successes.
            "SV-53007r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Security Group Management" with "Success" selected.  
                if (($auditpol -match "Security Group Management") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security Group Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26537
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Management - User Account Management successes.
            "SV-53003r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit User Account Management" with "Success" selected.  
                if (($auditpol -match "User Account Management") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "User Account Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26538
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Account Management - User Account Management failures.
            "SV-53001r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit User Account Management" with "Failure" selected.  
                if (($auditpol -match "User Account Management") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "User Account Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26539
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Detailed Tracking - Process Creation successes.
            "SV-52999r1_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking
                #"Audit Process Creation" with "Success" selected.  
                if (($auditpol -match "Process Creation") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Process Creation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26540
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Logon/Logoff - Logoff successes.
            "SV-52996r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logoff" with "Success" selected.  
                if (($auditpol -match "^(\s)+Logoff") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logoff") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26541
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Logon/Logoff - Logon successes.
            "SV-52994r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logon" with "Success" selected.  
                if (($auditpol -match "^(\s)+Logon") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26542
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Logon/Logoff - Logon failures.
            "SV-52993r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logon" with "Failure" selected.  
                if (($auditpol -match "^(\s)+Logon") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26543
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Logon/Logoff - Special Logon successes.
            "SV-52987r1_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Special Logon" with "Success" selected.  
                if (($auditpol -match "Special Logon") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Special Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26546
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Policy Change - Audit Policy Change successes.
            "SV-52983r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Audit Policy Change" with "Success" selected. 
                if (($auditpol -match "Audit Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Audit Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26547
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Policy Change - Audit Policy Change failures.
            "SV-52982r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Audit Policy Change" with "Failure" selected. 
                if (($auditpol -match "Audit Policy Change") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Audit Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26548
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Policy Change - Authentication Policy Change successes.
            "SV-52981r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Authentication Policy Change" with "Success" selected. 
                if (($auditpol -match "Authentication Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Authentication Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26549
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.
            "SV-52980r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
                #"Audit Sensitive Privilege Use" with "Success" selected. 
                if (($auditpol -match "Sensitive Privilege Use") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26550
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.
            "SV-52979r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
                #"Audit Sensitive Privilege Use" with "Failure" selected. 
                if (($auditpol -match "Sensitive Privilege Use") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26551
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - IPsec Driver successes.
            "SV-52978r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit IPsec Driver" with "Success" selected. 
                if (($auditpol -match "IPsec Driver") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "IPsec Driver") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26552
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - IPsec Driver failures.
            "SV-52977r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit IPsec Driver" with "Failure" selected. 
                if (($auditpol -match "IPsec Driver") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "IPsec Driver") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26553
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - Security State Change successes.
            "SV-52976r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit Security State Change" with "Success" selected. 
                if (($auditpol -match "Security State Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security State Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26555
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - Security System Extension successes.
            "SV-52974r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit Security State Extension" with "Success" selected. 
                if (($auditpol -match "Security System Extension") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security System Extension") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26557
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - System Integrity successes.
            "SV-52972r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit System Integrity" with "Success" selected. 
                if (($auditpol -match "System Integrity") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "System Integrity") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26558
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit System - System Integrity failures.
            "SV-52971r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit System Integrity" with "Failure" selected. 
                if (($auditpol -match "System Integrity") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "System Integrity") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26575
            #Windows Server 2012/2012 R2 MS STIG
            #The 6to4 IPv6 transition technology must be disabled.
            "SV-52970r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
                #"Set 6to4 State" to "Enabled: Disabled State". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "6to4_State" "SilentlyContinue"
                if ($Value -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26576
            #Windows Server 2012/2012 R2 MS STIG
            #The IP-HTTPS IPv6 transition technology must be disabled.
            "SV-52969r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
                #"Set IP-HTTPS State" to "Enabled: Disabled State".
                #Note: "IPHTTPS URL:" must be entered in the policy even if set to Disabled State. Enter "about:blank". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\" "IPHTTPS_ClientState" "SilentlyContinue"
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26577
            #Windows Server 2012/2012 R2 MS STIG
            #The ISATAP IPv6 transition technology must be disabled.
            "SV-52968r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
                #"Set ISATAP State" to "Enabled: Disabled State". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "ISATAP_State" "SilentlyContinue"
                if ($Value -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26578
            #Windows Server 2012/2012 R2 MS STIG
            #The Teredo IPv6 transition technology must be disabled.
            "SV-52967r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
                #"Set Teredo State" to "Enabled: Disabled State". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "Teredo_State"
                if ($Value -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26579
            #Windows Server 2012/2012 R2 MS STIG
            #The Application event log size must be configured to 32768 KB or greater.
            "SV-52966r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" "MaxSize"
                if ($Value -ge 32768) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26580
            #Windows Server 2012/2012 R2 MS STIG
            #The Security event log size must be configured to 196608 KB or greater.
            "SV-52965r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" "MaxSize"
                if ($Value -ge 196608) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26581
            #Windows Server 2012/2012 R2 MS STIG
            #The Setup event log size must be configured to 32768 KB or greater.
            "SV-52964r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Setup 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" "MaxSize"
                if ($Value -ge 32768) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26582
            #Windows Server 2012/2012 R2 MS STIG
            #The System event log size must be configured to 32768 KB or greater.
            "SV-52963r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" "MaxSize"
                if ($Value -ge 32768) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26600
            #Windows Server 2012/2012 R2 MS STIG
            #The Fax service must be disabled if installed.
            "SV-52236r2_rule" {
                $service = Get-Service -Name fax -EA SilentlyContinue
                if ($service -eq $null -or $service.StartType -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26602
            #Windows Server 2012/2012 R2 MS STIG
            #The Microsoft FTP service must not be installed unless required.
            "SV-52237r4_rule" {
                $service = Get-Service -Name FTPSVC -EA SilentlyContinue
                if ($service -eq $null -or $service.StartType -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26604
            #Windows Server 2012/2012 R2 MS STIG
            #The Peer Networking Identity Manager service must be disabled if installed.
            "SV-52238r2_rule" {
                $service = Get-Service -Name p2pimsvc -EA SilentlyContinue
                if ($service -eq $null -or $service.StartType -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26605
            #Windows Server 2012/2012 R2 MS STIG
            #The Simple TCP/IP Services service must be disabled if installed.
            "SV-52239r2_rule" {
                $service = Get-Service -Name simptcp -EA SilentlyContinue
                if ($service -eq $null -or $service.StartType -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-26606
            #Windows Server 2012/2012 R2 MS STIG
            #The Telnet service must be disabled if installed.
            "SV-52240r2_rule" {
                $service = Get-Service -Name tlntsvr -EA SilentlyContinue
                if ($service -eq $null -or $service.StartType -eq "Disabled") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-28504
            #Windows Server 2012/2012 R2 MS STIG
            #Windows must be prevented from sending an error report when a device driver requests additional software during installation.
            "SV-52962r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation
                #"Prevent Windows from sending an error report when a device driver requests additional software during installation" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSendRequestAdditionalSoftwareToWER"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-30016
            #Windows Server 2012/2012 R2 DC STIG
            #Unauthorized accounts must not have the Add workstations to domain user right.
            "SV-51143r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Add workstations to domain" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeMachineAccountPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-32272
            #Windows Server 2012/2012 R2 MS STIG
            #The DoD Root CA certificates must be installed in the Trusted Root Store.
            "SV-52961r6_rule" {
                Remove-Variable certs,HasDodRoot2,HasDodRoot3,HasDodRoot4,HasDodRoot5 -EA SilentlyContinue
                $certs = Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*"
                $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" -and $_.NotAfter -gt $currDate}
                $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "D73CA91102A2204A36459ED32213B467D7CE97FB" -and $_.NotAfter -gt $currDate}
                $HasDodRoot4 = $certs | Where {$_.subject -eq "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "B8269F25DBD937ECAFD4C35A9838571723F2D026" -and $_.NotAfter -gt $currDate}
                $HasDodRoot5 = $certs | Where {$_.subject -eq "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "4ECB5CC3095670454DA1CBD410FC921F46B8564B" -and $_.NotAfter -gt $currDate}
                if ($HasDodRoot2 -and $HasDodRoot3 -and $HasDodRoot4 -and $HasDodRoot5) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-32274
            #Windows Server 2012/2012 R2 MS STIG
            #The DoD Interoperability Root CA cross-certificates must be installed into the Untrusted Certificates Store on unclassified systems.
            "SV-52957r7_rule" {
                [datetime]$NotAfterDate="1/22/2022"
                if($NotAfterDate -gt $currDate){
                    if ($IsNIPR) {
                        Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
                        $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}
                        $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "AC06108CA348CC03B53795C64BF84403C1DBD341"}
                        if ($HasDodRoot3) {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-32282
            #Windows Server 2012/2012 R2 MS STIG
            #Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.
            "SV-52956r3_rule" { 
                $FCIR=@('BUILTIN\Administrators','NT AUTHORITY\SYSTEM')
                $RIR=@('BUILTIN\Users','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES')

                #Make sure 32 bit version of registry key has default permissions
                $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
                if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$32bitFine = $false}
                else{$32bitFine = $true}

                #If 64-bit, do it all again
                if ($OSArch -eq 64) {
                    $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
                    if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$64bitFine = $false}
                    else{$64bitFine = $true}
                    }

                #If its not 64 bit, then we dont need to bother with it
                else {$64bitFine = $true}

                if ($32bitFine -eq $true -and $64bitFine -eq $true) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-33663
            #Windows Server 2012/2012 R2 DC STIG
            #The system must be configured to audit DS Access - Directory Service Access successes.
            "SV-51151r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Access" with "Success" selected. 
                if (($auditpol -match "Directory Service Access") -match "Success") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $auditpolrepair}
                }

            #V-33664
            #Windows Server 2012/2012 R2 DC STIG
            #The system must be configured to audit DS Access - Directory Service Access failures.
            "SV-51152r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Access" with "Failure" selected. 
                if (($auditpol -match "Directory Service Access") -match "Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $auditpolrepair}
                }

            #V-33665
            #Windows Server 2012/2012 R2 DC STIG
            #The system must be configured to audit DS Access - Directory Service Changes successes.
            "SV-51153r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Changes" with "Success" selected. 
                if (($auditpol -match "Directory Service Changes") -match "Success") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $auditpolrepair}
                }

            #V-33666
            #Windows Server 2012/2012 R2 DC STIG
            #The system must be configured to audit DS Access - Directory Service Changes failures.
            "SV-51155r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Changes" with "Failure" selected. 
                if (($auditpol -match "Directory Service Changes") -match "Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
                }

            #V-34974
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Installer Always install with elevated privileges option must be disabled.
            "SV-52954r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Always install with elevated privileges" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "AlwaysInstallElevated"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36439
            #Windows Server 2012/2012 R2 MS STIG
            #Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.
            "SV-51590r3_rule" { 
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Apply UAC restrictions to local accounts on network logons" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LocalAccountTokenFilterPolicy"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36656
            #Windows Server 2012/2012 R2 MS STIG
            #A screen saver must be enabled on the system.
            "SV-51758r2_rule" {
                #User Configuration -> Administrative Templates -> Control Panel -> Personalization
                #"Enable screen saver" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaveActive"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36657
            #Windows Server 2012/2012 R2 MS STIG
            #The screen saver must be password protected.
            "SV-51760r1_rule" {
                #User Configuration -> Administrative Templates -> Control Panel -> Personalization
                #"Password protect the screen saver" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaverIsSecure"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36667
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Object Access - Removable Storage failures.
            "SV-51604r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
                #"Audit Removable Storage" with "Failure" selected. 
                if (($auditpol -match "Removable Storage") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Removable Storage") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36668
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Object Access - Removable Storage successes.
            "SV-51601r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
                #"Audit Removable Storage" with "Success" selected. 
                if (($auditpol -match "Removable Storage") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Removable Storage") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36673
            #Windows Server 2012/2012 R2 MS STIG
            #IP stateless autoconfiguration limits state must be enabled.
            "SV-51605r1_rule" {
                #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters
                #"Set IP Stateless Autoconfiguration Limits State" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnableIPAutoConfigurationLimits"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36677
            #Windows Server 2012/2012 R2 MS STIG
            #Optional component installation and component repair must be prevented from using Windows Update.
            "SV-51606r1_rule" {
                #Computer Configuration -> Administrative Templates -> System
                #"Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\" "UseWindowsUpdate"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36678
            #Windows Server 2012/2012 R2 MS STIG
            #Device driver updates must only search managed servers, not Windows Update.
            "SV-51607r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Device Installation
                #"Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected. 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "DriverServerSelection"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36679
            #Windows Server 2012/2012 R2 MS STIG
            #Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.
            "SV-51608r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware
                #"Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected. 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Policies\EarlyLaunch\" "DriverLoadPolicy"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36680
            #Windows Server 2012/2012 R2 MS STIG
            #Access to the Windows Store must be turned off.
            "SV-51609r2_rule" {
                #If the \Windows\WinStore directory exists:
                #Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings
                #"Turn off access to the Store" to "Enabled".

                #Alternately, uninstall the "Desktop Experience" feature from Windows 2012. 
                #This is located under "User Interfaces and Infrastructure" in the "Add Roles and Features Wizard". 
                #The \Windows\WinStore directory may need to be manually deleted after this. 
                if (Test-Path "C:\Windows\WinStore") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\" "NoUseStoreOpenWith"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-36681
            #Windows Server 2012/2012 R2 MS STIG
            #Copying of user input methods to the system account for sign-in must be prevented.
            "SV-51610r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Locale Services
                #"Disallow copying of user input methods to the system account for sign-in" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Control Panel\International\" "BlockUserInputMethodsForSignIn"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36684
            #Windows Server 2012/2012 R2 MS STIG
            #Local users on domain-joined computers must not be enumerated.
            "SV-51611r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Logon
                #"Enumerate local users on domain-joined computers" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "EnumerateLocalUsers"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36687
            #Windows Server 2012/2012 R2 MS STIG
            #App notifications on the lock screen must be turned off.
            "SV-51612r1_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Logon
                #"Turn off app notifications on the lock screen" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "DisableLockScreenAppNotifications"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36696
            #Windows Server 2012/2012 R2 MS STIG
            #The detection of compatibility issues for applications and drivers must be turned off.
            "SV-51737r2_rule" {
                #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Application Compatibility Diagnostics
                #"Detect compatibility issues for applications and drivers" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" "DisablePcaUI"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36697
            #Windows Server 2012/2012 R2 MS STIG
            #Trusted app installation must be enabled to allow for signed enterprise line of business apps.
            "SV-51738r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment
                #"Allow all trusted apps to install" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Appx\" "AllowAllTrustedApps"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36698
            #Windows Server 2012/2012 R2 MS STIG
            #The use of biometrics must be disabled.
            "SV-51739r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics
                #"Allow the use of biometrics" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\" "Enabled"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36700
            #Windows Server 2012/2012 R2 MS STIG
            #The password reveal button must not be displayed.
            "SV-51740r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface
                #"Do not display the password reveal button" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CredUI\" "DisablePasswordReveal"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36707
            #Windows Server 2012/2012 R2 MS STIG
            #Windows SmartScreen must be enabled on Windows 2012/2012 R2.
            "SV-51747r5_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface
                #"Do not display the password reveal button" to "Enabled". 
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CredUI\" "DisablePasswordReveal"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-36708
            #Windows Server 2012/2012 R2 MS STIG
            #The location feature must be turned off.
            "SV-51748r2_rule" {
                #Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Location and Sensors
                #"Turn off location" to "Enabled".
                #If location services are approved by the organization for a device, this must be documented. 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors\" "DisableLocation"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36709
            #Windows Server 2012/2012 R2 MS STIG
            #Basic authentication for RSS feeds over HTTP must be turned off.
            "SV-51749r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
                #"Turn on Basic feed authentication over HTTP" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "AllowBasicAuthInClear"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36710
            #Windows Server 2012/2012 R2 MS STIG
            #Automatic download of updates from the Windows Store must be turned off.
            "SV-51750r2_rule" {
                #The Windows Store is not installed by default. If the \Windows\WinStore directory does not exist, this is NA.
                #Windows 2012 R2 split the original policy that configures this setting into two separate ones. Configuring either one to "Enabled" will update the registry value as identified in the Check section.
                #Computer Configuration -> Administrative Templates -> Windows Components -> Store
                #"Turn off Automatic Download of updates on Win8 machines" or "Turn off Automatic Download and install of updates" to "Enabled".

                #Windows 2012:
                #Computer Configuration -> Administrative Templates -> Windows Components -> Store 
                #"Turn off Automatic Download of updates" to "Enabled". 
                if (Test-Path "C:\Windows\WinStore") {
                    if ($OS -match "Server 2012 R2") {$Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\" "AutoDownload"}
                    elseif ($OS -match "Server 2012" -and $OS -notmatch "Server 2012 R2") {$Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\" "AutoDownload"}
                    if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "C:\Windows\WinStore folder exists and registry values incorrectly configured"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-36711
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Store application must be turned off.
            "SV-51751r2_rule" {
                #If the \Windows\WinStore directory does not exist, this is NA.
                #Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store
                #"Turn off the Store application" to "Enabled". 
                if (Test-Path "C:\Windows\WinStore") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\" "RemoveWindowsStore"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "C:\Windows\WinStore folder exists and registry values incorrectly configured"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-36712
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) client must not use Basic authentication.
            "SV-51752r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Allow Basic authentication" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowBasic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36713
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
            "SV-51753r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Allow unencrypted traffic" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowUnencryptedTraffic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36714
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) client must not use Digest authentication.
            "SV-51754r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Disallow Digest authentication" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowDigest"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36718
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) service must not use Basic authentication.
            "SV-51755r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Allow Basic authentication" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "AllowBasic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36719
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
            "SV-51756r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Allow unencrypted traffic" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" "AllowUnencryptedTraffic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36720
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Remote Management (WinRM) service must not store RunAs credentials.
            "SV-51757r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Disallow WinRM from storing RunAs credentials" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "DisableRunAs"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36722
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-51569r1_rule" { 
                $applicationACL=(Get-Acl C:\Windows\System32\winevt\Logs\Application.evtx).access
                $accounts=($applicationACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }

            #V-36723
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-51571r1_rule" { 
                $securityACL=(Get-Acl C:\Windows\System32\winevt\Logs\Security.evtx).access
                $accounts=($securityACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }

            #V-36724
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-51572r1_rule" { 
                $systemACL=(Get-Acl C:\Windows\System32\winevt\Logs\System.evtx).access
                $accounts=($systemACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }

            #V-36734
            #Windows Server 2012/2012 R2 MS STIG
            #The operating system must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).
            "SV-51582r3_rule" { 
                if($installedprograms.displayname -contains "McAfee Agent"){$ActualStatus = "NotAFinding"}
                }

            #V-36735
            #Windows Server 2012/2012 R2 MS STIG
            #The system must support automated patch management tools to facilitate flaw remediation.
            "SV-51583r2_rule" {
                #SCCM does this
                if ((Get-Process -name "CcmExec" -EA SilentlyContinue) -ne $null) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36736
            #Windows Server 2012/2012 R2 MS STIG
            #The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.
            "SV-51584r1_rule" {
                #axway
                if (Get-WmiObject -class Win32reg_addremoveprograms64 -Filter "DisplayName = 'Axway Desktop Validator'") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36773
            #Windows Server 2012/2012 R2 MS STIG
            #The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.
            "SV-51596r2_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive logon: Machine inactivity limit" to "900" seconds" or less. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "InactivityTimeoutSecs"
                if ($Value -le "900") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36776
            #Windows Server 2012/2012 R2 MS STIG
            #Notifications from Windows Push Network Service must be turned off.
            "SV-51762r1_rule" {
                #User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications
                #"Turn off notifications network usage" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoCloudApplicationNotification"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-36777
            #Windows Server 2012/2012 R2 MS STIG
            #Toast notifications to the lock screen must be turned off.
            "SV-51763r1_rule" {
                #User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications
                #"Turn off toast notifications on the lock screen" to "Enabled". 
                $Value = Check-RegKeyValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoToastApplicationNotificationOnLockScreen"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-39331
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-51176r2_rule" { 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')
                    
                    $sysvolacl=(Get-Acl E:\Windows\SYSVOL).Access

                    if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-39334
            #Windows Server 2012/2012 R2 DC STIG
            #Domain controllers must have a PKI server certificate.
            "SV-51189r2_rule" {
                if ((Get-ChildItem Cert:\LocalMachine\my) -ne $null) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-40177
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-52135r3_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $badacl=@()
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')

                    $programfilesacl=(Get-Acl 'C:\Program Files').Access
                    $programfiles86acl=(Get-Acl 'C:\Program Files (x86)').Access
                    if($programfilesacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files'}
                    if($programfiles86acl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files (x86)'}
                    if($badacl.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following folder(s) contain a bad ACL entry: $badacl"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-40178
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-52136r3_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators')

                    $Cacl=(Get-Acl C:\).Access
                    if($Cacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-40179
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-52137r3_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')

                    $windowsacl=(Get-Acl C:\Windows).Access
                    if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-40200
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Object Access - Central Access Policy Staging failures.
            "SV-52159r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access
                #"Audit Central Access Policy Staging" with "Failure" selected. 
                if (($auditpol -match "Central Policy Staging") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Central Policy Staging") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-40202
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Object Access - Central Access Policy Staging successes.
            "SV-52161r3_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access
                #"Audit Central Access Policy Staging" with "Success" selected. 
                if (($auditpol -match "Central Policy Staging") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Central Policy Staging") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-40204
            #Windows Server 2012/2012 R2 MS STIG
            #Only the default client printer must be redirected to the Remote Desktop Session Host.  (Remote Desktop Services Role).
            "SV-52163r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Printer Redirection
                #"Redirect only the default client printer" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "RedirectOnlyDefaultClientPrinter"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-40206
            #Windows Server 2012/2012 R2 MS STIG
            #The Smart Card Removal Policy service must be configured to automatic.
            "SV-52165r2_rule" {
                if ((Get-Service -DisplayName "Smart Card Removal Policy").StartType -eq "Automatic") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-40237
            #Windows Server 2012/2012 R2 MS STIG
            #The US DoD CCEB Interoperability Root CA cross-certificates must be installed into the Untrusted Certificates Store on unclassified systems.
            "SV-52196r6_rule" {
                #This date is from the STIG. The cert does not have to be in the store after it expires.
                [datetime]$NotAfterDate="9/27/2019"
                if($currDate -gt $NotAfterDate){$ActualStatus = "NotAFinding"}
                else{
                    if ($IsNIPR) {
                        Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
                        $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*CCEB Interoperability*"}
                        $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "929BF3196896994C0A201DF4A5B71F603FEFBF2E"}
                        if ($HasDodRoot3) {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"
                        $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should run DOD Install Root and re-verify"}
                        }
                    else {$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-42420
            #Windows Server 2012/2012 R2 MS STIG
            #A host-based firewall must be installed and enabled on the system.
            "SV-55085r1_rule" {
                if ($installedprograms.displayname -contains "McAfee Host Intrusion Prevention") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-43238
            #Windows Server 2012/2012 R2 MS STIG
            #The display of slide shows on the lock screen must be disabled (Windows 2012 R2).
            "SV-56343r2_rule" {
                #Computer Configuration -> Administrative Templates -> Control Panel -> Personalization
                #"Prevent enabling lock screen slide show" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\" "NoLockScreenSlideshow"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-43239
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012 R2 must include command line data in process creation events.
            "SV-56344r3_rule" {
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Computer Configuration -> Administrative Templates -> System -> Audit Process Creation
                #"Include command line in process creation events" to "Enabled". 
                if ($OS -match "Server 2012 R2") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" "ProcessCreationIncludeCmdLine_Enabled"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                Else {$ActualStatus = "Not_Applicable"}
                }

            #V-43240
            #Windows Server 2012/2012 R2 MS STIG
            #The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2).
            "SV-56346r2_rule" {
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled". 
                if ($OS -match "Server 2012 R2") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "DontDisplayNetworkSelectionUI"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                Else {$ActualStatus = "Not_Applicable"}
                }

            #V-43241
            #Windows Server 2012/2012 R2 MS STIG
            #The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2).
            "SV-56353r2_rule" {
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Computer Configuration -> Administrative Templates -> Windows Components -> App Runtime -> "Allow Microsoft accounts to be optional" to "Enabled". 
                if ($OS -match "Server 2012 R2") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                Else {$ActualStatus = "Not_Applicable"}
                }

            #V-43245
            #Windows Server 2012/2012 R2 MS STIG
            #Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2).
            "SV-56355r2_rule" {
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options
                #"Sign-in last interactive user automatically after a system-initiated restart" to "Disabled". 
                if ($OS -match "Server 2012 R2") {
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableAutomaticRestartSignOn"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                Else {$ActualStatus = "Not_Applicable"}
                }

            #V-46473
            #Microsoft Internet Explorer 11 STIG
            #Turn off Encryption Support must be enabled.
            "SV-59337r8_rule" {
                #TLS 1.1 and 1.2 only
                #SSL 2.0 - 8
                #SSL 3.0 - 32
                #TLS 1.0 - 128
                #TLS 1.1 - 512
                #TLS 1.2 - 2048
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\" "SecureProtocols" "SilentlyContinue"
                if ($Value -eq "2560") {$ActualStatus = "NotAFinding"}
                else {
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR + ". This finding is covered by the USAF STIG Deviation Memo."}
                }

            #V-46475
            #Microsoft Internet Explorer 11 STIG
            #The Internet Explorer warning about certificate address mismatch must be enforced.
            "SV-59339r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Turn on certificate address mismatch warning : Enabled
                $ValueName = "WarnOnBadCertRecving"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46477
            #Microsoft Internet Explorer 11 STIG
            #Check for publishers certificate revocation must be enforced.
            "SV-59341r4_rule" {
                #NA if SIPR
                if ($IsNIPR) {
                    $ValueName = "State"
                    $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name $ValueName | select -ExpandProperty $ValueName
                    if ($Value -eq "146432") {$ActualStatus = "NotAFinding"} #0x23C00
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-46481
            #Microsoft Internet Explorer 11 STIG
            #The Download signed ActiveX controls property must be disallowed (Internet zone).
            "SV-59345r1_rule" {
                $ValueName = "1001"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46483
            #Microsoft Internet Explorer 11 STIG
            #The Download unsigned ActiveX controls property must be disallowed (Internet zone).
            "SV-59347r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #Download unsigned ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box
                $ValueName = "1004"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46501
            #Microsoft Internet Explorer 11 STIG
            #The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone).
            "SV-59365r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box.
                $ValueName = "1201"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46505
            #Microsoft Internet Explorer 11 STIG
            #Font downloads must be disallowed (Internet zone).
            "SV-59369r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box.
                $ValueName = "1604"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46507
            #Microsoft Internet Explorer 11 STIG
            #The Java permissions must be disallowed (Internet zone).
            "SV-59371r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46509
            #Microsoft Internet Explorer 11 STIG
            #Accessing data sources across domains must be disallowed (Internet zone).
            "SV-59373r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #"Access data sources across domains" will be set to "Enabled" and "Disable"
                $ValueName = "1406"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46511
            #Microsoft Internet Explorer 11 STIG
            #Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).
            "SV-59375r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1802"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46513
            #Microsoft Internet Explorer 11 STIG
            #Launching programs and files in IFRAME must be disallowed (Internet zone).
            "SV-59377r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1804"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46515
            #Microsoft Internet Explorer 11 STIG
            #Navigating windows and frames across different domains must be disallowed (Internet zone).
            "SV-59379r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box.
                $ValueName = "1607"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46517
            #Microsoft Internet Explorer 11 STIG
            #Userdata persistence must be disallowed (Internet zone).
            "SV-59381r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1606"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}                
                }

            #V-46521
            #Microsoft Internet Explorer 11 STIG
            #Clipboard operations via script must be disallowed (Internet zone).
            "SV-59385r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1407"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}                
                }

            #V-46523
            #Microsoft Internet Explorer 11 STIG
            #Logon options must be configured to prompt (Internet zone).
            "SV-59387r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #"Logon options" to "Enabled", and select "Prompt for user name and password" from the drop-down box. 
                $ValueName = "1A00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 65536) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46525
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be configured with High Safety (Intranet zone).
            "SV-59389r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Intranet Zone
                #"Java permissions" will be set to “Enabled” and "High Safety".
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 65536) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46543
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be configured with High Safety (Trusted Sites zone).
            "SV-59407r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Trusted Sites Zone
                #"Java permissions" will be set to “Enabled” and "High Safety".
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 65536) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46545
            #Microsoft Internet Explorer 11 STIG
            #Dragging of content from different domains within a window must be disallowed (Internet zone).
            "SV-59409r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone
                #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
                $ValueName = "2708"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46547
            #Microsoft Internet Explorer 11 STIG
            #Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).
            "SV-59411r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
                #'Enable dragging of content from different domains across windows' to 'Enabled', and select 'Disabled' from the drop-down box.
                $ValueName = "2709"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46549
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer).
            "SV-59413r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
                #“Internet Explorer Processes” must be “Enabled”. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46553
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore).
            "SV-59417r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
                #“Internet Explorer Processes” must be “Enabled”. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46555
            #Microsoft Internet Explorer 11 STIG
            #Dragging of content from different domains within a window must be disallowed (Restricted Sites zone).
            "SV-59419r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
                #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
                $ValueName = "2708"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq 3) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46573
            #Microsoft Internet Explorer 11 STIG
            #The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).
            "SV-59437r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1001"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46575
            #Microsoft Internet Explorer 11 STIG
            #The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone).
            "SV-59439r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
                #"Download unsigned ActiveX controls" to "Enabled", and select "Disable" from the drop-down box.
                $ValueName = "1004"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46577
            #Microsoft Internet Explorer 11 STIG
            #The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone).
            "SV-59441r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
                #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1201"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46579
            #Microsoft Internet Explorer 11 STIG
            #ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).
            "SV-59443r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
                #'Run ActiveX controls and plugins' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1200"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46581
            #Microsoft Internet Explorer 11 STIG
            #ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).
            "SV-59445r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Script ActiveX controls marked safe for scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1405"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46583
            #Microsoft Internet Explorer 11 STIG
            #File downloads must be disallowed (Restricted Sites zone).
            "SV-59447r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1803"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46585
            #Microsoft Internet Explorer 11 STIG
            #Font downloads must be disallowed (Restricted Sites zone).
            "SV-59449r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1604"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46587
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Restricted Sites zone).
            "SV-59451r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46589
            #Microsoft Internet Explorer 11 STIG
            #Accessing data sources across domains must be disallowed (Restricted Sites zone).
            "SV-59453r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Access data sources across domains' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1406"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46591
            #Microsoft Internet Explorer 11 STIG
            #The Allow META REFRESH property must be disallowed (Restricted Sites zone).
            "SV-59455r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow META REFRESH' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1608"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46593
            #Microsoft Internet Explorer 11 STIG
            #Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone).
            "SV-59457r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1802"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46597
            #Microsoft Internet Explorer 11 STIG
            #Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).
            "SV-59461r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1804"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46599
            #Microsoft Internet Explorer 11 STIG
            #Navigating windows and frames across different domains must be disallowed (Restricted Sites zone).
            "SV-59463r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1607"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46601
            #Microsoft Internet Explorer 11 STIG
            #Userdata persistence must be disallowed (Restricted Sites zone).
            "SV-59465r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box 
                $ValueName = "1606"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46603
            #Microsoft Internet Explorer 11 STIG
            #Active scripting must be disallowed (Restricted Sites Zone).
            "SV-59467r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow active scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1400"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46605
            #Microsoft Internet Explorer 11 STIG
            #Clipboard operations via script must be disallowed (Restricted Sites zone).
            "SV-59469r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1407"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46607
            #Microsoft Internet Explorer 11 STIG
            #Logon options must be configured and enforced (Restricted Sites zone).
            "SV-59471r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Logon options' to 'Enabled', and select 'Anonymous logon' from the drop-down box. 
                $ValueName = "1A00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "196608") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46609
            #Microsoft Internet Explorer 11 STIG
            #Configuring History setting must be set to 40 days.
            "SV-59473r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
                #'Disable Configuring History' to 'Enabled', and enter '40' in 'Days to keep pages in History'. 
                $ValueName1 = "History"
                $Value1 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel" -Name $ValueName1 | select -ExpandProperty $ValueName1
                $ValueName2 = "DaysToKeep"
                $Value2 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" -Name $ValueName2 | select -ExpandProperty $ValueName2
                if ($Value1 -eq "1" -and $Value2 -eq "40") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46615
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer must be set to disallow users to add/delete sites.
            "SV-59479r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components
                #Internet Explorer "Security Zones: Do not allow users to add/delete sites" to "Enabled". 
                $ValueName = "Security_zones_map_edit"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}       
                }

            #V-46617
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer must be configured to disallow users to change policies.
            "SV-59481r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components
                #Internet Explorer 'Security Zones: Do not allow users to change policies' to 'Enabled'. 
                $ValueName = "Security_options_edit"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46619
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer must be configured to use machine settings.
            "SV-59483r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components
                #Internet Explorer 'Security Zones: Use only machine settings' to 'Enabled'. 
                $ValueName = "Security_HKLM_only"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46621
            #Microsoft Internet Explorer 11 STIG
            #Security checking features must be enforced.
            "SV-59485r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
                #'Turn off the Security Settings Check feature' to 'Disabled'.
                $ValueName = "DisableSecuritySettingsCheck"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46625
            #Microsoft Internet Explorer 11 STIG
            #Software must be disallowed to run or install with invalid signatures.
            "SV-59489r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
                #'Allow software to run or install even if the signature is invalid' to 'Disabled'. 
                $ValueName = "RunInvalidSignatures"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46629
            #Microsoft Internet Explorer 11 STIG
            #Checking for server certificate revocation must be enforced.
            "SV-59493r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
                #'Check for server certificate revocation' to 'Enabled'. 
                $ValueName = "CertificateRevocation"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46633
            #Microsoft Internet Explorer 11 STIG
            #Checking for signatures on downloaded programs must be enforced.
            "SV-59497r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
                #'Check for signatures on downloaded programs' to 'Enabled'. 
                $ValueName = "CheckExeSignatures"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "yes") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46635
            #Microsoft Internet Explorer 11 STIG
            #All network paths (UNCs) for Intranet sites must be disallowed.
            "SV-59499r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #'Intranet Sites: Include all network paths (UNCs)' to 'Disabled'. 
                $ValueName = "UNCAsIntranet"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46637
            #Microsoft Internet Explorer 11 STIG
            #Script-initiated windows without size or position constraints must be disallowed (Internet zone).
            "SV-59501r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2102"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46639
            #Microsoft Internet Explorer 11 STIG
            #Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone).
            "SV-59503r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2102"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46641
            #Microsoft Internet Explorer 11 STIG
            #Scriptlets must be disallowed (Internet zone).
            "SV-59505r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1209"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46643
            #Microsoft Internet Explorer 11 STIG
            #Automatic prompting for file downloads must be disallowed (Internet zone).
            "SV-59507r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2200"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46645
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Local Machine zone).
            "SV-59509r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Local Machine Zone
                #"Java permissions" to "Enabled", and "Disable Java" selected from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46647
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Locked Down Local Machine zone).
            "SV-59511r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Local Machine Zone
                #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46649
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Locked Down Intranet zone).
            "SV-59513r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Intranet Zone
                #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46653
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Locked Down Trusted Sites zone).
            "SV-59517r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Trusted Sites Zone
                #"Java permissions" to "Enabled", and select "Disable Java" from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46663
            #Microsoft Internet Explorer 11 STIG
            #Java permissions must be disallowed (Locked Down Restricted Sites zone).
            "SV-59527r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone
                #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
                $ValueName = "1C00"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46665
            #Microsoft Internet Explorer 11 STIG
            #XAML files must be disallowed (Internet zone).
            "SV-59529r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2402"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46669
            #Microsoft Internet Explorer 11 STIG
            #XAML files must be disallowed (Restricted Sites zone).
            "SV-59533r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2402"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46681
            #Microsoft Internet Explorer 11 STIG
            #Protected Mode must be enforced (Internet zone).
            "SV-59545r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "2500"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46685
            #Microsoft Internet Explorer 11 STIG
            #Protected Mode must be enforced (Restricted Sites zone).
            "SV-59549r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "2500"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46689
            #Microsoft Internet Explorer 11 STIG
            #Pop-up Blocker must be enforced (Internet zone).
            "SV-59553r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "1809"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46691
            #Microsoft Internet Explorer 11 STIG
            #Pop-up Blocker must be enforced (Restricted Sites zone).
            "SV-59555r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "1809"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                
                }

            #V-46693
            #Microsoft Internet Explorer 11 STIG
            #Websites in less privileged web content zones must be prevented from navigating into the Internet zone.
            "SV-59557r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2101"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46695
            #Microsoft Internet Explorer 11 STIG
            #Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone.
            "SV-59559r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2101"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46701
            #Microsoft Internet Explorer 11 STIG
            #Allow binary and script behaviors must be disallowed (Restricted Sites zone).
            "SV-59565r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #"Allow binary and script behaviors" to "Enabled", and select "Disable" from the drop-down box. 
                $ValueName = "2000"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46705
            #Microsoft Internet Explorer 11 STIG
            #Automatic prompting for file downloads must be disallowed (Restricted Sites zone).
            "SV-59569r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2200"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46709
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME handling must be enforced. (Reserved)
            "SV-59573r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46711
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME handling must be enforced (Explorer).
            "SV-59575r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46713
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME handling must be enforced (iexplore).
            "SV-59577r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46715
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME sniffing must be enforced (Reserved).
            "SV-59579r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46717
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME sniffing must be enforced (Explorer).
            "SV-59581r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46719
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MIME sniffing must be enforced (iexplore).
            "SV-59583r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46721
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MK protocol must be enforced (Reserved).
            "SV-59585r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
                #"Internet Explorer Processes" to "Enabled". 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46723
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MK protocol must be enforced (Explorer).
            "SV-59587r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
                #"Internet Explorer Processes" to "Enabled". 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46725
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for MK protocol must be enforced (iexplore).
            "SV-59589r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
                #"Internet Explorer Processes" to "Enabled". 
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46727
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Zone Elevation must be enforced (Reserved).
            "SV-59591r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46729
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Zone Elevation must be enforced (Explorer).
            "SV-59593r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46731
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Zone Elevation must be enforced (iexplore).
            "SV-59595r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46733
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Restrict File Download must be enforced (Reserved).
            "SV-59597r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download
                #'Internet Explorer Processes' to 'Enabled'.
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46779
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Restrict File Download must be enforced (Explorer).
            "SV-59645r1_rule" {
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46781
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Restrict File Download must be enforced (iexplore).
            "SV-59647r1_rule" {
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46787
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).
            "SV-59653r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46789
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer).
            "SV-59655r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46791
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore).
            "SV-59657r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46797
            #Microsoft Internet Explorer 11 STIG
            #.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone).
            "SV-59663r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2004"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if($Value -eq "3"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000382910"}
                }

            #V-46799
            #Microsoft Internet Explorer 11 STIG
            #.NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone).
            "SV-59665r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box.
                $ValueName = "2001"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000382926"}
                }

            #V-46801
            #Microsoft Internet Explorer 11 STIG
            #Scripting of Java applets must be disallowed (Restricted Sites zone).
            "SV-59667r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #"Scripting of Java applets" to "Enabled", and select "Disable" from the drop-down box. 
                $ValueName = "1402"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46807
            #Microsoft Internet Explorer 11 STIG
            #AutoComplete feature for forms must be disallowed.
            "SV-59673r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
                #'Disable AutoComplete for forms' to 'Enabled'. 
                $ValueName = "Use FormSuggest"
                $Value = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "no") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46811
            #Microsoft Internet Explorer 11 STIG
            #Crash Detection management must be enforced.
            "SV-59677r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
                #'Turn off Crash Detection' to 'Enabled'.
                $ValueName = "NoCrashDetection"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46815
            #Microsoft Internet Explorer 11 STIG
            #Turn on the auto-complete feature for user names and passwords on forms must be disabled.
            "SV-59681r1_rule" {
                #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
                #"Turn on the auto-complete feature for user names and passwords on forms" to "Disabled". 
                $ValueName1 = "FormSuggest Passwords"
                $Value1 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName1 | select -ExpandProperty $ValueName1
                $ValueName2 = "FormSuggest PW Ask"
                $Value2 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName2 | select -ExpandProperty $ValueName2
                if ($Value1 -eq "no" -and $Value2 -eq "no") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46819
            #Microsoft Internet Explorer 11 STIG
            #Managing SmartScreen Filter use must be enforced.
            "SV-59685r3_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
                #"Prevent Managing SmartScreen Filter" to "Enabled", and select "On" from the drop-down box. 
                if (!$IsNIPR) {
                    $ActualStatus = "Not_Applicable"
                    break rulecheck
                    }
                $ValueName = "EnabledV9"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46829
            #Microsoft Internet Explorer 11 STIG
            #Browser must retain history on exit.
            "SV-59695r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
                #“Configure Delete Browsing History on exit” to “Disabled”.
                $ValueName = "ClearBrowsingHistoryOnExit"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46841
            #Microsoft Internet Explorer 11 STIG
            #Deleting websites that the user has visited must be disallowed.
            "SV-59707r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History"
                #Prevent Deleting Web sites that the User has Visited" to "Enabled". 
                $ValueName = "CleanHistory"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46847
            #Microsoft Internet Explorer 11 STIG
            #InPrivate Browsing must be disallowed.
            "SV-59713r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Privacy
                #'Turn off InPrivate Browsing' to 'Enabled'
                $ValueName = "EnableInPrivateBrowsing"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46849
            #Microsoft Internet Explorer 11 STIG
            #Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone).
            "SV-59715r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1206"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46853
            #Microsoft Internet Explorer 11 STIG
            #When uploading files to a server, the local directory path must be excluded (Internet zone).
            "SV-59719r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #"Include local path when user is uploading files to a server" to "Enabled", and select "Disable" from the drop-down box. 
                $ValueName = "160A"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46857
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Notification Bars must be enforced (Reserved).
            "SV-59723r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46859
            #Microsoft Internet Explorer 11 STIG
            #Security Warning for unsafe files must be set to prompt (Internet zone).
            "SV-59725r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Prompt' from the drop-down box. 
                $ValueName = "1806"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46861
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Notification Bars must be enforced (Explorer).
            "SV-59727r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
                #'Internet Explorer Processes' to 'Enabled'.
                $ValueName = "explorer.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46865
            #Microsoft Internet Explorer 11 STIG
            #ActiveX controls without prompt property must be used in approved domains only (Internet zone).
            "SV-59729r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "120b"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46869
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes for Notification Bars must be enforced (iexplore).
            "SV-59735r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
                #'Internet Explorer Processes' to 'Enabled'.  
                $ValueName = "iexplore.exe"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46879
            #Microsoft Internet Explorer 11 STIG
            #Cross-Site Scripting Filter must be enforced (Internet zone).
            "SV-59745r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
                #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box.  
                $ValueName = "1409"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46883
            #Microsoft Internet Explorer 11 STIG
            #Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone).
            "SV-59749r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1206"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46885
            #Microsoft Internet Explorer 11 STIG
            #When uploading files to a server, the local directory path must be excluded (Restricted Sites zone).
            "SV-59751r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Include local path when user is uploading files to a server' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "160A"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46889
            #Microsoft Internet Explorer 11 STIG
            #Security Warning for unsafe files must be disallowed (Restricted Sites zone).
            "SV-59755r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1806"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46893
            #Microsoft Internet Explorer 11 STIG
            #ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone).
            "SV-59759r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "120b"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46895
            #Microsoft Internet Explorer 11 STIG
            #Cross-Site Scripting Filter property must be enforced (Restricted Sites zone).
            "SV-59761r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
                #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box. 
                $ValueName = "1409"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46897
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved).
            "SV-59763r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
                #'Internet Explorer Processes' to 'Enabled'. 
                $ValueName = "(Reserved)"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46903
            #Microsoft Internet Explorer 11 STIG
            #Status bar updates via script must be disallowed (Internet zone).
            "SV-59769r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Internet Zone 'Allow updates to status bar via script' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2103"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46907
            #Microsoft Internet Explorer 11 STIG
            #.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).
            "SV-59773r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Internet Zone 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2004"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46921
            #Microsoft Internet Explorer 11 STIG
            #.NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone).
            "SV-59787r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Internet Zone 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "2001"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46927
            #Microsoft Internet Explorer 11 STIG
            #Scriptlets must be disallowed (Restricted Sites zone).
            "SV-59793r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Restricted Sites Zone 'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
                $ValueName = "1209"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46939
            #Microsoft Internet Explorer 11 STIG
            #Status bar updates via script must be disallowed (Restricted Sites zone).
            "SV-59805r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
                #Restricted Sites Zone "Allow updates to status bar via script" to "Enabled", and select "Disable" from the drop-down box. 
                $ValueName = "2103"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46975
            #Microsoft Internet Explorer 11 STIG
            #When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode.
            "SV-59841r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 
                #'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' to 'Enabled'. 
                $ValueName = "DisableEPMCompat"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46981
            #Microsoft Internet Explorer 11 STIG
            #Dragging of content from different domains across windows must be disallowed (Internet zone).
            "SV-59847r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone 
                #"Enable dragging of content from different domains across windows" to "Enabled", and select "Disabled". 
                $ValueName = "2709"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46987
            #Microsoft Internet Explorer 11 STIG
            #Enhanced Protected Mode functionality must be enforced.
            "SV-59853r3_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page
                #"Turn on Enhanced Protected Mode" to "Enabled". 
                $ValueName = "Isolation"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "PMEM") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46995
            #Microsoft Internet Explorer 11 STIG
            #The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on.
            "SV-59861r2_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Advanced Page 
                #'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' to 'Enabled'. 
                $ValueName = "Isolation64Bit"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR + ". This finding is covered by the USAF STIG Deviation Memo."}
                }

            #V-46997
            #Microsoft Internet Explorer 11 STIG
            #Anti-Malware programs against ActiveX controls must be run for the Internet zone.
            "SV-59863r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Internet Zone 
                #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
                $ValueName = "270C"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-46999
            #Microsoft Internet Explorer 11 STIG
            #Anti-Malware programs against ActiveX controls must be run for the Intranet zone.
            "SV-59865r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Intranet Zone 
                #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
                $ValueName = "270C"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-47003
            #Microsoft Internet Explorer 11 STIG
            #Anti-Malware programs against ActiveX controls must be run for the Local Machine zone.
            "SV-59869r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Local Machine Zone 
                #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
                $ValueName = "270C"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-47005
            #Microsoft Internet Explorer 11 STIG
            #Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone.
            "SV-59871r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
                #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
                $ValueName = "270C"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-47009
            #Microsoft Internet Explorer 11 STIG
            #Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone.
            "SV-59875r1_rule" {
                #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
                #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
                $ValueName = "270C"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-57633
            #Windows Server 2012/2012 R2 MS STIG
            #The system must be configured to audit Policy Change - Authorization Policy Change successes.
            "SV-72043r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Authorization Policy Change" with "Success" selected. 
                if (($auditpol -match "Authorization Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Authorization Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-57637
            #Windows Server 2012/2012 R2 MS STIG
            #The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
            "SV-72047r5_rule" {
                #Manual review required, even if AppLocker is used
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-57639
            #Windows Server 2012/2012 R2 MS STIG
            #Users must be required to enter a password to access private keys stored on the computer.
            "SV-72049r2_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\" "ForceKeyProtection"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-57721
            #Windows Server 2012/2012 R2 MS STIG
            #Event Viewer must be protected from unauthorized modification and deletion.
            "SV-72135r2_rule" {
                #Checks that trusted installer is the only one with modify or full control
                $FSR=@(
                'FullControl',
                '268435456',
                'Modify',
                '-536805376')
                
                $IR=@('NT SERVICE\TrustedInstaller')

                $eventvwrAcl =(Get-Acl C:\Windows\System32\eventvwr.exe).Access
                if($eventvwrAcl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-64711
            #Microsoft Internet Explorer 11 STIG
            #Prevent bypassing SmartScreen Filter warnings must be enabled.
            "SV-79201r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
                #”Prevent bypassing SmartScreen Filter warnings” to ”Enabled”. 
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverride"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-64713
            #Microsoft Internet Explorer 11 STIG
            #Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled.
            "SV-79203r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
                #”Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet” to ”Enabled”. 
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverrideAppRepUnknown"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-64715
            #Microsoft Internet Explorer 11 STIG
            #Prevent per-user installation of ActiveX controls must be enabled.
            "SV-79205r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
                #”Prevent per-user installation of ActiveX controls” to ”Enabled”. 
                $ValueName = "BlockNonAdminActiveXInstall"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-64717
            #Microsoft Internet Explorer 11 STIG
            #Prevent ignoring certificate errors option must be enabled.
            "SV-79207r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel
                #”Prevent ignoring certificate errors” to ”Enabled”. 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -regValueName "PreventIgnoreCertErrors"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "SIPR CRQ000020012988"}
                }

            #V-64719
            #Microsoft Internet Explorer 11 STIG
            #Turn on SmartScreen Filter scan option for the Internet Zone must be enabled.
            "SV-79209r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
                #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
                $ValueName = "2301"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-64721
            #Microsoft Internet Explorer 11 STIG
            #Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled.
            "SV-79211r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
                #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
                $ValueName = "2301"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-64723
            #Microsoft Internet Explorer 11 STIG
            #The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone).
            "SV-79213r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
                #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
                $ValueName = "1201"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-64725
            #Microsoft Internet Explorer 11 STIG
            #The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone).
            "SV-79215r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
                #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
                $ValueName = "1201"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-64729
            #Microsoft Internet Explorer 11 STIG
            #Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled.
            "SV-79219r3_rule" {
                #Computer Configuration >> Administrative Templates >> Internet Explorer >> Security Features
                #"Allow fallback to SSL 3.0 (Internet Explorer)" to "Enabled", and select "No Sites" from the drop-down box. 
                $ValueName = "SecureProtocols"
                $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "2688") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-72753
            #Windows Server 2012/2012 R2 MS STIG
            #WDigest Authentication must be disabled.
            "SV-87391r1_rule" {
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"WDigest Authentication (disabling may require KB2871997)" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" "UseLogonCredential"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-72757
            #Microsoft Internet Explorer 11 STIG
            #Run once selection for running outdated ActiveX controls must be disabled.
            "SV-87395r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
                #"Remove the Run this time button for outdated ActiveX controls in IE" to "Enabled". 
                $ValueName = "RunThisTimeEnabled"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "SIPR CRQ000020012988"}
                }

            #V-72759
            #Microsoft Internet Explorer 11 STIG
            #Enabling outdated ActiveX controls for Internet Explorer must be blocked.
            "SV-87397r2_rule" {
                #(User Configuration? >>) Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
                #"Turn off blocking of outdated ActiveX controls for IE" to "Disabled". 
                $ValueName = "VersionCheckEnabled"
                $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "SIPR CRQ000020012988"}
                }

            #V-72761
            #Microsoft Internet Explorer 11 STIG
            #Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone.
            "SV-87399r2_rule" {
                #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
                #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
                if($OS -eq "Microsoft Windows Server 2016 Standard"){
                    $ValueName = "120c"
                    $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                    if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Not_Applicable"}
                }

            #V-72763
            #Microsoft Internet Explorer 11 STIG
            #Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone.
            "SV-87401r2_rule" {
                #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
                #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
                if($OS -eq "Microsoft Windows Server 2016 Standard"){
                    $ValueName = "120c"
                    $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                    if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Not_Applicable"}
                }

            #V-73519
            #Windows Server 2012/2012 R2 MS STIG
            #The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.
            "SV-88193r2_rule" {
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Configure SMBv1 Server" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-73523
            #Windows Server 2012/2012 R2 MS STIG
            #The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.
            "SV-88205r2_rule" {
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Configure SMBv1 client (extra setting needed for pre-Win8.1/2012R2)" to "Enabled" with the following three lines of text entered for "Configure LanmanWorkstation Dependencies":
                #Bowser
                #MRxSmb20
                #NSI
                $Value1 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
                $Value2 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\" "DependOnService"
                if ($Value1 -eq "4" -and $value2.Count -eq 3 -and $value2 -contains "Bowser" -and $value2 -contains "MRxSmb20" -and $value2 -contains "NSI") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-73805
            #Windows Server 2012/2012 R2 MS STIG
            #The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2.
            "SV-88471r2_rule" {
                #if 73523 and 73519 are configured this is not a finding. No way to guarantee they go before this so I'll just check twice.
                $Value1 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
                $Value2 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\" "DependOnService"
                if ($Value1 -eq "4" -and $value2.Count -eq 3 -and $value2 -contains "Bowser" -and $value2 -contains "MRxSmb20" -and $value2 -contains "NSI") {$73523 = $true}

                $Value3 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
                if ($Value3 -eq "0") {$73519 = $true}

                if($73523 -eq $true -and $73519 -eq $true){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-75169
            #Microsoft Internet Explorer 11 STIG
            #VBScript must not be allowed to run in Internet Explorer (Internet zone).
            "SV-89849r1_rule" { #Only applies to Win 10 Redstone 2 and higher.  I assume we are.
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
                #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
                if($OS -eq "Microsoft Windows 10 Enterprise"){
                    $ValueName = "140C"
                    $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
                    if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Not_Applicable"}
                }

            #V-75171
            #Microsoft Internet Explorer 11 STIG
            #VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).
            "SV-89851r1_rule" { #Only applies to Win 10 Redstone 2 and higher.  I assume we are.
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
                #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
                if($OS -eq "Microsoft Windows 10 Enterprise"){
                    $ValueName = "140C"
                    $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
                    if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Not_Applicable"}
                }

            #V-75915
            #Windows Server 2012/2012 R2 MS STIG
            #Orphaned security identifiers (SIDs) must be removed from user rights on Windows 2012 / 2012 R2.
            "SV-90603r1_rule" {
                #Check RSOP for deleted accounts
                if($UserRights.Accountlist -match "S-\d-\d+-(\d+-){1,14}\d+"){
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-76679
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server remote authors or content providers must only use secure encrypted logons and connections to upload web server content.
            "SV-91375r1_rule" { 
                $ActualStatus = "Not_Applicable"
                }

            #V-76681
            #IIS 8.5 Server STIG
            #The enhanced logging for the IIS 8.5 web server must be enabled and capture all user and web server events.
            "SV-91377r1_rule" { 
                if($serverlogfile.logFormat -eq "W3C"){
                    $valuestolookfor=@(
                    'Date',
                    'Time',
                    'ClientIP',
                    'UserName',
                    'Method',
                    'UriQuery',
                    'HttpStatus',
                    'Referer')
                    if (($valuestolookfor.where{$_ -notin $serverlogfile.logExtFileFlags.Split(",")}).count -eq 0){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-76683
            #IIS 8.5 Server STIG
            #Both the log file and Event Tracing for Windows (ETW) for the IIS 8.5 web server must be enabled.
            "SV-91379r1_rule" { 
                if ($serverlogfile.logTargetW3C -eq 'File,ETW'){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76685
            #IIS 8.5 Server STIG
            #Both the log file and Event Tracing for Windows (ETW) for the IIS 8.5 web server must be enabled.
            "SV-91381r2_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76687
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 web server events.
            "SV-91383r3_rule" { 
                foreach($customfield in $serverlogfile.customFields.Collection){
                    if($customfield.sourceName -eq "Connection" -and $customfield.sourceType -eq "RequestHeader"){$conreqheader=$true}
                    else{$conreqheader=$false}
                    if($customfield.sourceName -eq "Warning" -and $customfield.sourceType -eq "RequestHeader"){$warnreqheader=$true}
                    {$warnreqheader=$false}
                    }
                if ($conreqheader -and $warnreqheader){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76689
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
            "SV-91385r5_rule" { 
                if($serverlogfile.logFormat -eq "W3C"){
                    $valuestolookfor=@(
                    'UserName',
                    'UserAgent',
                    'Referer')
                    if(($valuestolookfor.where{$_ -notin $serverlogfile.logExtFileFlags.Split(",")}).count -eq 0){
                        foreach($customfield in $serverlogfile.customFields.Collection){
                            if($customfield.sourceName -eq "Authorization" -and $customfield.sourceType -eq "RequestHeader"){$authreqheader=$true}
                            if($customfield.sourceName -eq "Content-Type" -and $customfield.sourceType -eq "ResponseHeader"){$conresheader=$true}
                            }
                        if ($authreqheader -and $conresheader){$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Open"}
            }

            #V-76695
            #IIS 8.5 Server STIG
            #The log information from the IIS 8.5 web server must be protected from unauthorized modification or deletion.
            "SV-91391r5_rule" { 
                $defaultacl="O:BAG:SYD:AI(A;OICIID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;FA;;;CO)"
                $logdiracl=(Get-Acl $serverlogfile.directory.Replace("%SystemDrive%",$env:SystemDrive)).Sddl
                if ($logdiracl -eq $defaultacl) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76697
            #IIS 8.5 Server STIG
            #The log data and records from the IIS 8.5 web server must be backed up onto a different system or media.
            "SV-91393r2_rule" { 
                $ActualStatus = "Open"
                }

            #V-76699
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must not perform user management for hosted applications.
            "SV-91395r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76701
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must only contain functions necessary for operation.
            "SV-91397r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76703
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must not be both a website server and a proxy server.
            "SV-91399r1_rule" { 
                #I don't want to install this to add the check since we don't have it installed.
                if((C:\Windows\System32\inetsrv\appcmd.exe list modules "ApplicationRequestRouting") -eq $null){$ActualStatus = "NotAFinding"}
                }

            #V-76705
            #IIS 8.5 Server STIG
            #All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server.
            "SV-91401r1_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76707
            #IIS 8.5 Server STIG
            #The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 8.5 server.
            "SV-91403r1_rule" { 
                if ((Get-LocalUser).count -eq 2) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76709
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
            "SV-91405r1_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76711
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
            "SV-91407r1_rule" { 
                $valuestolookfor=@(
                '.exe.',
                '.dll',
                '.com',
                '.bat',
                '.csh')
                $mimetypes=(Get-WebConfiguration system.webserver/staticContent).collection.fileExtension
                if ($valuestolookfor -contains $mimetypes){$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-76713
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
            "SV-91409r1_rule" { 
                if($installedFeatures.name -contains "Web-DAV-Publishing"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-76715
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must perform RFC 5280-compliant certification path validation.
            "SV-91411r3_rule" { 
                $certs = Get-ChildItem Cert:\Localmachine\WebHosting
                if(($certs.issuer | Where-Object {$_ -notmatch "OU=PKI, OU=DoD, O=U.S. Government, C=US"}).count -eq 0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76717
            #IIS 8.5 Server STIG
            #Java software installed on a production IIS 8.5 web server must be limited to .class files and the Java Virtual Machine.
            "SV-91413r1_rule" { 
                if($javalist.count -eq 0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76719
            #IIS 8.5 Server STIG
            #IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
            "SV-91415r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76721
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must separate the hosted applications from hosted web server management functionality.
            "SV-91417r1_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76725
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must use cookies to track session state.
            "SV-91421r5_rule" { 
                if($serversessionstate.cookieless -eq "UseCookies") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76727
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must limit the amount of time a cookie persists.
            "SV-91423r4_rule" { 
                if($serversessionstate.cookieless -eq "UseCookies"){
                    if($serversessionstate.timeout -le [timespan]"00:20"){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-76729
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must augment re-creation to a stable and known baseline.
            "SV-91425r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76731
            #IIS 8.5 Server STIG
            #The production IIS 8.5 web server must utilize SHA2 encryption for the Machine Key.
            "SV-91427r3_rule" { 
                $machinekey=Get-WebConfiguration system.web/machinekey
                $valuestolookfor=@(
                'HMACSHA256',
                'HMACSHA384',
                'HMACSHA512')
                if($valuestolookfor -contains $machinekey.validation -and $machinekey.decryption -eq "Auto"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76733
            #IIS 8.5 Server STIG
            #Directory Browsing on the IIS 8.5 web server must be disabled.
            "SV-91429r2_rule" { 
                if ((Get-WebConfiguration system.webServer/directoryBrowse).enabled -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
                
            #V-76735
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server Indexing must only index web content.
            "SV-91431r2_rule" { 
                #We don't use it so I don't want to make a check for it
                $Value = Check-RegKeyValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalog"
                if ($Value -eq $null){$ActualStatus = "Not_Applicable"}
                }

            #V-76737
            #IIS 8.5 Server STIG
            #Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 web server, patches, loaded modules, and directory paths.
            "SV-91433r2_rule" { 
                if((Get-WebConfiguration system.webServer/httpErrors).errormode -eq "DetailedLocalOnly"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-76739
            #IIS 8.5 Server STIG
            #Remote access to the IIS 8.5 web server must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements.
            "SV-91435r2_rule" { 
                $ActualStatus = "Not_Applicable"
                }
                
            #V-76741
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must restrict inbound connections from nonsecure zones.
            "SV-91437r2_rule" { 
                if($installedFeatures.name -contains "Web-Mgmt-Service"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-76743
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
            "SV-91439r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76745
            #IIS 8.5 Server STIG
            #IIS 8.5 web server system files must conform to minimum file permission requirements.
            "SV-91441r2_rule" { 
                $defaultacl="O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"
                $inetpubacl=(Get-Acl C:\inetpub).Sddl
                if($inetpubacl -eq $defaultacl){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76747
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 web server.
            "SV-91443r1_rule" { 
                if ($serverlogfile.period -ne "MaxSize") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76749
            #IIS 8.5 Server STIG
            #Access to web administration tools must be restricted to the web manager and the web managers designees.
            "SV-91445r1_rule" { 
                $defaultacl="O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)"
                $inetmgracl=(Get-Acl C:\Windows\System32\inetsrv\InetMgr.exe).Sddl
                if ($inetmgracl -eq $defaultacl) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76751
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must not be running on a system providing any other role.
            "SV-91447r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76753
            #IIS 8.5 Server STIG
            #The Internet Printing Protocol (IPP) must be disabled on the IIS 8.5 web server.
            "SV-91449r1_rule" { 
                #Not installed so I'm not making checks for it
                if($installedFeatures.name -notcontains "Print-Services" -and $installedFeatures.name -notcontains "Print-Internet"){$ActualStatus = "Not_Applicable"}
                }

            #V-76755
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must be tuned to handle the operational requirements of the hosted application.
            "SV-91451r1_rule" { 
                $Value1 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\" "URIEnableCache"
                $Value2 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\" "UriMaxUriBytes"
                $Value3 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\" "UriScavengerPeriod"
                if ($Value1 -eq "1" -and $Value2 -eq "262144" -and $Value3 -eq "120") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76757
            #IIS 8.5 Server STIG
            #IIS 8.5 web server session IDs must be sent to the client using TLS.
            "SV-91453r1_rule" { 
                if ((Get-WebConfiguration system.webserver/asp/session).keepSessionIdSecure -eq $true){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76759
            #IIS 8.5 Server STIG
            #An IIS 8.5 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.
            "SV-91455r3_rule" { 
                $tlsregkeys=@()
                #TLS 1.2
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "DisabledByDefault") -eq 0){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault"}
                #TLS 1.1
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "DisabledByDefault") -eq 1){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault"}
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" "Enabled") -eq 0){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled"}
                #TLS 1.0
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "DisabledByDefault") -eq 1){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault"}
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" "Enabled") -eq 0){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled"}
                #SSL 2.0
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" "DisabledByDefault") -eq 1){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\DisabledByDefault"}
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" "Enabled") -eq 0){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled"}
                ##SSL 3.0
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" "DisabledByDefault") -eq 1){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\DisabledByDefault"}
                if(-not(Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" "Enabled") -eq 0){$tlsregkeys += "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled"}

                if ($tlsregkeys.count -eq 0){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following registry keys were misconfigured: `n$tlsregkeys"}
                }

            #V-76761
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must not be running on a system providing any other role.
            "SV-91457r2_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76765
            #IIS 8.5 Server STIG
            #All accounts installed with the IIS 8.5 web server software and tools must have passwords assigned and default passwords changed.
            "SV-91461r1_rule" { 
                if ((Get-LocalUser).count -eq 2) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76767
            #IIS 8.5 Server STIG
            #The File System Object component must be disabled on the IIS 8.5 web server.
            "SV-91463r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76769
            #IIS 8.5 Server STIG
            #Unspecified file extensions on a production IIS 8.5 web server must be removed.
            "SV-91465r1_rule" { 
                $isapi=Get-WebConfiguration system.webServer/security/isapiCgiRestriction
                if ($isapi.notListedCgisAllowed -eq $false -and $isapi.notListedIsapisAllowed -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76771
            #IIS 8.5 Server STIG
            #The IIS 8.5 web server must have a global authorization rule configured to restrict access.
            "SV-91467r4_rule" { 
                $netauth=(Get-WebConfiguration system.web/authorization).Collection.Users
                if ($netauth -eq "Administrator" -or $netauth.count -eq 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76775
            #IIS 8.5 Site STIG
            #The IIS 8.5 website session state must be enabled.
            "SV-91471r2_rule" { 
                if ((Get-WebConfiguration system.web/sessionstate -PSPath "IIS:\Sites\Default Web Site").mode -eq "InProc") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76777
            #IIS 8.5 Site STIG
            #The IIS 8.5 website session state cookie settings must be configured to Use Cookies mode.
            "SV-91473r3_rule" { 
                if ((Get-WebConfiguration system.web/sessionstate -PSPath "IIS:\Sites\Default Web Site").cookieless -eq "UseCookies") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76779
            #IIS 8.5 Site STIG
            #A private IIS 8.5 website must only accept Secure Socket Layer connections.
            "SV-91475r4_rule" { 
                if ((Get-WebConfiguration system.webServer/security/access -PSPath "IIS:\Sites\Default Web Site").sslFlags.split(",") -contains "Ssl") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76781
            #IIS 8.5 Site STIG
            #A public IIS 8.5 website must only accept Secure Socket Layer connections when authentication is required.
            "SV-91477r2_rule" { 
                $ActualStatus = "Not_Applicable"
                }

            #V-76783
            #IIS 8.5 Site STIG
            #The enhanced logging for each IIS 8.5 website must be enabled and capture, record, and log all content related to a user session.
            "SV-91479r1_rule" { 
                if($sitelogfile.logFormat -eq "W3C"){
                    $valuestolookfor=@(
                    'Date',
                    'Time',
                    'ClientIP',
                    'UserName',
                    'Method',
                    'UriQuery',
                    'HttpStatus',
                    'Referer')
                    if (($valuestolookfor.where{$_ -notin $sitelogfile.logExtFileFlags.Split(",")}).count -eq 0){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-76785
            #IIS 8.5 Site STIG
            #Both the log file and Event Tracing for Windows (ETW) for each IIS 8.5 website must be enabled.
            "SV-91481r1_rule" { 
                #Comments detailing the GPO setting path
                #Comments describing the setting to configure and what to set it to
                if ($sitelogfile.logTargetW3C -eq 'File,ETW'){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76787
            #IIS 8.5 Server STIG
            #An IIS 8.5 website behind a load balancer or proxy server, must produce log records containing the source client IP and destination information.
            "SV-91483r3_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76789
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 website events.
            "SV-91485r2_rule" { 
                foreach($customfield in $sitelogfile.customFields.Collection){
                    if($customfield.sourceName -eq "Connection" -and $customfield.sourceType -eq "RequestHeader"){$conreqheader=$true}
                    else{$conreqheader=$false}
                    if($customfield.sourceName -eq "Warning" -and $customfield.sourceType -eq "RequestHeader"){$warnreqheader=$true}
                    else{$warnreqheader=$false}
                    }
                if ($conreqheader -and $warnreqheader){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76791
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
            "SV-91487r3_rule" { 
                if($sitelogfile.logFormat -eq "W3C"){
                    $valuestolookfor=@(
                    'UserName',
                    'UserAgent',
                    'Referer')
                    if(($valuestolookfor.where{$_ -notin $sitelogfile.logExtFileFlags.Split(",")}).count -eq 0){
                        foreach($customfield in $serverlogfile.customFields.Collection){
                            if($customfield.sourceName -eq "Authorization" -and $customfield.sourceType -eq "RequestHeader"){$authreqheader=$true}
                            else{$authreqheader=$false}
                            if($customfield.sourceName -eq "Content-Type" -and $customfield.sourceType -eq "ResponseHeader"){$conresheader=$true}
                            else{$conresheader=$false}
                            }
                        if ($authreqheader -and $conresheader){$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-76797
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
            "SV-91493r1_rule" { 
                $valuestolookfor=@(
                '.exe.',
                '.dll',
                '.com',
                '.bat',
                '.csh')
                $mimetypes=(Get-WebConfiguration system.webserver/staticContent -PSPath "IIS:\Sites\Default Web Site").Collection.fileExtension
                if ($valuestolookfor -contains $mimetypes){$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-76799
            #IIS 8.5 Site STIG
            #Mappings to unused and vulnerable scripts on the IIS 8.5 website must be removed.
            "SV-91495r3_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76801
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must have resource mappings set to disable the serving of certain file types.
            "SV-91497r2_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76803
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must have Web Distributed Authoring and Versioning (WebDAV) disabled.
            "SV-91499r1_rule" { 
                if($installedFeatures.name -contains "Web-DAV-Publishing"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-76807
            #IIS 8.5 Site STIG
            #Each IIS 8.5 website must be assigned a default host header.
            "SV-91503r3_rule" { 
                $ActualStatus = "NotAFinding"
                $bindings=(Get-WebBinding -Name 'Default Web Site').bindinginformation
                foreach($binding in $bindings){if(($binding.split(":")).count -ne 3){$ActualStatus = "Open"}}
                }

            #V-76809
            #IIS 8.5 Site STIG
            #A private websites authentication mechanism must use client certificates to transmit session identifier to assure integrity.
            "SV-91505r2_rule" { 
                if((Get-WebConfiguration system.webServer/security/access -PSPath "IIS:\Sites\Default Web Site").sslFlags.split(",") -contains "SslRequireCert"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76811
            #IIS 8.5 Site STIG
            #Anonymous IIS 8.5 website access accounts must be restricted.
            "SV-91507r3_rule" { 
                $anon=Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -PSPath "IIS:\Sites\Default Web Site"
                if ($anon.enabled -eq "False"){$ActualStatus = "NotAFinding"}
                else{
                    if((Get-LocalUser $anon.userName -ErrorAction SilentlyContinue) -eq $null){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-76813
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must generate unique session identifiers that cannot be reliably reproduced.
            "SV-91509r2_rule" { 
                if ((Get-WebConfiguration system.web/sessionstate -PSPath "IIS:\Sites\Default Web Site").mode -eq "InProc") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76815
            #IIS 8.5 Site STIG
            #The IIS 8.5 website document directory must be in a separate partition from the IIS 8.5 websites system files.
            "SV-91511r1_rule" { 
                if ((Get-Website -Name "Default Web Site").PhysicalPath -notmatch "%SystemDrive%") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76817
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must be configured to limit the maxURL.
            "SV-91513r1_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering/requestlimits -PSPath "IIS:\Sites\Default Web Site").maxurl -le 4096) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76819
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must be configured to limit the size of web requests.
            "SV-91515r2_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering/requestlimits -PSPath "IIS:\Sites\Default Web Site").maxAllowedContentLength -le 30000000) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76821
            #IIS 8.5 Site STIG
            #The IIS 8.5 websites Maximum Query String limit must be configured.
            "SV-91517r1_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering/requestlimits -PSPath "IIS:\Sites\Default Web Site").maxQueryString -le 2048) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76823
            #IIS 8.5 Site STIG
            #Non-ASCII characters in URLs must be prohibited by any IIS 8.5 website.
            "SV-91519r1_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering -PSPath "IIS:\Sites\Default Web Site").allowHighBitCharacters -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76825
            #IIS 8.5 Site STIG
            #Double encoded URL requests must be prohibited by any IIS 8.5 website.
            "SV-91521r1_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering -PSPath "IIS:\Sites\Default Web Site").allowDoubleEscaping -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76827
            #IIS 8.5 Site STIG
            #Unlisted file extensions in URL requests must be filtered by any IIS 8.5 website.
            "SV-91523r2_rule" { 
                if ((Get-WebConfiguration system.webServer/security/requestFiltering/fileExtensions -PSPath "IIS:\Sites\Default Web Site").allowUnlisted -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76829
            #IIS 8.5 Site STIG
            #Directory Browsing on the IIS 8.5 website must be disabled.
            "SV-91525r2_rule" { 
                if ((Get-WebConfiguration system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site").enabled -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76835
            #IIS 8.5 Server STIG
            #Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 website, patches, loaded modules, and directory paths.
            "SV-91531r1_rule" { 
                if((Get-WebConfiguration system.webServer/httpErrors -PSPath "IIS:\Sites\Default Web Site").errormode -eq "DetailedLocalOnly"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-76837
            #IIS 8.5 Site STIG
            #Debugging and trace information used to diagnose the IIS 8.5 website must be disabled.
            "SV-91533r1_rule" { 
                if ((Get-WebConfiguration system.web/compilation -PSPath "IIS:\Sites\Default Web Site").debug -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76839
            #IIS 8.5 Site STIG
            #The Idle Time-out monitor for each IIS 8.5 website must be enabled.
            "SV-91535r2_rule" { 
                $processModel=Get-ItemProperty IIS:\AppPools\$appPool -Name processmodel
                if ($processModel.idleTimeout -le [timespan]"00:20" -and $processModel.idleTimeout -gt [timespan]"00:00") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76841
            #IIS 8.5 Site STIG
            #The IIS 8.5 websites connectionTimeout setting must be explicitly configured to disconnect an idle session.
            "SV-91537r2_rule" { 
                if ((Get-WebConfiguration system.web/sessionstate -PSPath "IIS:\Sites\Default Web Site").timeout -le [timespan]"00:20") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76843
            #IIS 8.5 Server STIG
            #The IIS 8.5 website must provide the capability to immediately disconnect or disable remote access to the hosted applications.
            "SV-91539r1_rule" { 
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                }

            #V-76845
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 website.
            "SV-91541r1_rule" { 
                if ($sitelogfile.period -ne "MaxSize") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76847
            #IIS 8.5 Site STIG
            #The IIS 8.5 websites must utilize ports, protocols, and services according to PPSM guidelines.
            "SV-91543r1_rule" { 
                $ActualStatus = "NotAFinding"
                $bindings=(Get-WebBinding -Name 'Default Web Site').bindinginformation
                foreach($binding in $bindings){if($binding.split(":")[1] -ne 443 -and $binding.split(":")[1] -ne 80){$ActualStatus = "Open"}}
                }

            #V-76849
            #IIS 8.5 Site STIG
            #The IIS 8.5 private website have a server certificate issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
            "SV-91545r4_rule" { 
                $SSLBinding=Get-ChildItem -Path IIS:SSLBindings | where Sites -eq "Default Web Site"
                $certificate = Get-ChildItem -Path Cert:\LocalMachine\WebHosting |Where-Object -Property Thumbprint -EQ -Value $SSLBinding.Thumbprint
                if($certificate.issuer -match "OU=PKI, OU=DoD, O=U.S. Government, C=US"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76851
            #IIS 8.5 Site STIG
            #The IIS 8.5 private website must employ cryptographic mechanisms (TLS) and require client certificates.
            "SV-91547r5_rule" { 
                if ((Get-WebConfiguration system.webServer/security/access -PSPath "IIS:\Sites\Default Web Site").sslflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76855
            #IIS 8.5 Site STIG
            #IIS 8.5 website session IDs must be sent to the client using TLS.
            "SV-91551r1_rule" {                 
                if ((Get-WebConfiguration system.webServer/asp/session -PSPath "IIS:\Sites\Default Web Site").keepsessionidsecure -eq $true) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76859
            #IIS 8.5 Site STIG
            #Cookies exchanged between the IIS 8.5 website and the client must use SSL/TLS, have cookie properties set to prohibit client-side scripts from reading the cookie data and must not be compressed.
            "SV-91555r4_rule" { 
                $httpcookies=(Get-WebConfiguration system.web/httpCookies -PSPath "IIS:\Sites\Default Web Site").requireSSL
                $sessionstate=(Get-WebConfiguration system.web/sessionState -PSPath "IIS:\Sites\Default Web Site").compressionEnabled
                if ($httpcookies -eq $true -and $sessionstate -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76861
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must maintain the confidentiality and integrity of information during preparation for transmission and during reception.
            "SV-91557r5_rule" { 
                if ((Get-WebConfiguration system.webServer/security/access -PSPath "IIS:\Sites\Default Web Site").sslflags -eq "Ssl,SslNegotiateCert,SslRequireCert,Ssl128") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76865
            #IIS 8.5 Site STIG
            #The IIS 8.5 website must have a unique application pool.
            "SV-91561r4_rule" { 
                if (((Get-Website -Name 'default web site').applicationpool).count -eq 1) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76867
            #IIS 8.5 Site STIG
            #The maximum number of requests an application pool can process for each IIS 8.5 website must be explicitly set.
            "SV-91563r4_rule" { 
                $recycling=Get-ItemProperty IIS:\AppPools\$appPool -Name recycling
                if ($recycling.periodicRestart.requests -ne 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76869
            #IIS 8.5 Site STIG
            #The amount of virtual memory an application pool uses for each IIS 8.5 website must be explicitly set.
            "SV-91565r4_rule" { 
                $recycling=Get-ItemProperty IIS:\AppPools\$appPool -Name recycling
                if ($recycling.periodicRestart.memory -ne 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76871
            #IIS 8.5 Site STIG
            #The amount of private memory an application pool uses for each IIS 8.5 website must be explicitly set.
            "SV-91567r3_rule" { 
                $recycling=Get-ItemProperty IIS:\AppPools\$appPool -Name recycling
                if ($recycling.periodicRestart.privateMemory -ne 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76873
            #IIS 8.5 Site STIG
            #The application pool for each IIS 8.5 website must have a recycle time explicitly set.
            "SV-91569r1_rule" { 
                $recycling=Get-ItemProperty IIS:\AppPools\$appPool -Name recycling
                if ($recycling.logEventOnRecycle -match "Time" -and $recycling.logEventOnRecycle -match "Schedule") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76875
            #IIS 8.5 Site STIG
            #The maximum queue length for HTTP.sys for each IIS 8.5 website must be explicitly configured.
            "SV-91571r1_rule" { 
                if ((Get-ItemProperty IIS:\AppPools\$appPool).queueLength -le 1000) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76877
            #IIS 8.5 Site STIG
            #The application pools pinging monitor for each IIS 8.5 website must be enabled.
            "SV-91573r1_rule" { 
                $processModel=Get-ItemProperty IIS:\AppPools\$appPool -Name processmodel
                if ($processModel.pingingenabled -eq $true) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76879
            #IIS 8.5 Site STIG
            #The application pools rapid fail protection for each IIS 8.5 website must be enabled.
            "SV-91575r1_rule" { 
                $failure=Get-ItemProperty IIS:\AppPools\$appPool -name failure
                if ($failure.rapidFailProtection -eq $true) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76881
            #IIS 8.5 Site STIG
            #The application pools rapid fail protection settings for each IIS 8.5 website must be managed.
            "SV-91577r1_rule" { 
                $failure=Get-ItemProperty IIS:\AppPools\$appPool -name failure
                if ($failure.rapidFailProtectionInterval -le [timespan]"00:05") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-76885
            #IIS 8.5 Site STIG
            #Interactive scripts on the IIS 8.5 web server must be located in unique and designated folders.
            "SV-91581r4_rule" { 
                $ActualStatus = "NotAFinding"
                }

            #V-76887
            #IIS 8.5 Site STIG
            #Interactive scripts on the IIS 8.5 web server must have restrictive access controls.
            "SV-91583r2_rule" { 
                #We don't use these so I don't really want to code to check for them
                $physicalPath=(Get-Website -Name "Default Web Site").PhysicalPath.replace("%SystemDrive%","$env:systemdrive")
                if ((Get-ChildItem $physicalPath -Recurse -Include *.cgi).count -eq 0) {$ActualStatus = "Not_Applicable"}
                else {$ActualStatus = "Open"}
                }

            #V-76889
            #IIS 8.5 Site STIG
            #Backup interactive scripts on the IIS 8.5 server must be removed.
            "SV-91585r1_rule" { 
                #We don't use these so I don't really want to code to check for them
                $physicalPath=(Get-Website -Name "Default Web Site").PhysicalPath.replace("%SystemDrive%","$env:systemdrive")
                if ((Get-ChildItem $physicalPath -Recurse -Include *.cgi).count -eq 0) {$ActualStatus = "Not_Applicable"}
                else {$ActualStatus = "Open"}
                }

            #V-76891
            #IIS 8.5 Server STIG
            #The required DoD banner page must be displayed to authenticated users accessing a DoD private website.
            "SV-91587r1_rule" { 
                if((Get-Content E:\inetpub\wwwroot\DRAWeb\WebConsole\Custom\appmessages.asp) -match "DOD_SPLASH"){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-78057
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout successes.
            "SV-92765r2_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Account Lockout" with "Success" selected. 
                if (($auditpol -match "Account Lockout") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Account Lockout") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-78059
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout failures.
            "SV-92769r2_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Account Lockout" with "Failure" selected. 
                if (($auditpol -match "Account Lockout") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Account Lockout") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-78061
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Server 2012/2012 R2 must be configured to audit System - Other System Events successes.
            "SV-92773r2_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
                #"Audit Other System Events" with "Success" selected.
                if (($auditpol -match "Other System Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other System Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-78063
            #Windows Server 2012/2012 R2 MS STIG
            #Windows Server 2012/2012 R2 must be configured to audit System - Other System Events failures.
            "SV-92781r2_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
                #"Audit Other System Events" with "Failure" selected.
                if (($auditpol -match "Other System Events") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other System Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-80473
            #Windows Server 2012/2012 R2 MS STIG
            #Windows PowerShell must be updated to a version that supports script block logging on Windows 2012/2012 R2.
            "SV-95179r1_rule" {
                $ActualStatus = "NotAFinding"
                }

            #V-80475
            #Windows Server 2012/2012 R2 MS STIG
            #PowerShell script block logging must be enabled on Windows 2012/2012 R2.
            "SV-95183r2_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell
                #"Turn on PowerShell Script Block Logging" to "Enabled". 
                #Install patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 on systems with PowerShell 4.0. 
                #PowerShell 5.x does not require the installation of an additional patch.
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" "EnableScriptBlockLogging" "SilentlyContinue"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-80477
            #Windows Server 2012/2012 R2 MS STIG
            #Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2.
            "SV-95185r1_rule" {
                if($installedFeatures.name -contains "Powershell-v2"){$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should uninstall Powershell-v2"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-91777
            #Windows Server 2012/2012 R2 DC STIG
            #The password for the krbtgt account on a domain must be reset at least every 180 days.
            "SV-101879r2_rule" { 
                $OldDate = (Get-Date).AddDays(-180)
                $krbtgtSet = Get-ADUser krbtgt -Property PasswordLastSet | select -ExpandProperty PasswordLastSet
                if ($krbtgtSet -gt $OldDate) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The password was last set $krbtgtSet"}
                }

            #V-92961
            #Windows Server 2019 STIG
            #Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.
            "SV-103049r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive logon: Machine inactivity limit" to "900" seconds" or less. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "InactivityTimeoutSecs"
                if ($Value -le "900") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92963
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-103051r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on through Remote Desktop Services" to include the following:
                #Guests Group 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                    if ($value -eq "Guests"){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-92965
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems.
            "SV-103053r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
                #"Deny log on through Remote Desktop Services" to include the following:
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    if ($PartOfDomain) {
                        $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Local account" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else{
                        if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    }
                }

            #V-92967
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit logon successes.
            "SV-103055r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logon" with "Success" selected.  
                if (($auditpol -match "^(\s)+Logon") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92969
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit logon failures.
            "SV-103057r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logon" with "Failure" selected.  
                if (($auditpol -match "^(\s)+Logon") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92971
            #Windows Server 2019 STIG
            #Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.
            "SV-103059r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
                #"Require secure RPC communication" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fEncryptRPCTraffic"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92973
            #Windows Server 2019 STIG
            #Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level.
            "SV-103061r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
                #"Set client connection encryption level" to "Enabled" and "High Level". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "MinEncryptionLevel"
                if ($Value -eq "3") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92975
            #Windows Server 2019 STIG
            #Windows Server 2019 must automatically remove or disable temporary user accounts after 72 hours.
            "SV-103063r1_rule" { 
                #Can't be checked
                $ActualStatus = "Not_Applicable"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not use temporary accounts in AFNET."
                }

            #V-92977
            #Windows Server 2019 STIG
            #Windows Server 2019 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
            "SV-103065r1_rule" { 
                #Can't be checked
                $ActualStatus = "Not_Applicable"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not use emergency administrator accounts."
                }
 
            #V-92979
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Management - Security Group Management successes.
            "SV-103067r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Security Group Management" with "Success" selected.  
                if (($auditpol -match "Security Group Management") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security Group Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92981
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Management - User Account Management successes.
            "SV-103069r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit User Account Management" with "Success" selected.  
                if (($auditpol -match "User Account Management") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "User Account Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92983
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Management - User Account Management failures.
            "SV-103071r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit User Account Management" with "Failure" selected.  
                if (($auditpol -match "User Account Management") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "User Account Management") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-92985
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Management - Computer Account Management successes.
            "SV-103073r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Computer Account Management" with "Success" selected.  
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if (($auditpol -match "Computer Account Management") -match "Success") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-92987
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout successes.
            "SV-103075r1_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Account Lockout" with "Success" selected. 
                if (($auditpol -match "Account Lockout") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Account Lockout") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-92989
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout failures.
            "SV-103077r1_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Account Lockout" with "Failure" selected. 
                if (($auditpol -match "Account Lockout") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Account Lockout") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-92991
            #Windows Server 2019 STIG
            #Windows Server 2019 local volumes must use a format that supports NTFS attributes.
            "SV-103079r1_rule" { 
                #All local volumes must be NTFS or ReFS
                #Check to see if there's any local volumes that AREN'T compliant
                #if (Get-WMIObject -Class Win32_Volume | Where {$_.DriveType -eq 3 -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {$ActualStatus = "Open"}
                if ([System.IO.DriveInfo]::getdrives() | Where-Object {$_.drivetype -eq "fixed" -and $_.driveformat -ne "NTFS" -and $_.driveformat -ne "ReFS"}) {$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-92993
            #Windows Server 2019 STIG
            #Windows Server 2019 non-administrative accounts or groups must only have print permissions on printer shares.
            "SV-103081r1_rule" { 
                $printShares = get-printer * -full -EA SilentlyContinue | Where {$_.shared -eq $true}
                if ($printShares.count -eq 0) {$ActualStatus = "Not_Applicable"}
                else {$ActualStatus = "Open"}
                }

            #V-92995
            #Windows Server 2019 STIG
            #Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.
            "SV-103083r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
                    if ($value.count -eq 3 -and $value -contains "Administrators" -and $value -contains "Authenticated Users" -and $value -contains "Enterprise Domain Controllers") {$ActualStatus = "NotAFinding"}
                    elseif ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-92997
            #Windows Server 2019 STIG
            #Windows Server 2019 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers.
            "SV-103085r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Allow log on through Remote Desktop Services" to only include the following accounts or groups:
                #Administrators 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
                    if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                }

            #V-92999
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-103087r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny access to this computer from the network" to include the following: Guests Group
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93001
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-103089r1_rule" {
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a batch job" to include the following:
                #Guests Group 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93003
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.
            "SV-103091r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on as a service" to include no entries (blank). 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if($UserRights.UserRight -contains "SeDenyServiceLogonRight"){
                        $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
                        if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93005
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.
            "SV-103093r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Deny log on locally" to include the following:
                #Guests Group 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
                    if ($value -contains "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93007
            #Windows Server 2019 STIG
            #Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone systems.
            "SV-103095r1_rule" { 
            #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Access this computer from the network" to only include the following accounts or groups:
                #Administrators
                #Authenticated Users
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
                    if ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93009
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems.
            "SV-103097r1_rule" { 
            #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
            if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
            else{
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
                if($PartOfDomain){
                    if($value -contains "Local account and member of Administrators group" -and $Value -match "\\Enterprise Admins" -and $Value -match "\\Domain Admins"){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                        }
                else{
                    if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93011
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.
            "SV-103099r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
                    if ($PartOfDomain) {
                        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {
                        if ($value -eq "Guests"){$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93013
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.
            "SV-103101r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
                    if ($PartOfDomain) {
                        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {
                        if ($value -eq $null) {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93015
            #Windows Server 2019 STIG
            #Windows Server 2019 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.
            "SV-103103r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
                    if ($PartOfDomain) {
                        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {
                        if ($value -eq "Guests") {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93017
            #Windows Server 2019 STIG
            #Windows Server 2019 Allow log on locally user right must only be assigned to the Administrators group.
            "SV-103105r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Allow log on locally" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeInteractiveLogonRight"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93019
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for the system drive root directory (usually C:\) must conform to minimum requirements.
            "SV-103107r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators')

                    $Cacl=(Get-Acl C:\).Access
                    if($Cacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-93021
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for program file directories must conform to minimum requirements.
            "SV-103109r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $badacl=@()
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')

                    $programfilesacl=(Get-Acl 'C:\Program Files').Access
                    $programfiles86acl=(Get-Acl 'C:\Program Files (x86)').Access
                    if($programfilesacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files'}
                    if($programfiles86acl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files (x86)'}
                    if($badacl.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following folder(s) contain a bad ACL entry: $badacl"}
                    }
                else{$ActualStatus = "Open"}
                }
                
            #V-93023
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for the Windows installation directory must conform to minimum requirements.
            "SV-103111r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')

                    $windowsacl=(Get-Acl C:\Windows).Access
                    if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                else{$ActualStatus = "Open"}
                }

            #V-93025
            #Windows Server 2019 STIG
            #Windows Server 2019 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
            "SV-103113r1_rule" { 
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('Security', 'Default', 'ReadPermissions')
                $regSECURITYAcl = ($key.GetAccessControl()).sddl
                $defaultacl="O:BAG:SYD:P(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)"
                if($regSECURITYAcl -eq $defaultacl){$securityperms = $true}

                $regSOFTWAREAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE").Sddl
                $defaultacl="O:BAG:SYD:PAI(A;CI;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)"
                if($regSOFTWAREAcl -eq $defaultacl){$softwareperms = $true}

                $regSYSTEMAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SYSTEM").Sddl
                $defaultacl="O:BAG:SYD:PAI(A;CIIO;GA;;;CO)(A;CIIO;GR;;;AU)(A;;KR;;;AU)(A;CIIO;GA;;;SY)(A;;KA;;;SY)(A;CIIO;GA;;;BA)(A;;KA;;;BA)(A;CIIO;GR;;;SO)(A;;KR;;;SO)(A;;KR;;;AC)(A;CIIO;GR;;;AC)(A;;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIO;GR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)"
                if($regSYSTEMAcl -eq $defaultacl){$systemperms = $true}

                if($securityperms -and $softwareperms -and $systemperms){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-93027
            #Windows Server 2019 STIG
            #Windows Server 2019 must only allow administrators responsible for the domain controller to have Administrator rights on the system.
            "SV-103115r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is enforced."
                    }
                }
            
            #V-93029
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions on the Active Directory data files must only allow System and Administrators access.
            "SV-103117r1_rule" { 
                #Since anyone that opens the NTDS folder gets added with full control, this check makes sure that any extra accounts are admin accounts based on the level codes in the naming convention TO.
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $NTDSacl=(Get-Acl E:\Windows\NTDS).Access
                    $accounts=($NTDSacl | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators"}).IdentityReference.Value
                
                    if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                    elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                    else{
                        foreach($account in $accounts){
                            if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                            }
                        }
                    }
                }

            #V-93031
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory SYSVOL directory must have the proper access control permissions.
            "SV-103119r1_rule" { 
            if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
            else{
                    $FSR=@(
                    'FullControl',
                    '268435456',
                    'Modify',
                    '-536805376')

                    $IR=@(
                    'CREATOR OWNER',
                    'NT AUTHORITY\SYSTEM',
                    'BUILTIN\Administrators',
                    'NT SERVICE\TrustedInstaller')
                    
                    $sysvolacl=(Get-Acl E:\Windows\SYSVOL).Access
                    if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93033
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Group Policy objects must have proper access control permissions.
            "SV-103121r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "There are no standard user accounts or groups that have permissions to the GPO's."
                    }
                }

            #V-93035
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions.
            "SV-103123r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93037
            #Windows Server 2019 STIG
            #Windows Server 2019 organization created Active Directory Organizational Unit (OU) objects must have proper access control permissions.
            "SV-103125r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93039
            #Windows Server 2019 STIG
            #Windows Server 2019 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers.
            "SV-103127r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Add workstations to domain" to only include the following accounts or groups:
                #Administrators 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeMachineAccountPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93041
            #Windows Server 2019 STIG
            #Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.
            "SV-103129r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Enable computer and user accounts to be trusted for delegation" to include the following:
                #Administrators 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
                    if ($value -contains "Administrators") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93043
            #Windows Server 2019 STIG
            #Windows Server 2019 must only allow administrators responsible for the member server or standalone system to have Administrator rights on the system.
            "SV-103131r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is enforced."
                    }
                }

            #V-93045
            #Windows Server 2019 STIG
            #Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems.
            "SV-103133r1_rule" { 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictRemoteSAM"
                    if ($Value -eq "O:BAG:BAD:(A;;RC;;;BA)") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93047
            #Windows Server 2019 STIG
            #Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone systems.
            "SV-103135r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank). 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    if($UserRights.UserRight -contains "SeEnableDelegationPrivilege"){
                        $value=$UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
                        if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                        else {$ActualStatus = "Open"}
                        }
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93049
            #Windows Server 2019 STIG
            #Windows Server 2019 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.
            "SV-103137r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Access Credential Manager as a trusted caller" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeTrustedCredManAccessPrivilege"){                
                    $value = $UserRights | Where-Object {$_.UserRight -eq "SeTrustedCredManAccessPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-93051
            #Windows Server 2019 STIG
            #Windows Server 2019 Act as part of the operating system user right must not be assigned to any groups or accounts.
            "SV-103139r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Act as part of the operating system" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeTcbPrivilege"){  
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeTcbPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }
                
            #V-93053
            #Windows Server 2019 STIG
            #Windows Server 2019 Back up files and directories user right must only be assigned to the Administrators group.
            "SV-103141r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Back up files and directories" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeBackupPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }                
                
            #V-93055
            #Windows Server 2019 STIG
            #Windows Server 2019 Create a pagefile user right must only be assigned to the Administrators group.
            "SV-103143r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create a pagefile" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreatePagefilePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }                
                
            #V-93057
            #Windows Server 2019 STIG
            #Windows Server 2019 Create a token object user right must not be assigned to any groups or accounts.
            "SV-103145r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create a token object" to be defined but containing no entries (blank).
                if($UserRights.UserRight -contains "SeCreateTokenPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateTokenPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }                
                
            #V-93059
            #Windows Server 2019 STIG
            #Windows Server 2019 Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.
            "SV-103147r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create global objects" to only include the following accounts or groups:
                #Administrators
                #Service
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateGlobalPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93061
            #Windows Server 2019 STIG
            #Windows Server 2019 Create permanent shared objects user right must not be assigned to any groups or accounts.
            "SV-103149r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Create permanent shared objects" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeCreatePermanentPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreatePermanentPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-93063
            #Windows Server 2019 STIG
            #Windows Server 2019 Create symbolic links user right must only be assigned to the Administrators group.
            "SV-103151r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
                #"Create symbolic links" to only include the following accounts or groups:
                #Administrators
                #Systems that have the Hyper-V role will also have "Virtual Machines" given this user right. If this needs to be added manually, enter it as "NT Virtual Machine\Virtual Machines". 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeCreateSymbolicLinkPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 1 -and $value -contains "Administrators") {$ActualStatus = "NotAFinding"}
                elseif ($value.Count -eq 2 -and $value -contains "Administrators" -and $value -contains "NT Virtual Machine\\Virtual Machines" -and ($installedFeatures.Name -contains "Hyper-V")) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93065
            #Windows Server 2019 STIG
            #Windows Server 2019 Debug programs: user right must only be assigned to the Administrators group.
            "SV-103153r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Debug programs" to only include the following accounts or groups:
                #Administrators 
                $value = $UserRights | Where-Object {$_.UserRight -eq "SeDebugPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators" -or $value -eq $null) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
                
            #V-93067
            #Windows Server 2019 STIG
            #Windows Server 2019 Force shutdown from a remote system user right must only be assigned to the Administrators group.
            "SV-103155r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Force shutdown from a remote system" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRemoteShutdownPrivilege"} | select -ExpandProperty AccountList
                if ($value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
                
            #V-93069
            #Windows Server 2019 STIG
            #Windows Server 2019 Generate security audits user right must only be assigned to Local Service and Network Service.
            "SV-103157r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Generate security audits" to only include the following accounts or groups:
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeAuditPrivilege"} | select -ExpandProperty AccountList
                if ($value.Count -eq 2 -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93071
            #Windows Server 2019 STIG
            #Windows Server 2019 Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.
            "SV-103159r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Impersonate a client after authentication" to only include the following accounts or groups:
                #Administrators
                #Service
                #Local Service
                #Network Service 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeImpersonatePrivilege"} | select -ExpandProperty AccountList as
                if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {$ActualStatus = "NotAFinding"}
                elseif($DomainName -eq "AFNOAPPS"){
                    if($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "AFNOAPPS\IIS_WPG") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-93073
            #Windows Server 2019 STIG
            #Windows Server 2019 Increase scheduling priority: user right must only be assigned to the Administrators group.
            "SV-103161r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Increase scheduling priority" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeIncreaseBasePriorityPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93075
            #Windows Server 2019 STIG
            #Windows Server 2019 Load and unload device drivers user right must only be assigned to the Administrators group.
            "SV-103163r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Load and unload device drivers" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeLoadDriverPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93077
            #Windows Server 2019 STIG
            #Windows Server 2019 Lock pages in memory user right must not be assigned to any groups or accounts.
            "SV-103165r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Lock pages in memory" to be defined but containing no entries (blank). 
                if($UserRights.UserRight -contains "SeLockMemoryPrivilege"){
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeLockMemoryPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else {$ActualStatus = "Open"}
                }                
                
            #V-93079
            #Windows Server 2019 STIG
            #Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group.
            "SV-103167r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Modify firmware environment values" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeSystemEnvironmentPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93081
            #Windows Server 2019 STIG
            #Windows Server 2019 Perform volume maintenance tasks user right must only be assigned to the Administrators group.
            "SV-103169r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Perform volume maintenance tasks" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeManageVolumePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93083
            #Windows Server 2019 STIG
            #Windows Server 2019 Profile single process user right must only be assigned to the Administrators group.
            "SV-103171r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Profile single process" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeProfileSingleProcessPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }                
                
            #V-93085
            #Windows Server 2019 STIG
            #Windows Server 2019 Restore files and directories user right must only be assigned to the Administrators group.
            "SV-103173r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Restore files and directories" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeRestorePrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }                
                
            #V-93087
            #Windows Server 2019 STIG
            #Windows Server 2019 Take ownership of files or other objects user right must only be assigned to the Administrators group.
            "SV-103175r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
                #"Take ownership of files or other objects" to only include the following accounts or groups:
                #Administrators 
                $value=$UserRights | Where-Object {$_.UserRight -eq "SeTakeOwnershipPrivilege"} | select -ExpandProperty AccountList
                if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }                               
                
            #V-93089
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Management - Other Account Management Events successes.
            "SV-103177r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
                #"Audit Other Account Management Events" with "Success" selected.  
                if (($auditpol -match "Other Account Management Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other Account Management Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93091
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Detailed Tracking - Process Creation successes.
            "SV-103179r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking
                #"Audit Process Creation" with "Success" selected.  
                if (($auditpol -match "Process Creation") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Process Creation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93093
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change successes.
            "SV-103181r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Audit Policy Change" with "Success" selected. 
                if (($auditpol -match "Audit Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Audit Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93095
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change failures.
            "SV-103183r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Audit Policy Change" with "Failure" selected. 
                if (($auditpol -match "Audit Policy Change") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Audit Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93097
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Policy Change - Authentication Policy Change successes.
            "SV-103185r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Authentication Policy Change" with "Success" selected. 
                if (($auditpol -match "Authentication Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Authentication Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93099
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Policy Change - Authorization Policy Change successes.
            "SV-103187r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
                #"Audit Authorization Policy Change" with "Success" selected. 
                if (($auditpol -match "Authorization Policy Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Authorization Policy Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93101
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use successes.
            "SV-103189r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
                #"Audit Sensitive Privilege Use" with "Success" selected. 
                if (($auditpol -match "Sensitive Privilege Use") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93103
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures.
            "SV-103191r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
                #"Audit Sensitive Privilege Use" with "Failure" selected. 
                if (($auditpol -match "Sensitive Privilege Use") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93105
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - IPsec Driver successes.
            "SV-103193r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit IPsec Driver" with "Success" selected. 
                if (($auditpol -match "IPsec Driver") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "IPsec Driver") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93107
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - IPsec Driver failures.
            "SV-103195r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit IPsec Driver" with "Failure" selected. 
                if (($auditpol -match "IPsec Driver") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "IPsec Driver") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93109
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - Other System Events successes.
            "SV-103197r1_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
                #"Audit Other System Events" with "Success" selected.
                if (($auditpol -match "Other System Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other System Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-93111
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - Other System Events failures.
            "SV-103199r1_rule" { 
                #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
                #"Audit Other System Events" with "Failure" selected.
                if (($auditpol -match "Other System Events") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other System Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-93113
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - Security State Change successes.
            "SV-103201r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit Security State Change" with "Success" selected. 
                if (($auditpol -match "Security State Change") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security State Change") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93115
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - Security System Extension successes.
            "SV-103203r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit Security State Extension" with "Success" selected. 
                if (($auditpol -match "Security System Extension") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Security System Extension") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93117
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - System Integrity successes.
            "SV-103205r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit System Integrity" with "Success" selected. 
                if (($auditpol -match "System Integrity") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "System Integrity") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93119
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit System - System Integrity failures.
            "SV-103207r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
                #"Audit System Integrity" with "Failure" selected. 
                if (($auditpol -match "System Integrity") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "System Integrity") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93121
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Group Policy objects must be configured with proper audit settings.
            "SV-103209r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93123
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Domain object must be configured with proper audit settings.
            "SV-103211r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93125
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Infrastructure object must be configured with proper audit settings.
            "SV-103213r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93127
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings.
            "SV-103215r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93129
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory AdminSDHolder object must be configured with proper audit settings.
            "SV-103217r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93131
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory RID Manager$ object must be configured with proper audit settings.
            "SV-103219r1_rule" { 
                #Idk how to check at least inclusive
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                }

            #V-93133
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit DS Access - Directory Service Access successes.
            "SV-103221r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Access" with "Success" selected.
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if (($auditpol -match "Directory Service Access") -match "Success") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93135
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures.
            "SV-103223r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Access" with "Failure" selected. 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if (($auditpol -match "Directory Service Access") -match "Failure") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93137
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit DS Access - Directory Service Changes successes.
            "SV-103225r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Changes" with "Success" selected. 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if (($auditpol -match "Directory Service Changes") -match "Success") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93139
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit DS Access - Directory Service Changes failures.
            "SV-103227r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
                #"Directory Service Changes" with "Failure" selected. 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if (($auditpol -match "Directory Service Changes") -match "Failure") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
                    }
                }

            #V-93141
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less.
            "SV-103229r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
                #"Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable). 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutThreshold -le 3 -and $passwordpolicy.LockoutThreshold -gt 0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }


            #V-93143
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.
            "SV-103231r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
                #"Reset account lockout counter after" to at least "60" minutes. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutObservationWindow -ge [timespan]"1:00"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93145
            #Windows Server 2019 STIG
            #Windows Server 2019 account lockout duration must be configured to 15 minutes or greater.
            "SV-103233r1_rule" {
                #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy
                #"Account lockout duration" to "15" minutes or greater, or 0.
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.LockoutDuration -ge [timespan]"00:15" -or $passwordpolicy.LockoutDuration -eq [timespan]0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93147
            #Windows Server 2019 STIG
            #Windows Server 2019 required legal notice must be configured to display before console logon.
            "SV-103235r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #“Interactive Logon: Message text for users attempting to log on” as outlined in the check. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeText"
                $LegalNotice = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details.
"@
                if ($Value -eq $LegalNotice) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
            }

            #V-93149
            #Windows Server 2019 STIG
            #Windows Server 2019 title for legal banner dialog box must be configured with the appropriate text.
            "SV-103237r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeCaption"
                if ($Value -eq "DoD Notice and Consent Banner" -or $Value -eq "US Department of Defense Warning Statement") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93151
            #Windows Server 2019 STIG
            #Windows Server 2019 must force audit policy subcategory settings to override audit policy category settings.
            "SV-103239r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "SCENoApplyLegacyAuditPolicy"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93153
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes.
            "SV-103241r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
                #"Audit Credential Validation" with "Success" selected. 
                if (($auditpol -match "Credential Validation") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Credential Validation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93155
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Account Logon - Credential Validation failures.
            "SV-103243r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
                #"Audit Credential Validation" with "Failure" selected. 
                if (($auditpol -match "Credential Validation") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Credential Validation") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93157
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Detailed Tracking - Plug and Play Events successes.
            "SV-103245r1_rule" { 
                if (($auditpol -match "Plug and Play Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Plug and Play Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93159
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Logon/Logoff - Group Membership successes.
            "SV-103247r1_rule" { 
                if (($auditpol -match "Group Membership") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Group Membership") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93161
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Logon/Logoff - Special Logon successes.
            "SV-103249r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Special Logon" with "Success" selected.  
                if (($auditpol -match "Special Logon") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Special Logon") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93163
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Object Access - Other Object Access Events successes.
            "SV-103251r1_rule" { 
                if (($auditpol -match "Other Object Access Events") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other Object Access Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93165
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Object Access - Other Object Access Events failures.
            "SV-103253r1_rule" { 
                if (($auditpol -match "Other Object Access Events") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Other Object Access Events") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93167
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Object Access - Removable Storage successes.
            "SV-103255r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
                #"Audit Removable Storage" with "Success" selected. 
                if (($auditpol -match "Removable Storage") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Removable Storage") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93169
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit Object Access - Removable Storage failures.
            "SV-103257r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
                #"Audit Removable Storage" with "Failure" selected. 
                if (($auditpol -match "Removable Storage") -match "Failure") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "Removable Storage") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93171
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to audit logoff successes.
            "SV-103259r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
                #"Audit Logoff" with "Success" selected.  
                if (($auditpol -match "^(\s)+Logoff") -match "Success") {$ActualStatus = "NotAFinding"}
                elseif (($auditpol -match "^(\s)+Logoff") -match "Success and Failure") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93173
            #Windows Server 2019 STIG
            #Windows Server 2019 command line data must be included in process creation events.
            "SV-103261r1_rule" { 
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Computer Configuration -> Administrative Templates -> System -> Audit Process Creation
                #"Include command line in process creation events" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" "ProcessCreationIncludeCmdLine_Enabled"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-93175
            #Windows Server 2019 STIG
            #Windows Server 2019 PowerShell script block logging must be enabled.
            "SV-103263r2_rule" { 
                #Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell
                #"Turn on PowerShell Script Block Logging" to "Enabled". 
                #Install patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 on systems with PowerShell 4.0. 
                #PowerShell 5.x does not require the installation of an additional patch.
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" "EnableScriptBlockLogging" "SilentlyContinue"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93177
            #Windows Server 2019 STIG
            #Windows Server 2019 Application event log size must be configured to 32768 KB or greater.
            "SV-103265r1_rule" { 
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" "MaxSize"
                if ($Value -ge 32768) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93179
            #Windows Server 2019 STIG
            #Windows Server 2019 Security event log size must be configured to 196608 KB or greater.
            "SV-103267r1_rule" { 
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" "MaxSize"
                if ($Value -ge 196608) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93181
            #Windows Server 2019 STIG
            #Windows Server 2019 System event log size must be configured to 32768 KB or greater.
            "SV-103269r1_rule" { 
                #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System 
                #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize"
                if ($Value -ge 32768) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93183
            #Windows Server 2019 STIG
            #Windows Server 2019 audit records must be backed up to a different system or media than the system being audited.
            "SV-103271r1_rule" { 
                #Idk how to check this
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}

            #V-93185
            #Windows Server 2019 STIG
            #Windows Server 2019 must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.
            "SV-103273r1_rule" { 
                #Not scriptable check
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}

            #V-93187
            #Windows Server 2019 STIG
            #The Windows Server 2019 time service must synchronize with an appropriate DoD time source.
            "SV-103275r1_rule" { 
                #Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers
                #"Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server. 
                $timeSettings = W32tm /query /configuration
                $type = ($timeSettings -match "Type: ").trim().split(":")[1].trim().split(" ")[0].trim()
                if ($type -eq "NT5DS") {$ActualStatus = "NotAFinding"}
                elseif($type -eq "NTP" -and ((gwmi win32_computersystem).Name -eq ((Get-ADDomain).PDCEmulator).split(".")[0])){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
            
            #V-93189
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for the Application event log must prevent access by non-privileged accounts.
            "SV-103277r1_rule" { 
                $applicationACL=(Get-Acl C:\Windows\System32\winevt\Logs\Application.evtx).access
                $accounts=($applicationACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93191
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts.
            "SV-103279r1_rule" { 
                $securityACL=(Get-Acl C:\Windows\System32\winevt\Logs\Security.evtx).access
                $accounts=($securityACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }

            #V-93193
            #Windows Server 2019 STIG
            #Windows Server 2019 permissions for the System event log must prevent access by non-privileged accounts.
            "SV-103281r1_rule" { 
                $systemACL=(Get-Acl C:\Windows\System32\winevt\Logs\System.evtx).access
                $accounts=($systemACL | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators" -and $_.IdentityReference -ne "NT SERVICE\EventLog"}).IdentityReference.Value
                
                if($accounts.count -eq 0){$ActualStatus = "NotAFinding"}
                elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){$ActualStatus = "Open";$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Orphaned SIDs found in the ACL."}
                else{
                    foreach($account in $accounts){
                        if($account.split('.')[-1] -notin $Adminlevelcodes){$ActualStatus = "Open"}
                        }
                    }
                }
        
            #V-93195
            #Windows Server 2019 STIG
            #Windows Server 2019 Event Viewer must be protected from unauthorized modification and deletion.
            "SV-103283r1_rule" { 
                #Checks that trusted installer is the only one with modify or full control
                $FSR=@(
                'FullControl',
                '268435456',
                'Modify',
                '-536805376')
                
                $IR=@('NT SERVICE\TrustedInstaller')

                $eventvwrAcl =(Get-Acl C:\Windows\System32\eventvwr.exe).Access
                if($eventvwrAcl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }
            
            #V-93197
            #Windows Server 2019 STIG
            #Windows Server 2019 Manage auditing and security log user right must only be assigned to the Administrators group.
            "SV-103285r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment 
                #"Manage auditing and security log" to only include the following accounts or groups:
                #Administrators 
                #Auditors groups is allowed
                #Applications can have this right, but only with documentation
                if($ServerRole -eq 2){
                    $value=($UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList) -join ","
                    if($DomainName -eq "AREA52"){if ($Value -eq "Administrators,AFNOAPPS\Exchange Servers,AREA52\Exchange Enterprise Servers,LOCAL SERVICE") {$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"}}
                    elseif($DomainName -eq "AFNOAPPS"){if ($Value -eq "Administrators,AFNOAPPS\Exchange Servers") {$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"}}
                    elseif($DomainName -eq "ACC"){if ($Value -eq "ACC\Exchange Enterprise Servers,ACCROOT\Exchange Servers,Administrators") {$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"}}
                    elseif($DomainName -eq "AFMC" -or "ACCROOT"){if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"}}

                    if($ActualStatus -eq "NotAFinding"){$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
                    }
                else{
                    $value=$UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList
                    if ($Value -eq "Administrators") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }       
            
            #V-93199
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent users from changing installation options.
            "SV-103287r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Allow user control over installs" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "EnableUserControl"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93201
            #Windows Server 2019 STIG
            #Windows Server 2019 must disable the Windows Installer Always install with elevated privileges option.
            "SV-103289r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Always install with elevated privileges" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "AlwaysInstallElevated"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
            
            #V-93203
            #Windows Server 2019 STIG
            #Windows Server 2019 system files must be monitored for unauthorized changes.
            "SV-103291r1_rule" { 
                if($installedprograms.displayname -contains "McAfee Agent"){$ActualStatus = "NotAFinding"}
                }            
            
            #V-93205
            #Windows Server 2019 STIG
            #Windows Server 2019 administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.
            "SV-103293r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Admin accounts when are automatically added to the BC_CAT_VI group by script which prevents internet access through the proxy."}
                       
            #V-93207
            #Windows Server 2019 STIG
            #Windows Server 2019 members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.
            "SV-103295r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}            
            
            #V-93209
            #Windows Server 2019 STIG
            #Windows Server 2019 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.
            "SV-103297r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "IAW AFMAN 17-1301 para 8.21.3, the ISSM ensures the service account passwords are changed as required. Also, IAW AFMAN 17-1301 para 8.5.4.3, passwords are changed at least every 60 days or more frequiently as determined by the ISO, IAW CJCSI 6510.01."}
            
            #V-93211
            #Windows Server 2019 STIG
            #The password for the krbtgt account on a domain must be reset at least every 180 days.
            "SV-103299r3_rule" { 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $OldDate = (Get-Date).AddDays(-180)
                    $krbtgtSet = Get-ADUser krbtgt -Property PasswordLastSet | select -ExpandProperty PasswordLastSet
                    if ($krbtgtSet -gt $OldDate) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The password was last set $krbtgtSet"}
                    }
                }

            #V-93213
            #Windows Server 2019 STIG
            #Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
            "SV-103301r1_rule" { 
                if((get-tpm).tpmready){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-93215
            #Windows Server 2019 STIG
            #Windows Server 2019 must be maintained at a supported servicing level.
            "SV-103303r1_rule" { 
                if ((Get-WmiObject -Class win32_operatingsystem).buildnumber -ge 17763) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93217
            #Windows Server 2019 STIG
            #Windows Server 2019 must use an anti-virus program.
            "SV-103305r1_rule" { 
                if ($installedprograms.displayname -contains "mcafee agent") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93219
            #Windows Server 2019 STIG
            #Windows Server 2019 must have a host-based intrusion detection or prevention system.
            "SV-103307r1_rule" { 
                if ($installedprograms.displayname -contains "McAfee Host Intrusion Prevention") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93221
            #Windows Server 2019 STIG
            #Windows Server 2019 must have software certificate installation files removed.
            "SV-103309r2_rule" { 
                if ($softcerts.count -eq 0) {$ActualStatus = "NotAFinding"}
                else {
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following files caused this to be a finding: $softcerts"
                    }
                }

            #V-93223
            #Windows Server 2019 STIG
            #Windows Server 2019 FTP servers must be configured to prevent anonymous logons.
            "SV-103311r1_rule" { 
                if($installedFeatures.name -notcontains "web-ftp-server"){$ActualStatus = "Not_Applicable"}
                else {$ManuallyVerify += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]}
                }

            #V-93225
            #Windows Server 2019 STIG
            #Windows Server 2019 FTP servers must be configured to prevent access to the system drive.
            "SV-103313r1_rule" { 
                if($installedFeatures.name -notcontains "web-ftp-server"){$ActualStatus = "Not_Applicable"}
                else {$ManuallyVerify += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]}
                }

            #V-93227
            #Windows Server 2019 STIG
            #Windows Server 2019 must have orphaned security identifiers (SIDs) removed from user rights.
            "SV-103315r1_rule" { 
                if($UserRights.Accountlist -match "S-\d-\d+-(\d+-){1,14}\d+"){
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93229
            #Windows Server 2019 STIG
            #Windows Server 2019 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
            "SV-103317r1_rule" { 
                try{Confirm-SecureBootUEFI -ErrorAction Stop | Out-Null
                $ActualStatus = "NotAFinding"}
                catch{$ActualStatus = "Open"}
                }

            #V-93231
            #Windows Server 2019 STIG
            #Windows Server 2019 must have Secure Boot enabled.
            "SV-103319r1_rule" { 
                try{Confirm-SecureBootUEFI -ErrorAction Stop | Out-Null
                $ActualStatus = "NotAFinding"}
                catch{$ActualStatus = "Open"}
                }

            #V-93233
            #Windows Server 2019 STIG
            #Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
            "SV-103321r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\" "DisableIpSourceRouting"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93235
            #Windows Server 2019 STIG
            #Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
            "SV-103323r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "DisableIPSourceRouting"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93237
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.
            "SV-103325r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnableICMPRedirect"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93239
            #Windows Server 2019 STIG
            #Windows Server 2019 insecure logons to an SMB server must be disabled.
            "SV-103327r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" "AllowInsecureGuestAuth"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93241
            #Windows Server 2019 STIG
            #Windows Server 2019 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
            "SV-103329r1_rule" { 
                $Value1 = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" "\\*\NETLOGON"
                $Value2 = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" "\\*\SYSVOL"
                if ($Value1 -eq "RequireMutualAuthentication=1,RequireIntegrity=1" -and $value2 -eq "RequireMutualAuthentication=1,RequireIntegrity=1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93243
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials.
            "SV-103331r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" "AllowProtectedCreds"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93245
            #Windows Server 2019 STIG
            #Windows Server 2019 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.
            "SV-103333r1_rule" { 
                $check=@()
                $deviceguard=gwmi -Class win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
                if($deviceguard.RequiredSecurityProperties -notcontains 2){$check+=$false}
                if($deviceguard.RequiredSecurityProperties -notcontains 3){$check+=$false}
                if($deviceguard.VirtualizationBasedSecurityStatus -ne 2){$check+=$false}
                if($check -contains $false){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93249
            #Windows Server 2019 STIG
            #Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.
            "SV-103337r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware
                #"Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected. 
                if(Get-ItemProperty -Name DriverLoadPolicy -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" "DriverLoadPolicy"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93251
            #Windows Server 2019 STIG
            #Windows Server 2019 group policy objects must be reprocessed even if they have not changed.
            "SV-103339r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Group Policy
                #"Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" "NoGPOListChanges"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93253
            #Windows Server 2019 STIG
            #Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery).
            "SV-103341r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
                #"Require a password when a computer wakes (on battery)" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "DCSettingIndex"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93255
            #Windows Server 2019 STIG
            #Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (plugged in).
            "SV-103343r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
                #"Require a password when a computer wakes (plugged in)" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "ACSettingIndex"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93257
            #Windows Server 2019 STIG
            #Windows Server 2019 Telemetry must be configured to Security or Basic.
            "SV-103345r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" "AllowTelemetry"
                if ($Value -eq "0" -or $Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}

                }

            #V-93259
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Update must not obtain updates from other PCs on the Internet.
            "SV-103347r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" "DODownloadMode"
                if ($Value -eq "3") {$ActualStatus = "Open"}
                else {$ActualStatus = "NotAFinding"}
                }

            #V-93261
            #Windows Server 2019 STIG
            #Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled.
            "SV-103349r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off heap termination on corruption" to "Disabled". 
                if(Get-ItemProperty -Name NoHeapTerminationOnCorruption -Path HKLM:\Software\Policies\Microsoft\Windows\Explorer -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoHeapTerminationOnCorruption"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93263
            #Windows Server 2019 STIG
            #Windows Server 2019 File Explorer shell protocol must run in protected mode.
            "SV-103351r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off shell protocol protected mode" to "Disabled". 
                if(Get-ItemProperty -Name PreXPSP2ShellProtocolBehavior -Path HKLM:\Software\Policies\Microsoft\Windows\Explorer -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "PreXPSP2ShellProtocolBehavior"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93265
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent attachments from being downloaded from RSS feeds.
            "SV-103353r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
                #"Prevent downloading of enclosures" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "DisableEnclosureDownload"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93267
            #Windows Server 2019 STIG
            #Windows Server 2019 users must be notified if a web-based program attempts to install software.
            "SV-103355r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
                #"Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled". 
                if(Get-ItemProperty -Name SafeForScripting -Path HKLM:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "SafeForScripting"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93269
            #Windows Server 2019 STIG
            #Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart.
            "SV-103357r1_rule" { 
                #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options
                #"Sign-in last interactive user automatically after a system-initiated restart" to "Disabled". 
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableAutomaticRestartSignOn"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }

            #V-93271
            #Windows Server 2019 STIG
            #Windows Server 2019 directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.
            "SV-103359r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Anonymous access is not allowed to the AD domain naming context."}
                    }

            #V-93273
            #Windows Server 2019 STIG
            #Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords.
            "SV-103361r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain controller: Refuse machine account password changes" to "Disabled". 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RefusePasswordChange"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93275
            #Windows Server 2019 STIG
            #Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers.
            "SV-103363r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "4" logons or less. 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "CachedLogonsCount"
                    if ($Value -le 4) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93277
            #Windows Server 2019 STIG
            #Windows Server 2019 must be running Credential Guard on domain-joined member servers.
            "SV-103365r1_rule" { 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $deviceguard=gwmi -Class win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
                    if($deviceguard.SecurityServicesRunning -notcontains 1){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93279
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent local accounts with blank passwords from being used from the network.
            "SV-103367r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Limit local account use of blank passwords to console logon only" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93281
            #Windows Server 2019 STIG
            #Windows Server 2019 built-in administrator account must be renamed.
            "SV-103369r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Rename administrator account" to a name other than "Administrator". 
                if(($Admin).Name -eq "Administrator"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93283
            #Windows Server 2019 STIG
            #Windows Server 2019 built-in guest account must be renamed.
            "SV-103371r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Rename guest account" to a name other than "Guest".
                if(($Guest).Name -eq "Guest"){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93285
            #Windows Server 2019 STIG
            #Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less.
            "SV-103373r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "MaximumPasswordAge"
                if ($Value -gt 0 -and $value -le 30) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93287
            #Windows Server 2019 STIG
            #Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation.
            "SV-103375r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Interactive logon: Smart card removal behavior" to "Lock Workstation" or "Force Logoff". 
                #Documentable Explanation: This can be left not configured or set to “No action” on workstations with the following conditions. This will be documented with the IAO.
                #    •The setting can't be configured due to mission needs, interferes with applications.
                #    •Policy must be in place that users manually lock workstations when leaving them unattended.
                #    •Screen saver requirement is properly configured to lock as required in V0001122. 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "SCRemoveOption"
                if ($Value -eq "1" -or $Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93289
            #Windows Server 2019 STIG
            #Windows Server 2019 must not allow anonymous SID/Name translation.
            "SV-103377r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Allow anonymous SID/Name translation" to "Disabled".
                $value = $secsettings | Where-Object {$_.KeyName -eq "LSAAnonymousNameLookup"} | select -ExpandProperty Setting
                if ($Value -eq $false) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93291
            #Windows Server 2019 STIG
            #Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.
            "SV-103379r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictAnonymousSAM"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93293
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group.
            "SV-103381r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options 
                #"Network access: Let everyone permissions apply to anonymous users" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93295
            #Windows Server 2019 STIG
            #Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.
            "SV-103383r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow Local System to use computer identity for NTLM" to "Enabled".
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\" "UseMachineId"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
            
            #V-93297
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent NTLM from falling back to a Null session.
            "SV-103385r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow LocalSystem NULL session fallback" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\MSV1_0\" "allownullsessionfallback"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }            

            #V-93299
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent PKU2U authentication using online identities.
            "SV-103387r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" "AllowOnlineID"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93301
            #Windows Server 2019 STIG
            #Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.
            "SV-103389r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "LmCompatibilityLevel"
                if ($Value -eq "5") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93303
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing.
            "SV-103391r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum. 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LDAP\" "LDAPClientIntegrity"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93305
            #Windows Server 2019 STIG
            #Windows Server 2019 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.
            "SV-103393r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinClientSec"
                if ($Value -eq "537395200") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93307
            #Windows Server 2019 STIG
            #Windows Server 2019 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.
            "SV-103395r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinServerSec"
                if ($Value -eq "537395200") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93309
            #Windows Server 2019 STIG
            #Windows Server 2019 default permissions of global system objects must be strengthened.
            "SV-103397r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Store passwords using reversible encryption" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93311
            #Windows Server 2019 STIG
            #Windows Server 2019 must preserve zone information when saving attachments.
            "SV-103399r1_rule" { 
                if(Get-ItemProperty -Name SaveZoneInformation -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "SaveZoneInformation"
                    if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93313
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on.
            "SV-103401r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    if($SysProcessMitigation.Dep.Enable -eq "OFF"){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93315
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection system-level mitigation, Control flow guard (CFG), must be on.
            "SV-103403r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    if($SysProcessMitigation.Cfg.Enable -eq "OFF"){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93317
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection system-level mitigation, Validate exception chains (SEHOP), must be on.
            "SV-103405r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    if($SysProcessMitigation.SEHOP.Enable -eq "OFF"){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93319
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection system-level mitigation, Validate heap integrity, must be on.
            "SV-103407r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    if($SysProcessMitigation.Heap.TerminateOnError -eq "OFF"){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93321
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for Acrobat.exe.
            "SV-103409r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "Acrobat.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93323
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for AcroRd32.exe.
            "SV-103411r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "AcroRd32.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93325
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for chrome.exe.
            "SV-103413r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "chrome.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93327
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for EXCEL.EXE.
            "SV-103415r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "EXCEL.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93329
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for firefox.exe.
            "SV-103417r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "firefox.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93331
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for FLTLDR.EXE.
            "SV-103419r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "FLTLDR.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93333
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for GROOVE.EXE.
            "SV-103421r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "GROOVE.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93335
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for iexplore.exe.
            "SV-103423r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "iexplore.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93337
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for INFOPATH.EXE.
            "SV-103425r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "INFOPATH.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93339
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for java.exe, javaw.exe, and javaws.exe.
            "SV-103427r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    if($ProcessMitigationList -contains "java.exe"){
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQQ "java.exe").ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "java.exe").Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    if($ProcessMitigationList -contains "javaw.exe"){
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaw.exe").Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    if($ProcessMitigationList -contains "javaws.exe"){
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ "javaws.exe").Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    if($ProcessMitigationList -notcontains "java.exe" -and "javaw.exe" -and "javaws.exe"){$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93341
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for lync.exe.
            "SV-103429r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "lync.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93343
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for MSACCESS.EXE.
            "SV-103431r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "MSACCESS.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93345
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for MSPUB.EXE.
            "SV-103433r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "MSPUB.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93347
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for OIS.EXE.
            "SV-103435r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "OIS.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93349
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for OneDrive.exe.
            "SV-103437r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "OneDrive.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93351
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for OUTLOOK.EXE.
            "SV-103439r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "OUTLOOK.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93353
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for plugin-container.exe.
            "SV-103441r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "plugin-container.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93355
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for POWERPNT.EXE.
            "SV-103443r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "POWERPNT.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93357
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for PPTVIEW.EXE.
            "SV-103445r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "PPTVIEW.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93359
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for VISIO.EXE.
            "SV-103447r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "VISIO.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93361
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for VPREVIEW.EXE.
            "SV-103449r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "VPREVIEW.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93363
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for WINWORD.EXE.
            "SV-103451r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "WINWORD.EXE"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93365
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for wmplayer.exe.
            "SV-103453r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "wmplayer.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93367
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection mitigations must be configured for wordpad.exe.
            "SV-103455r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $ProcessName = "wordpad.exe"
                    if($ProcessMitigationList -contains $ProcessName){
                        $ActualStatus = "NotAFinding"
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON"){$ActualStatus = "Open"}
                        if(($ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON"){$ActualStatus = "Open"}
                        }
                    else{$ActualStatus = "Not_Applicable"}
                    }
                }

            #V-93369
            #Windows Server 2019 STIG
            #Windows Server 2019 users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.
            "SV-103457r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "In accordance to AFMAN 17-1301 para 4.2.2.6, everyone with administrative privileges has a separate account for user duties and one for privileged duties."}
 
            #V-93373
            #Windows Server 2019 STIG
            #Windows Server 2019 Autoplay must be turned off for non-volume devices.
            "SV-103459r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
                #"Disallow Autoplay for non-volume devices" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoAutoplayfornonVolume"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93375
            #Windows Server 2019 STIG
            #Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands.
            "SV-103461r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
                #"Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoAutorun"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93377
            #Windows Server 2019 STIG
            #Windows Server 2019 AutoPlay must be disabled for all drives.
            "SV-103463r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies 
                #"Turn off AutoPlay" to "Enabled:All Drives". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" "NoDriveTypeAutoRun"
                if ($Value -eq "255") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93379
            #Windows Server 2019 STIG
            #Windows Server 2019 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
            "SV-103465r1_rule" { 
                #Manual review required, even if AppLocker is used
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}}

            #V-93381
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the roles and features required by the system documented.
            "SV-103467r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}

            #V-93383
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have the Fax Server role installed.
            "SV-103469r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "Fax"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93385
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have the Peer Name Resolution Protocol installed.
            "SV-103471r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "PNRP"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93387
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have Simple TCP/IP Services installed.
            "SV-103473r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "Simple-TCPIP"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93389
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have the TFTP Client installed.
            "SV-103475r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "TFTP-Client"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93391
            #Windows Server 2019 STIG
            #Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed.
            "SV-103477r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "FS-SMB1"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93393
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.
            "SV-103479r1_rule" { 
                #if 73523 and 73519 are configured this is not a finding. No way to guarantee they go before this so I'll just check twice.
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93395
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.
            "SV-103481r1_rule" { 
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Configure SMBv1 client (extra setting needed for pre-Win8.1/2012R2)" to "Enabled" with the following three lines of text entered for "Configure LanmanWorkstation Dependencies":
                #Bowser
                #MRxSmb20
                #NSI
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
                if ($Value -eq "4") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93397
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have Windows PowerShell 2.0 installed.
            "SV-103483r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "PowerShell-v2"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93399
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent the display of slide shows on the lock screen.
            "SV-103485r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Control Panel -> Personalization
                #"Prevent enabling lock screen slide show" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\" "NoLockScreenSlideshow"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93401
            #Windows Server 2019 STIG
            #Windows Server 2019 must have WDigest Authentication disabled.
            "SV-103487r1_rule" { 
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"WDigest Authentication (disabling may require KB2871997)" to "Disabled".
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" "UseLogonCredential"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93403
            #Windows Server 2019 STIG
            #Windows Server 2019 downloading print driver packages over HTTP must be turned off.
            "SV-103489r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off downloading of print drivers over HTTP" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableWebPnPDownload"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93405
            #Windows Server 2019 STIG
            #Windows Server 2019 printing over HTTP must be turned off.
            "SV-103491r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
                #"Turn off printing over HTTP" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableHTTPPrinting"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93407
            #Windows Server 2019 STIG
            #Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen.
            "SV-103493r1_rule" { 
                #Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "DontDisplayNetworkSelectionUI"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93409
            #Windows Server 2019 STIG
            #Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
            "SV-103495r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility
                #"Turn off Inventory Collector" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" "DisableInventory"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93411
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Defender SmartScreen must be enabled.
            "SV-103497r2_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "EnableSmartScreen"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93413
            #Windows Server 2019 STIG
            #Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP.
            "SV-103499r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
                #"Turn on Basic feed authentication over HTTP" to "Disabled". 
                if(Get-ItemProperty -Name AllowBasicAuthInClear -Path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds' -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "AllowBasicAuthInClear"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93415
            #Windows Server 2019 STIG
            #Windows Server 2019 must prevent Indexing of encrypted files.
            "SV-103501r1_rule" { 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" "AllowIndexingEncryptedStoresOrItems"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93417
            #Windows Server 2019 STIG
            #Windows Server 2019 domain controllers must run on a machine dedicated to that function.
            "SV-103503r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "No other application-related components are listed in services."}
                    }

            #V-93419
            #Windows Server 2019 STIG
            #Windows Server 2019 local users on domain-joined member servers must not be enumerated.
            "SV-103505r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Logon
                #"Enumerate local users on domain-joined computers" to "Disabled". 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "EnumerateLocalUsers"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93421
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization.
            "SV-103507r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "Web-Ftp-Service"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93423
            #Windows Server 2019 STIG
            #Windows Server 2019 must not have the Telnet Client installed.
            "SV-103509r1_rule" { 
                #If the Web-DAV-Publishing role is not installed this is not a finding
                if($installedFeatures.name -notcontains "Telnet-Client"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Not_Reviewed"}
                }

            #V-93425
            #Windows Server 2019 STIG
            #Windows Server 2019 must not save passwords in the Remote Desktop Client.
            "SV-103511r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client
                #"Do not allow passwords to be saved" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "DisablePasswordSaving"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93427
            #Windows Server 2019 STIG
            #Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection.
            "SV-103513r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security 
                #"Always prompt for password upon connection" to "Enabled". 
                $Value = Check-RegKeyValue "hklm\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93429
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials.
            "SV-103515r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Disallow WinRM from storing RunAs credentials" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "DisableRunAs"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93431
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled.
            "SV-103517r1_rule" { 
                #Not Applicable if Server Core
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "FilterAdministratorToken"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93433
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control must automatically deny standard user requests for elevation.
            "SV-103519r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorUser"
                    if ($Value -eq 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93435
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
            "SV-103521r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Run all administrators in Admin Approval Mode" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableLUA"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93437
            #Windows Server 2019 STIG
            #Windows Server 2019 shared user accounts must not be permitted.
            "SV-103523r1_rule" { 
                #Not checkable via script
                $ActualStatus = "Not_Applicable"}

            #V-93439
            #Windows Server 2019 STIG
            #Windows Server 2019 accounts must require passwords.
            "SV-103525r2_rule" { 
                if($ServerRole -eq 2){
                    $V93439=$users | where {$_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true}
                    if($V93439.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following accounts were found: `n$V93439"}
                }
                else{
                    $nopwd = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount
                    if($nopwd.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus -ne "Open"}
                    }
                }

            #V-93441
            #Windows Server 2019 STIG
            #Windows Server 2019 Active Directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), Personal Identity Verification (PIV)-compliant hardware token, or Alternate Logon Token (ALT) for user authentication.
            "SV-103527r1_rule" { 
                #Can't be checked
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}

            #V-93443
            #Windows Server 2019 STIG
            #Windows Server 2019 Kerberos user logon restrictions must be enforced.
            "SV-103529r1_rule" { 
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Enforce user logon restrictions" to "Enabled".
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $secsettings | Where-Object {$_.KeyName -eq "TicketValidateClient"} | select -ExpandProperty Setting
                    if ($Value -eq $true) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93445
            #Windows Server 2019 STIG
            #Windows Server 2019 Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.
            "SV-103531r1_rule" { 
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for service ticket" to a maximum of 600 minutes, but not 0 which equates to "Ticket doesn't expire". 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $secsettings | Where-Object {$_.KeyName -eq "MaxServiceAge"} | select -ExpandProperty Setting
                    if ($value -le "600"-and $value -gt 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93447
            #Windows Server 2019 STIG
            #Windows Server 2019 Kerberos user ticket lifetime must be limited to 10 hours or less.
            "SV-103533r1_rule" { 
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for user ticket" to a maximum of 10 hours, but not 0 which equates to "Ticket doesn't expire".
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $secsettings | Where-Object {$_.KeyName -eq "MaxTicketAge"} | select -ExpandProperty Setting
                    if ($value -le "10"-and $value -gt 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93449
            #Windows Server 2019 STIG
            #Windows Server 2019 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.
            "SV-103535r1_rule" { 
                #Default Domain Policy
                #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum lifetime for user ticket renewal" to a maximum of 7 days or less. 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $secsettings | Where-Object {$_.KeyName -eq "MaxRenewAge"} | select -ExpandProperty Setting
                    if ($value -le "7") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93451
            #Windows Server 2019 STIG
            #Windows Server 2019 computer clock synchronization tolerance must be limited to five minutes or less.
            "SV-103537r1_rule" { 
                #Default Domain Policy
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
                #"Maximum tolerance for computer clock synchronization" to a maximum of 5 minutes or less.
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $value = $secsettings | Where-Object {$_.KeyName -eq "MaxClockSkew"} | select -ExpandProperty Setting
                    if ($value -le "5") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93453
            #Windows Server 2019 STIG
            #Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems.
            "SV-103539r1_rule" { 
                #Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call
                #"Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated". 
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" "RestrictRemoteClients"
                    if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93455
            #Windows Server 2019 STIG
            #Windows Server 2019 computer account password must not be prevented from being reset.
            "SV-103541r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Disable machine account password changes" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "DisablePasswordChange"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93457
            #Windows Server 2019 STIG
            #Windows Server 2019 outdated or unused accounts must be removed or disabled.
            "SV-103543r1_rule" {  
                #Can't be checked
                if($ServerRole -eq 2){
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "AFMAN 17-1301 para 4.6.1 lists the ISSM/ISSO's responsability for disabling accounts."}
                else{
                    if((Get-LocalUser).enabled -contains $true){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93459
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the built-in Windows password complexity policy enabled.
            "SV-103545r1_rule" { 
                #Computer Configuration >> Windows Settings -> Security Settings >> Account Policies >> Password Policy 
                #"Password must meet complexity requirements" to "Enabled". 
                if($passwordpolicy.ComplexityEnabled -eq $true){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93461
            #Windows Server 2019 STIG
            #Windows Server 2019 manually managed application account passwords must be at least 15 characters in length.
            "SV-103547r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "IAW AFMAN 17-1301 para 8.21.3, the ISSM ensures the service account passwords are changed as required. Also, IAW AFMAN 17-1301 para 8.5.4.3, passwords are changed at least every 60 days or more frequiently as determined by the ISO, IAW CJCSI 6510.01."}

            #V-93463
            #Windows Server 2019 STIG
            #Windows Server 2019 minimum password length must be configured to 14 characters.
            "SV-103549r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Minimum password length" to "14" characters. 
                #This is set in default domain policy
                if($passwordpolicy.MinPasswordLength -eq 14){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93465
            #Windows Server 2019 STIG
            #Windows Server 2019 reversible password encryption must be disabled.
            "SV-103551r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Store passwords using reversible encryption" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93467
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to prevent the storage of the LAN Manager hash of passwords.
            "SV-103553r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network security: Do not store LAN Manager hash value on next password change" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "NoLMHash"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93469
            #Windows Server 2019 STIG
            #Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.
            "SV-103555r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled". 
                $Value = Check-RegKeyValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93471
            #Windows Server 2019 STIG
            #Windows Server 2019 minimum password age must be configured to at least one day.
            "SV-103557r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Minimum password age" to at least "1" day. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.MinPasswordAge -ge [timespan]"1.00:00"){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93473
            #Windows Server 2019 STIG
            #Windows Server 2019 passwords for the built-in Administrator account must be changed at least every 60 days.
            "SV-103559r1_rule" { 
                #Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet
                if($ServerRole -eq 3){
                    if($Admin.PasswordLastSet -gt (Get-Date).AddYears(-1)){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should change the local admin password."}
                    }
                elseif($ServerRole -eq 2){
                    if($Admin.PasswordLastSet -gt (get-date).AddYears(-1)) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The password was last set: $($Admin.PasswordLastSet)"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                }

            #V-93475
            #Windows Server 2019 STIG
            #Windows Server 2019 passwords must be configured to expire.
            "SV-103561r1_rule" { 
                if($ServerRole -eq 2){
                    $V93475=$users | where {$_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true -and $_.smartcardlogonrequired -eq $false -and $_.distinguishedname -notlike "*Service Account*"}
                    if($V93475.count -eq 0){$ActualStatus = "NotAFinding"}
                    else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following accounts were found: `n$V93475"}
                    }
                else{
                    if(((Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' and PasswordExpires='False'").Name).count -eq 0) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                }

            #V-93477
            #Windows Server 2019 STIG
            #Windows Server 2019 maximum password age must be configured to 60 days or less.
            "SV-103563r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
                #"Maximum password age" to "60" days or less (excluding "0" which is unacceptable). 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.MaxPasswordAge -le [timespan]"60.00:00:00" -and $passwordpolicy.MaxPasswordAge -gt [timespan]0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93479
            #Windows Server 2019 STIG
            #Windows Server 2019 password history must be configured to 24 passwords remembered.
            "SV-103565r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy
                #"Enforce password history" to "24" passwords remembered. 
                #This is set in the default domain policy, but the STIG says to check locally.
                if($passwordpolicy.PasswordHistoryCount -ge 24){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93481
            #Windows Server 2019 STIG
            #Windows Server 2019 domain controllers must have a PKI server certificate.
            "SV-103567r1_rule" { 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if ((Get-ChildItem Cert:\LocalMachine\my) -ne $null) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93483
            #Windows Server 2019 STIG
            #Windows Server 2019 domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA).
            "SV-103569r1_rule" { 
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $cert = Get-ChildItem Cert:\Localmachine\My
                    $issuer = $cert.Issuer.split(",")[0].Split("=")[1]
                    #Our list of trusted CA
                    $DoDorECA = @"
AFNOAPPS LTMA CA-1
AFNOAPPS LTMA CA-2
NSS SW CA-2
NSS SW CA-4
NSS SW-CA-4
"@.Split("`n") | foreach {$_.trim()}
                    if ($DoDorECA -contains $issuer) {$ActualStatus = "NotAFinding"}
                    else {
                        #Prompt user to see if we trust it.  If we do, add it to the script
                        $title = "Trusted CA?"
                        $message = "Is $issuer a trusted DoD CA or ECA?"
                        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
                        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"
                        $options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
                        $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                        if ($result -eq 1) {
                            [System.Collections.ArrayList]$SelfScript = Get-Content $MyInvocation.MyCommand.Definition
                            for ($i = 0;$i -lt $SelfScript.count -and $SelfScript[$i] -notlike "*DoDorECA = @*";$i++) {;}
                            $SelfScript.Insert($i + 1,$issuer)
                            Out-File -InputObject $SelfScript -Encoding default -LiteralPath $MyInvocation.MyCommand.Definition
                            $ActualStatus = "NotAFinding"
                            }
                        else {$ActualStatus = "Open"}
                        }
                    }
                }
            
            #V-93485
            #Windows Server 2019 STIG
            #Windows Server 2019 PKI certificates associated with user accounts must be issued by a DoD PKI or an approved External Certificate Authority (ECA).
            "SV-103571r1_rule" { 
                #This requires manual validation
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "You cannot run this on the domain, it will time out. TO 00-33D-2001 provides guidance on the USAF UPN requirements."
                    $ActualStatus = "NotAFinding"}
                }

            #V-93487
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.
            "SV-103573r1_rule" { 
                Remove-Variable certs,HasDodRoot2,HasDodRoot3,HasDodRoot4,HasDodRoot5 -EA SilentlyContinue
                $certs = Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*"
                $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" -and $_.NotAfter -gt $currDate}
                $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "D73CA91102A2204A36459ED32213B467D7CE97FB" -and $_.NotAfter -gt $currDate}
                $HasDodRoot4 = $certs | Where {$_.subject -eq "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "B8269F25DBD937ECAFD4C35A9838571723F2D026" -and $_.NotAfter -gt $currDate}
                $HasDodRoot5 = $certs | Where {$_.subject -eq "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "4ECB5CC3095670454DA1CBD410FC921F46B8564B" -and $_.NotAfter -gt $currDate}
                if ($HasDodRoot2 -and $HasDodRoot3 -and $HasDodRoot4 -and $HasDodRoot5) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should run DOD Install Root and re-verify"}
                }

            #V-93489
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.
            "SV-103575r1_rule" { 
                if ($IsNIPR) {
                    Remove-Variable certs,ExpCert,HasDodRoot2,HasDodRoot3 -EA SilentlyContinue
                    $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}
                    $ExpCert = $certs | Where {$_.NotAfter -lt $currDate}
                    $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "22BBE981F0694D246CC1472ED2B021DC8540A22F"}
                    $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "AC06108CA348CC03B53795C64BF84403C1DBD341"}
                    if ($ExpCert -and $HasDodRoot2 -and $HasDodRoot3) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should run DOD Install Root and re-verify"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-93491
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.
            "SV-103577r1_rule" { 
                if ($IsNIPR) {
                    Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
                    $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*CCEB Interoperability*"}
                    $ExpCert = $certs | Where {$_.NotAfter -lt $currDate}
                    $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "929BF3196896994C0A201DF4A5B71F603FEFBF2E"}
                    if ($ExpCert -and $HasDodRoot3) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Technician should run DOD Install Root and re-verify"}
                    }
                else {$ActualStatus = "Not_Applicable"}
                }

            #V-93493
            #Windows Server 2019 STIG
            #Windows Server 2019 users must be required to enter a password to access private keys stored on the computer.
            "SV-103579r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\" "ForceKeyProtection"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93495
            #Windows Server 2019 STIG
            #Windows Server 2019 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
            "SV-103581r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Network security: Configure encryption types allowed for Kerberos" is configured, only the following selections are allowed:
                #AES128_HMAC_SHA1
                #AES256_HMAC_SHA1
                #Future encryption types 

                #This value is stored in bits.  The 1 bit is DES_CBC_CRC, the 2 bit is DES_CBC_MD5, the 4 bit is RC4_HMAC_MD5, the 8 bit is AES128_HMAC_SHA1, the 16 bit is AES256_HMAC_SHA1, and for "Future encryption types" they just turn on every other bit.
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes"
                #if (!($Value -band 1) -and !($value -band 2) -and !($value -band 4) -and $value -band 8 -and $value -band 16) {$ActualStatus = "NotAFinding"} #These checks make sure each bit flag is set properly.  I'm an idiot in trying to be smart by doing this complicated, because checking for every other bit is stupid
                if ($value -eq "2147483640") {$ActualStatus = "NotAFinding"}
                else {
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR + ". This finding is covered by the USAF STIG Deviation Memo."}
                }

            #V-93497
            #Windows Server 2019 STIG
            #Windows Server 2019 must have the built-in guest account disabled.
            "SV-103583r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Accounts: Guest account status" to "Disabled".
                if(($Guest).Enabled -eq $false){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-93499
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic.
            "SV-103585r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Allow unencrypted traffic" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowUnencryptedTraffic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93501
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic.
            "SV-103587r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Disallow WinRM from storing RunAs credentials" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "DisableRunAs"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93503
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication.
            "SV-103589r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Allow Basic authentication" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowBasic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93505
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication.
            "SV-103591r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
                #"Disallow Digest authentication" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowDigest"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93507
            #Windows Server 2019 STIG
            #Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication.
            "SV-103593r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
                #"Allow Basic authentication" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "AllowBasic"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93509
            #Windows Server 2019 STIG
            #Windows Server 2019 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.
            "SV-103595r1_rule" { 
                #I figured it out - Calabrese
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    if($IsNIPR){$LDAPAdminLimits=dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,DC=AFNOAPPS,DC=USAF,DC=MIL" -attr LDAPAdminLimits}
                    elseif($DomainName -like "ACC*"){$LDAPAdminLimits=dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,DC=ACCROOT,DC=DS,DC=AF,DC=SMIL,DC=MIL" -attr LDAPAdminLimits}
                    elseif($DomainName -match "AFMC"){$LDAPAdminLimits=dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,cn=Configuration,DC=AFMC,DC=DS,DC=AF,DC=SMIL,DC=MIL" -attr LDAPAdminLimits}
                    $MaxConnIdleTime=($LDAPAdminLimits.Split(";") | Select-String -Pattern MaxConnIdleTime).ToString().TrimStart(" MaxConnIdleTime=")
                    if([int]$MaxConnIdleTime -le 300){$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "This is set to $MaxConnIdleTime"}
                    }
                }

            #V-93511
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
            "SV-103597r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" "Enabled"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93513
            #Windows Server 2019 STIG
            #Windows Server 2019 must use separate, NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.
            "SV-103599r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93515
            #Windows Server 2019 STIG
            #Windows Server 2019 systems requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
            "SV-103601r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "All systems that we manage have adequate physical protection across the Air Force."}

            #V-93517
            #Windows Server 2019 STIG
            #Windows Server 2019 administrator accounts must not be enumerated during elevation.
            "SV-103603r1_rule" { 
                #Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface
                #"Enumerate administrator accounts on elevation" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" "EnumerateAdministrators"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93519
            #Windows Server 2019 STIG
            #Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers.
            "SV-103605r1_rule" { 
                #Computer Configuration >> Administrative Templates >> MS Security Guide
                #"Apply UAC restrictions to local accounts on network logons" to "Enabled".
                if($ServerRole -eq 2){$ActualStatus = "Not_Applicable"}
                else{
                    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LocalAccountTokenFilterPolicy"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }
                
            #V-93521
            #Windows Server 2019 STIG
            #Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.
            "SV-103607r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableUIADesktopToggle"
                if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93523
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.
            "SV-103609r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".
                #More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop). 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorAdmin"
                    if ($Value -le 4 -and $Value -gt 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93525
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation.
            "SV-103611r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Detect application installations and prompt for elevation" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableInstallerDetection"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93527
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations.
            "SV-103613r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableSecureUIAPaths"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93529
            #Windows Server 2019 STIG
            #Windows Server 2019 User Account Control (UAC) must virtualize file and registry write failures to per-user locations.
            "SV-103615r1_rule" { 
                #UAC requirements are NA on Server Core installations.
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled". 
                if ($IsServerCore) {$ActualStatus = "Not_Applicable"}
                else {
                    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableVirtualization"
                    if ($Value -eq 1) {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                }

            #V-93531
            #Windows Server 2019 STIG
            #Windows Server 2019 non-system-created file shares must limit access to groups that require it.
            "SV-103617r1_rule" { 
                #Check all non system shares to see if theres Everyone permission with allow.  If not, it's sure constrained permissions
                #Judgment call
                $ActualStatus = "NotAFinding"
                $badshares=@()
                if($ServerRole -eq 2){
                    $NonDefaultShares = Get-SmbShare | where {$_.name -ne "ADMIN$" -and $_.name -ne "C$" -and $_.name -ne "IPC$" -and $_.name -ne "D$" -and $_.name -ne "E$" -and $_.name -ne "F$" -and $_.name -ne "NETLOGON" -and $_.name -ne "SYSVOL"}
                    foreach ($share in $NonDefaultShares) {
                        $SharePerms = Get-SmbShareAccess $share.name
                        if ($SharePerms | where {$_.AccountName -match "Everyone" -and $_.AccessControlType -eq "Allow"}) {$ActualStatus = "Open"
                        $badshares += $share.path}
                        $NTFSPerms = (get-acl $share.path).Access
                        if ($SharePerms | where {$_.IdentityReference -match "Everyone" -and $_.AccessControlType -eq "Allow"}) {$ActualStatus = "Open"
                        $badshares += $share.path}
                        }
                    }
                else{
                $NonDefaultShares = Get-SmbShare | where {$_.name -ne "ADMIN$" -and $_.name -ne "C$" -and $_.name -ne "D$" -and $_.name -ne "E$" -and $_.name -ne "F$" -and $_.name -ne "IPC$" -and $_.name -ne "emie" -and $_.name -ne "logonscripts" -and $_.name -ne "scripts" -and $_.name -ne "startupscripts"}
                if($NonDefaultShares.count -gt 1){$ActualStatus = "Open"
                $badshares += $NonDefaultShares.name}
                }
                if ($ActualStatus -eq "Open") {$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following shares have been found: $badshares"}
                }

            #V-93533
            #Windows Server 2019 STIG
            #Windows Server 2019 Remote Desktop Services must prevent drive redirection.
            "SV-103619r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
                #"Do not allow drive redirection" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCdm"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93535
            #Windows Server 2019 STIG
            #Windows Server 2019 data files owned by users must be on a different logical partition from the directory server data files.
            "SV-103621r1_rule" { 
                #Can't be checked
                if($ServerRole -eq 3){$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not keep user shares on Domain Controllers."}
                    }

            #V-93537
            #Windows Server 2019 STIG
            #Windows Server 2019 must not allow anonymous enumeration of shares.
            "SV-103623r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "RestrictAnonymous"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93539
            #Windows Server 2019 STIG
            #Windows Server 2019 must restrict anonymous access to Named Pipes and Shares.
            "SV-103625r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "RestrictNullSessAccess"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93541
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers.
            "SV-103627r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" "NoNameReleaseOnDemand"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93543
            #Windows Server 2019 STIG
            #Windows Server 2019 must implement protection methods such as TLS, encrypted VPNs, or IPsec if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.
            "SV-103629r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Protection methods are configured."}

            #V-93545
            #Windows Server 2019 STIG
            #Windows Server 2019 domain controllers must require LDAP access signing.
            "SV-103631r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain controller: LDAP server signing requirements" to "Require signing". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\NTDS\Parameters\" "LDAPServerIntegrity"
                if ($Value -eq "2") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-93547
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.
            "SV-103633r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireSignOrSeal"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93549
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled.
            "SV-103635r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Domain member: Digitally encrypt secure channel data (when possible)" to "SealSecureChannel". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SealSecureChannel"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93551
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.
            "SV-103637r1_rule" { 
                #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
                #"Domain member: Digitally sign secure channel data (when possible)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SignSecureChannel"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93553
            #Windows Server 2019 STIG
            #Windows Server 2019 must be configured to require a strong session key.
            "SV-103639r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireStrongKey"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93555
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.
            "SV-103641r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network client: Digitally sign communications (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "RequireSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93557
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.
            "SV-103643r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters\" "EnableSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93559
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.
            "SV-103645r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Digitally sign communications (always)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "RequireSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93561
            #Windows Server 2019 STIG
            #Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.
            "SV-103647r1_rule" { 
                #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
                #"Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled". 
                $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableSecuritySignature"
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-93563
            #Windows Server 2019 STIG
            #Windows Server 2019 Explorer Data Execution Prevention must be enabled.
            "SV-103649r1_rule" { 
                #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
                #"Turn off Data Execution Prevention for Explorer" to "Disabled". 
                if(Get-ItemProperty -Name NoDataExecutionPrevention -Path 'HKLM:\Software\Policies\Microsoft\Internet Explorer' -ErrorAction SilentlyContinue){
                    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoDataExecutionPrevention"
                    if ($Value -eq "0") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                else{$ActualStatus = "NotAFinding"}
                }

            #V-93565
            #Windows Server 2019 STIG
            #Windows Server 2019 Exploit Protection system-level mitigation, Randomize memory allocations (Bottom-Up ASLR), must be on.
            "SV-103651r1_rule" { 
                if(!($IsNIPR)){$ActualStatus = "Not_Applicable"}
                else{
                    if($SysProcessMitigation.ASLR.BottomUp -eq "OFF"){$ActualStatus = "Open"}
                    else{$ActualStatus = "NotAFinding"}
                    }
                }

            #V-93567
            #Windows Server 2019 STIG
            #Windows Server 2019 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where Host Based Security System (HBSS) is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).
            "SV-103653r1_rule" { 
                if($installedprograms.displayname -contains "McAfee Agent"){$ActualStatus = "NotAFinding"}
                }

            #V-93571
            #Windows Server 2019 STIG
            #Windows Server 2019 must have a host-based firewall installed and enabled.
            "SV-103657r1_rule" { 
                if ($installedprograms.displayname -contains "McAfee Host Intrusion Prevention") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-95633
            #IIS 8.5 Server STIG
            #The IIS 8.5 MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
            "SV-104771r1_rule" { 
                if ((Get-WebConfiguration system.applicationHost/sites/sitedefaults/limits).maxConnections -gt 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-97527
            #Microsoft Internet Explorer 11 STIG
            #Internet Explorer Development Tools Must Be Disabled.
            "SV-106631r1_rule" {
                #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Toolbars
                #“Turn off Developer Tools” must be “Enabled”.
                $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools" -regValueName "Disabled" -EA SilentlyContinue
                if ($Value -eq "1") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000382927"}
                }

            #V-102619
            #Windows Server 2012/2012 R2 MS STIG
            #The Windows Explorer Preview pane must be disabled for Windows 2012.
            "SV-111569r1_rule" { 
                #checks reg keys
                $Value1 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoPreviewPane" -EA SilentlyContinue
                $Value2 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoReadingPane" -EA SilentlyContinue
                if ($Value1 -eq "1" -and $value2 -eq "1" ) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "This registry key is incorrectly configured."
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000385900"}
                }

            #V-102625
            #Windows Server 2019 STIG
            #The Windows Explorer Preview pane must be disabled for Windows Server 2019.
            "SV-111575r1_rule" { 
                #checks reg keys
                $Value1 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoPreviewPane" -EA SilentlyContinue
                $Value2 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoReadingPane" -EA SilentlyContinue
                if ($Value1 -eq "1" -and $value2 -eq "1" ) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "This registry key is incorrectly configured."
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $REQ + "REQ000000385900"}
                }

            #V-102893
            #IIS 8.5 Server STIG
            #An IIS Server configured to be a SMTP relay must require authentication.
            "SV-111855r1_rule" { 
                if ($installedFeatures.name -notcontains "SMTP-Server") {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }
            
            #V-215573
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must prohibit recursion on authoritative name servers for which forwarders have not been configured for external queries.
            "SV-215573r561297_rule" { 
                #Not Applicable on SIPR
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                #if forwarders are used, recursion must be enabled, root hints must be disabled
                elseif(((Get-DnsServerForwarder).IPAddress).Count -gt 0){
                    if((Get-DnsServerRecursion).enable -and (!(Get-DnsServerForwarder).UseRootHint)){$ActualStatus = "NotAFinding"}}
                #if forwarders are not used, recursion must be disabled, root hints must be disabled
                elseif(((Get-DnsServerForwarder).IPAddress).Count -eq 0){
                    if((!(Get-DnsServerRecursion).enable) -and (!(Get-DnsServerForwarder).UseRootHint)){$ActualStatus = "NotAFinding"}}
                else{$ActualStatus = "Open"}
                }

            #V-215574
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Forwarders on an authoritative Windows 2012 DNS Server, if enabled for external resolution, must only forward to either an internal, non-AD-integrated DNS server or to the DoD Enterprise Recursive Services (ERS).
            "SV-215574r561297_rule" { 
                #Not Applicable on SIPR
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "NotAFinding"
                    $forwarders=((Get-DnsServerForwarder).IPAddress).IPAddressToString
                    foreach($forwarder in $forwarders){
                        try{Resolve-DnsName $forwarder -ErrorAction Stop | Out-Null}
                        catch{$ActualStatus = "Open"}
                        }
                    }
                }

            #V-215575
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server with a caching name server role must restrict recursive query responses to only the IP addresses and IP address ranges of known supported clients.
            "SV-215575r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215576
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server with a caching name server role must be secured against pollution by ensuring the authenticity and integrity of queried records.
            "SV-215576r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215577
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).
            "SV-215577r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215578
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.
            "SV-215578r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215579
            #Microsoft Windows 2012 Server Domain Name System STIG
            #NSEC3 must be used for all internal DNS zones.
            "SV-215579r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215580
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers zone files must have NS records that point to active name servers authoritative for the domain specified in that record.
            "SV-215580r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is configured correctly"}

            #V-215581
            #Microsoft Windows 2012 Server Domain Name System STIG
            #All authoritative name servers for a zone must be located on different network segments.
            "SV-215581r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215582
            #Microsoft Windows 2012 Server Domain Name System STIG
            #All authoritative name servers for a zone must have the same version of zone information.
            "SV-215582r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215583
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to enable DNSSEC Resource Records.
            "SV-215583r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215584
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.
            "SV-215584r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215585
            #Microsoft Windows 2012 Server Domain Name System STIG
            #For zones split between the external and internal sides of a network, the RRs for the external hosts must be separate from the RRs for the internal hosts.
            "SV-215585r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Our Domain Controllers only host internal DNS RRs."}

            #V-215586
            #Microsoft Windows 2012 Server Domain Name System STIG
            #In a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.
            "SV-215586r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "There are no external facing DNS servers."}

            #V-215587
            #Microsoft Windows 2012 Server Domain Name System STIG
            #In a split DNS configuration, where separate name servers are used between the external and internal networks, the internal name server must be configured to not be reachable from outside resolvers.
            "SV-215587r561297_rule" { 
                #Exports mcafee config for firewall to search
                try{
                    C:\"Program Files"\McAfee\"Host Intrusion Prevention"\ClientControl.exe /exportconfig $env:USERPROFILE\Desktop\firewallexport.txt 3
                    $firewallrules=Get-Content $env:USERPROFILE\Desktop\firewallexport.txt -Encoding Unicode -ErrorAction Stop
                    Remove-Item $env:USERPROFILE\Desktop\firewallexport.txt -ErrorAction Stop
                    if ($firewallrules -match "Deny By Default") {$ActualStatus = "NotAFinding"}
                    else {$ActualStatus = "Open"}
                    }
                catch{
                    $ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Unable to verify McAfee settings."
                    }
                }

            #V-215588
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.
            "SV-215588r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215589
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers zone database files must not be accessible for edit/write by users and/or processes other than the Windows 2012 DNS Server service account and/or the DNS database administrator.
            "SV-215589r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215590
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must implement internal/external role separation.
            "SV-215590r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "There are no external facing DNS servers."}

            #V-215591
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server authoritative for local zones must only point root hints to the DNS servers that host the internal root domain.
            "SV-215591r561297_rule" { 
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                #Checks root hints
                elseif((Get-DnsServerRootHint -ErrorAction SilentlyContinue).count -ne 0){$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-215592
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The DNS name server software must be at the latest version.
            "SV-215592r561297_rule" { 
                #Checks for patches installed within the last month
                #Technically IAVMs don't exist but I believe in the concept of this check
                $hotfix=Get-HotFix
                if(($hotfix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)}).count -gt 0){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"
                $hotfixdate=($hotfix | sort installedon).installedon | select -last 1
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The last update was installed: $hotfixdate"}
                }

            #V-215593
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers zone files must not include resource records that resolve to a fully qualified domain name residing in another zone.
            "SV-215593r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not have any hosts in the zone files that resolve to hosts in another zone that are not in the exceptions"}

            #V-215594
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers zone files must not include CNAME records pointing to a zone with lesser security for more than six months.
            "SV-215594r561297_rule" { 
                #Checks every zone for CNames
                $oldrecords=@()
                $dnszones=($ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false}).ZoneName
                foreach($dnszone in $dnszones){
                $CNames=@()
                $CNames=Get-DnsServerResourceRecord -RRType CName -ZoneName $dnszone
                $oldrecords+=$CNames | Where-Object {$_.Timestamp -lt ((Get-Date).AddMonths(-6)) -and $_.TimeToLive -gt "180:00:00"}
                }
                if($oldrecords.Count -gt 0){$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = $oldrecords}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-215595
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Non-routable IPv6 link-local scope addresses must not be configured in any zone.
            "SV-215595r561297_rule" { 
                $ActualStatus = "NotAFinding"
                $dnszones=($ALLDNSZones | where {$_.IsReverseLookupZone -eq $false }).ZoneName
                $AAAA=@()
                foreach($dnszone in $dnszones){
                $AAAA+=Get-DnsServerResourceRecord -RRType AAAA -ZoneName $dnszone
                }
                if(($AAAA.RecordData.IPv6Address.IPAddressToString | where {$_ -like "fe8*" -or $_ -like "fe9*" -or $_ -like "fea*" -or $_ -like "feb*"}).count -gt 0){$ActualStatus = "Open"}
                }

            #V-215596
            #Microsoft Windows 2012 Server Domain Name System STIG
            #AAAA addresses must not be configured in a zone for hosts that are not IPv6-aware.
            "SV-215596r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "All hosts are IPv6 aware"}

            #V-215597
            #Microsoft Windows 2012 Server Domain Name System STIG
            #IPv6 protocol must be disabled unless the Windows 2012 DNS server is configured to answer for and hosting IPv6 AAAA records.
            "SV-215597r561297_rule" { 
                #Checks for IPV6 records then reg key
                $dnszones=($ALLDNSZones | Where-Object {$_.IsDsIntegrated -eq $true}).ZoneName
                $AAAA=@()
                foreach($dnszone in $dnszones){
                $AAAA+=Get-DnsServerResourceRecord -RRType AAAA -ZoneName $dnszone
                }
                if($AAAA.Count -gt 0){$ActualStatus = "Not_Applicable"}
                elseif((Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\" "DisabledComponents" "SilentlyContinue") -eq 255){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-215598
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to prohibit or restrict unapproved ports and protocols.
            "SV-215598r561297_rule" { 
                #Check TCP connections for 53
                if(Get-NetTCPConnection -LocalPort 53){
                    #Checks UDP connections for 53
                    if(Get-NetUDPEndpoint -LocalPort 53){$ActualStatus = "NotAFinding"}
                    }
                else {$ActualStatus = "Open"}
                }

            #V-215599
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must require devices to re-authenticate for each dynamic update request connection attempt.
            "SV-215599r561297_rule" { 
                $ActualStatus = "NotAFinding"
                $dnszones=($ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).ZoneName
                foreach($dnszone in $dnszones){
                    if(($ALLDNSZones | where ZONENAME -eq $dnszone).DynamicUpdate -notmatch "Secure"){$ActualStatus = "Open"}
                    }
                }

            #V-215600
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must uniquely identify the other DNS server before responding to a server-to-server transaction.
            "SV-215600r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215601
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The secondary Windows DNS name servers must cryptographically authenticate zone transfers from primary name servers.
            "SV-215601r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215602
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS primary server must only send zone transfers to a specific list of secondary name servers.
            "SV-215602r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215603
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must provide its identity with returned DNS information by enabling DNSSEC and TSIG/SIG(0).
            "SV-215603r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215604
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-215604r561297_rule" { 
                $cryptoACL=(Get-ChildItem C:\ProgramData\Microsoft\Crypto | Get-Acl).Access
                if((Test-Path C:\ProgramData\Microsoft\Crypto) -eq $false){$ActualStatus = "Not Applicable"}
                elseif($cryptoACL | Where-Object {($_.filesystemrights -eq "FullControl") -and ($_.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM" -and $_.IdentityReference -notmatch "BUILTIN\\Administrators")}){$ActualStatus="Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                elseif($cryptoACL.FileSystemRights -match "Modify"){$ActualStatus="Open"}
                else{$ActualStatus="NotAFinding"}
                }

            #V-215605
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server key file must be owned by the account under which the Windows 2012 DNS Server service is run.
            "SV-215605r561297_rule" { 
                #Checks if C:\ProgramData\Microsoft\Crypto exists
                if (!(Test-Path C:\ProgramData\Microsoft\Crypto)) {$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    $BadFile=@()
                    #Checks the account running DNS
                    $logonas=(Get-WmiObject Win32_Service -Filter "Name='dns'").StartName
                    Switch($logonas){
                        "LocalSystem" {$DNSowner="NT AUTHORITY\SYSTEM"}
                        default {$DNSowner=$logonas}
                        }
                    #Check the owner on sub files and folders
                    $subfiles=(Get-ChildItem C:\ProgramData\Microsoft\Crypto).FullName
                    $subfiles+="C:\ProgramData\Microsoft\Crypto"
                    foreach($file in $subfiles){
                        if((Get-Acl $file).owner -ne $dnsowner){
                            $ActualStatus = "Open"
                            $BadFile+=$file}
                            }
                    if($ActualStatus -eq "Open"){$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following file(s) have the wrong owner: $BadFile"}
                    }
                }

            #V-215606
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server permissions must be set so that the key file can only be read or modified by the account that runs the name server software.
            "SV-215606r561297_rule" { 
                #Checks if C:\ProgramData\Microsoft\Crypto exists
                if (!(Test-Path C:\ProgramData\Microsoft\Crypto)) {$ActualStatus = "Not_Applicable"}
                else{
                    $ActualStatus = "NotAFinding"
                    #Check the FullControl on sub files and folders
                    $subfiles=(Get-ChildItem C:\ProgramData\Microsoft\Crypto).FullName
                    $subfiles+="C:\ProgramData\Microsoft\Crypto"
                    foreach($file in $subfiles){if((Get-Acl $file).Access | Where-Object {$_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators"}){$ActualStatus = "Open"}}
                    }
                }

            #V-215607
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The private key corresponding to the ZSK must only be stored on the name server that does support dynamic updates.
            "SV-215607r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215608
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must implement a local cache of revocation data for PKIauthentication in the event revocation information via the network is not accessible.
            "SV-215608r561297_rule" { 
                #Waiting on KCSA
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Waiting on implementation of KCSA servers"
                }

            #V-215609
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The salt value for zones signed using NSEC3 RRs must be changed every time the zone is completely re-signed.
            "SV-215609r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215610
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must include data origin with authoritative data the system returns in response to external name/address resolution queries.
            "SV-215610r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215611
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers IP address must be statically defined and configured locally on the server.
            "SV-215611r561297_rule" { 
                $adapterconfig=Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where IpAddress -ne $null
                if($adapterconfig.dhcpenabled -eq $false -and $adapterconfig.IPAddress -ne $null -and $adapterconfig.IPSubnet -ne $null -and $adapterconfig.DefaultIPGateway -ne $null){$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-215612
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must return data information in responses to internal name/address resolution queries.
            "SV-215612r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215613
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must use DNSSEC data within queries to confirm data origin to DNS resolvers.
            "SV-215613r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215614
            #Microsoft Windows 2012 Server Domain Name System STIG
            #WINS lookups must be disabled on the Windows 2012 DNS Server.
            "SV-215614r561297_rule" { 
                if(($ALLDNSZones).IsWinsEnabled -contains $true){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-215615
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must use DNSSEC data within queries to confirm data integrity to DNS resolvers.
            "SV-215615r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215616
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured with the DS RR carrying the signature for the RR that contains the public key of the child zone.
            "SV-215616r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215617
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must enforce approved authorizations between DNS servers through the use of digital signatures in the RRSet.
            "SV-215617r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215618
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Name Resolution Policy Table (NRPT) must be configured in Group Policy to enforce clients to request DNSSEC validation for a domain.
            "SV-215618r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215619
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to validate an authentication chain of parent and child domains via response data.
            "SV-215619r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215620
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Trust anchors must be exported from authoritative Windows 2012 DNS Servers and distributed to validating Windows 2012 DNS Servers.
            "SV-215620r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215621
            #Microsoft Windows 2012 Server Domain Name System STIG
            #Automatic Update of Trust Anchors must be enabled on key rollover.
            "SV-215621r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215622
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS secondary servers must request data origin authentication verification from the primary server when requesting name/address resolution.
            "SV-215622r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215623
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS secondary server must request data integrity verification from the primary server when requesting name/address resolution.
            "SV-215623r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215624
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS secondary server must validate data integrity verification on the name/address resolution responses received from primary name servers.
            "SV-215624r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215625
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS secondary server must validate data origin verification authentication on the name/address resolution responses received from primary name servers.
            "SV-215625r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215626
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must protect the authenticity of zone transfers via transaction signing.
            "SV-215626r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215627
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must protect the authenticity of dynamic updates via transaction signing.
            "SV-215627r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215628
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must protect the authenticity of query responses via DNSSEC.
            "SV-215628r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215629
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must only allow the use of an approved DoD PKI-established certificate authorities for verification of the establishment of protected transactions.
            "SV-215629r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215630
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must protect secret/private cryptographic keys while at rest.
            "SV-215630r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "RMAD server backs up all DNS information"}

            #V-215631
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must not contain zone records that have not been validated in over a year.
            "SV-215631r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215632
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must restrict individuals from using it for launching Denial of Service (DoS) attacks against other information systems.
            "SV-215632r561297_rule" { 
                $checks=@()
                if(($UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList) -notmatch "Administrators"){$checks+="Allow log on through Remote Desktop Services"}
                if(($UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList) -notmatch "Guests"){$checks+="Deny access to this computer from the network"}
                if(($UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList) -notmatch "Guests"){$checks+="Deny log on locally"}
                if($checks.Count -eq 0){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "The following User Rights Assignment is incorrectly configured: `n$checks"}
                }

            #V-215633
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must use DNS Notify to prevent denial of service through increase in workload.
            "SV-215633r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215634
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must protect the integrity of transmitted information.
            "SV-215634r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215635
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must maintain the integrity of information during preparation for transmission.
            "SV-215635r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215636
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must maintain the integrity of information during reception.
            "SV-215636r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215637
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.
            "SV-215637r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215638
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to only allow zone information that reflects the environment for which it is authoritative, to include IP ranges and IP versions.
            "SV-215638r561297_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is configured correctly"}

            #V-215639
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.
            "SV-215639r561297_rule" { 
                #Not A Finding
                if(!($NonDSZones)){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-215640
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The DNS Name Server software must be configured to refuse queries for its version information.
            "SV-215640r561297_rule" { 
                if ((Get-DnsServerSetting -All -WarningAction SilentlyContinue).EnableVersionQuery -eq 0) {$ActualStatus = "NotAFinding"}
                else {$ActualStatus = "Open"}
                }

            #V-215641
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The HINFO, RP, TXT and LOC RR types must not be used in the zone SOA.
            "SV-215641r561297_rule" { 
                $dnszones=($ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false}).ZoneName
                $badRRs=@()
                foreach($dnszone in $dnszones){
                $badRRs+=Get-DnsServerResourceRecord -RRType HInfo -ZoneName $dnszone
                $badRRs+=Get-DnsServerResourceRecord -RRType Rp -ZoneName $dnszone
                $badRRs+=Get-DnsServerResourceRecord -RRType Loc -ZoneName $dnszone
                $badRRs+=Get-DnsServerResourceRecord -RRType Txt -ZoneName $dnszone
                }
                if($badRRs.count -gt 0){$ActualStatus = "Open"}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-215642
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must, when a component failure is detected, activate a notification to the system administrator.
            "SV-215642r561297_rule" { 
                #NIPR has SolarWinds but we need docs, SIPR has nothing so it's an Open
                if($isNipr){$ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Solarwinds monitors DNS servers and sends notifications to system administrator."}
                else{$ActualStatus = "Open"}
                }

            #V-215643
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.
            "SV-215643r561297_rule" { 
                #This really assumes that the agent is installed and therefore the rest of the McAfee suite is also installed.
                if($installedprograms.displayname -contains "McAfee Agent"){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-215644
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.
            "SV-215644r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215645
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to notify the ISSO/ISSM/DNS administrator when functionality of DNSSEC/TSIG has been removed or broken.
            "SV-215645r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215647
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must restrict incoming dynamic update requests to known clients.
            "SV-215647r561297_rule" { 
                $ActualStatus = "NotAFinding"
                $dnszones=($ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).ZoneName
                foreach($dnszone in $dnszones){
                    if(($ALLDNSZones | Where ZoneName -eq $dnszone).DynamicUpdate -notmatch "Secure"){$ActualStatus = "Open"}
                    }
                }

            #V-215648
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must be configured to record, and make available to authorized personnel, who added/modified/deleted DNS zone information.
            "SV-215648r561297_rule" { 
                if($dnsdiag.EventLogLevel -ge 2){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-215649
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server must, in the event of an error validating another DNS servers identity, send notification to the DNS administrator.
            "SV-215649r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-215650
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server log must be enabled.
            "SV-215650r561297_rule" { 
                if($dnsdiag.EventLogLevel -ge 2){$ActualStatus = "NotAFinding"}
                else{$ActualStatus = "Open"}
                }

            #V-215651
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server logging must be enabled to record events from all DNS server functions.
            "SV-215651r561297_rule" { 
                $diagnostics= @()
                $diagnostics+=$dnsdiag.Queries
                $diagnostics+=$dnsdiag.Answers
                $diagnostics+=$dnsdiag.Notifications
                $diagnostics+=$dnsdiag.Update
                $diagnostics+=$dnsdiag.QuestionTransactions
                $diagnostics+=$dnsdiag.UnmatchedResponse
                $diagnostics+=$dnsdiag.SendPackets
                $diagnostics+=$dnsdiag.ReceivePackets
                $diagnostics+=$dnsdiag.TcpPackets
                $diagnostics+=$dnsdiag.UdpPackets
                $diagnostics+=$dnsdiag.FullPackets
                $diagnostics+=$dnsdiag.UseSystemEventLog
                $diagnostics+=$dnsdiag.EnableLoggingForLocalLookupEvent
                $diagnostics+=$dnsdiag.EnableLoggingForPluginDllEvent
                $diagnostics+=$dnsdiag.EnableLoggingForRecursiveLookupEvent
                $diagnostics+=$dnsdiag.EnableLoggingForRemoteServerEvent
                $diagnostics+=$dnsdiag.EnableLoggingForServerStartStopEvent
                $diagnostics+=$dnsdiag.EnableLoggingForTombstoneEvent
                $diagnostics+=$dnsdiag.EnableLoggingForZoneDataWriteEvent
                $diagnostics+=$dnsdiag.EnableLoggingForZoneLoadingEvent

                if($diagnostics -contains $false){$ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                else{$ActualStatus = "NotAFinding"}
                }

            #V-215652
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Server logging criteria must only be configured by the ISSM or individuals appointed by the ISSM.
            "SV-215652r561297_rule" { 
                if($DomainName -eq "AREA52"){$auditors="Administrators,AFNOAPPS\\Exchange Servers,AREA52\\Exchange Enterprise Servers,LOCAL SERVICE"}
                elseif($DomainName -eq "AFNOAPPS"){$auditors="Administrators,AFNOAPPS\\Exchange Servers"}
                elseif($DomainName -eq "ACC"){$auditors="ACC\\Exchange Enterprise Servers,ACCROOT\\Exchange Servers,Administrators"}
                else{$auditors="Administrators"}
                $ActualStatus="NotAFinding"
                $value=($UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList) -join ","
                if ($Value -notmatch $auditors) {$ActualStatus = "Open"}
                else{
                    $DNSACL=(Get-Acl 'C:\Windows\System32\winevt\Logs\DNS Server.evtx').Access
                    foreach($acl in $DNSACL){
                    if($acl.FileSystemRights -match "FullControl" -and $acl.IdentityReference -notmatch "NT SERVICE\\EventLog" -and $acl.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM" -and $acl.IdentityReference -notmatch "BUILTIN\\Administrators")
                    {$ActualStatus="Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                    }
                  }
                }

            #V-215660
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows 2012 DNS Servers audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.
            "SV-215660r561297_rule" { 
                #RMAD backs up the DNS zones on NIPR
                if($IsNipr){$ActualStatus = "NotAFinding"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "RMAD backs up all DNS zones since they are AD integrated."}
                #RMAD might be coming but for now it's not
                #Document the SIPR backup process
                else{$ActualStatus = "Open"
                    $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
                }

            #V-215661
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The validity period for the RRSIGs covering the DS RR for a zones delegated children must be no less than two days and no more than one week.
            "SV-215661r561297_rule" { 
                #Not Applicable
                if($IsNIPR -eq $false){$ActualStatus = "Not_Applicable"}
                elseif(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }

            #V-228571
            #Microsoft Windows 2012 Server Domain Name System STIG
            #The Windows DNS name servers for a zone must be geographically dispersed.
            "SV-228571r561297_rule" { 
                #Not Applicable
                if(!($NonDSZones)){$ActualStatus = "Not_Applicable"}
                else{$ActualStatus = "Open"}
                }



        ###START Manual Corrections
        #I really hate having manual corrections but when reviewed quarterly they can be accurate and save a ton of time

            #V-1070
            #Windows Server 2012/2012 R2 MS STIG
            #Server systems must be located in a controlled access area, accessible only to authorized personnel.
            "SV-52838r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Base CFP and owners of the equipment are held responsible for the physical security of systems"}
            #V-1072
            #Windows Server 2012/2012 R2 MS STIG
            #Shared user accounts must not be permitted on the system.
            "SV-52839r2_rule" {
                #Not checkable via script
                $ActualStatus = "Not_Applicable"}
            #V-1076
            #Windows Server 2012/2012 R2 DC STIG
            #System-level information must be backed up in accordance with local recovery time and recovery point objectives.
            "SV-52841r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Active Directory and Group Policy is backed up on a regular basis"}
            #V-1127
            #Windows Server 2012/2012 R2 DC STIG
            #Only administrators responsible for the member server must have Administrator rights on the system.
            "SV-51157r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is enforced."}
            #V-1127
            #Windows Server 2012/2012 R2 MS STIG
            #Only administrators responsible for the member server must have Administrator rights on the system.
            "SV-51511r4_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This is enforced."}
            #V-1128
            #Windows Server 2012/2012 R2 MS STIG
            #Security configuration tools or equivalent processes must be used to configure and maintain platforms for security compliance.
            "SV-52859r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We use GPO's and STIGs to configure security requirements."}
            #V-1168
            #Windows Server 2012/2012 R2 MS STIG
            #Members of the Backup Operators group must be documented.
            "SV-52156r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
            #V-3487
            #Windows Server 2012/2012 R2 MS STIG
            #Necessary services must be documented to maintain a baseline to determine if additional, unnecessary services have been added to a system.
            "SV-52218r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $NIPRMFR}
            #V-8317
            #Windows Server 2012/2012 R2 DC STIG
            #Data files owned by users must be on a different logical partition from the directory server data files.
            "SV-51180r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not keep user shares on Domain Controllers."}
            #V-8326
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-51183r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "No other application-related components are listed in services."}
            #V-14783
            #Windows Server 2012/2012 R2 DC STIG
            #Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data-in-transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data.
            "SV-51185r3_rule" { 
                #Can't be checked
                $ActualStatus = "Not_Applicable"}
            #V-14798
            #Windows Server 2012/2012 R2 DC STIG
            #Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.
            "SV-51187r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Anonymous access is not allowed to the AD domain naming context."}
            #V-15488
            #Windows Server 2012/2012 R2 DC STIG
            #Active directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), PIV-compliant hardware token, or Alternate Logon Token (ALT) for user authentication.
            "SV-51192r4_rule" { 
                #Can't be checked
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-26683
            #Windows Server 2012/2012 R2 DC STIG
            #PKI certificates associated with user accounts must be issued by the DoD PKI or an approved External Certificate Authority (ECA).
            "SV-51191r5_rule" {
                #This requires manual validation
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "You cannot run this on the domain, it will time out. TO 00-33D-2001 provides guidance on the USAF UPN requirements."
                $ActualStatus = "NotAFinding"}
            #V-33673
            #Windows Server 2012/2012 R2 DC STIG
            #Active Directory Group Policy objects must have proper access control permissions.
            "SV-51177r5_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "There are no standard user accounts or groups that have permissions to the GPO's."}
            #V-36431
            #Active Directory Domain STIG
            #Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.
            "SV-47837r2_rule" { 
                #Unable to be checked
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36432
            #Active Directory Domain STIG
            #Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.
            "SV-47838r2_rule" { 
                #Unable to be checked
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36435
            #Active Directory Domain STIG
            #Delegation of privileged accounts must be prohibited.
            "SV-47841r2_rule" { 
                #Can be checked but can vary drastically
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36451
            #Windows Server 2012/2012 R2 MS STIG
            #Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.
            "SV-51578r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Admin accounts when are automatically added to the BC_CAT_VI group by script which prevents internet access through the proxy."}
            #V-36658
            #Windows Server 2012/2012 R2 MS STIG
            #Users with administrative privilege must be documented.
            "SV-51575r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "ISSO maintains 2875s that administrators have to fill out to obtain admin accounts."}
            #V-36659
            #Windows Server 2012/2012 R2 MS STIG
            #Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.
            "SV-51576r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "In accordance to AFMAN 17-1301 para 4.2.2.6, everyone with administrative privileges has a separate account for user duties and one for privileged duties."}
            #V-36661
            #Windows Server 2012/2012 R2 MS STIG
            #Policy must require application account passwords be at least 15 characters in length.
            "SV-51579r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "AFMAN 17-1301 para 8.5.4.5 has guidlines for passwords."}
            #V-36662
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012/2012 R2 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.
            "SV-51580r3_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "IAW AFMAN 17-1301 para 8.21.3, the ISSM ensures the service account passwords are changed as required. Also, IAW AFMAN 17-1301 para 8.5.4.3, passwords are changed at least every 60 days or more frequiently as determined by the ISO, IAW CJCSI 6510.01."}
            #V-36666
            #Windows Server 2012/2012 R2 MS STIG
            #Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.
            "SV-51577r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Military are trained in tech school before arriving to the squadron. All contractors and civilians are required to be familiar with the systems before being hired."}
            #V-36670
            #Windows Server 2012/2012 R2 MS STIG
            #Audit data must be reviewed on a regular basis.
            "SV-51561r1_rule" {
                #Can't script it.
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36671
            #Windows Server 2012/2012 R2 MS STIG
            #Audit data must be retained for at least one year.
            "SV-51563r1_rule" {
                #Can't script it.  We don't have a log storage solution anyway
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36672
            #Windows Server 2012/2012 R2 MS STIG
            #Audit records must be backed up onto a different system or media than the system being audited.
            "SV-51566r2_rule" {
                #Idk how to check this
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-36733
            #Windows Server 2012/2012 R2 MS STIG
            #User-level information must be backed up in accordance with local recovery time and recovery point objectives.
            "SV-51581r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "User-level information is backed up daily by our RMAD server."}
            #V-39325
            #Windows Server 2012/2012 R2 DC STIG
            #Active Directory Group Policy objects must be configured with proper audit settings.
            "SV-51169r5_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39326
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory Domain object must be configured with proper audit settings.
            "SV-51170r2_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39327
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory Infrastructure object must be configured with proper audit settings.
            "SV-51171r2_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39328
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings.
            "SV-51172r2_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39329
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory AdminSDHolder object must be configured with proper audit settings.
            "SV-51173r2_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39330
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory RID Manager$ object must be configured with proper audit settings.
            "SV-51174r3_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}                
            #V-39332
            #Windows Server 2012/2012 R2 DC STIG
            #The Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions.
            "SV-51178r4_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-39333
            #Windows Server 2012/2012 R2 DC STIG
            #Domain created Active Directory Organizational Unit (OU) objects must have proper access control permissions.
            "SV-51179r3_rule" {
                #Idk how to check at least inclusive
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-40172
            #Windows Server 2012/2012 R2 MS STIG
            #Backups of system-level information must be protected.
            "SV-52130r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "All backups are stored in a secure data center that requires badge access from authorized personnel."}
            #V-40173
            #Windows Server 2012/2012 R2 MS STIG
            #System-related documentation must be backed up in accordance with local recovery time and recovery point objectives.
            "SV-52131r3_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Backups are performed daily by the RMAD server."}
            #V-40198
            #Windows Server 2012/2012 R2 Domain Controller Security Technical Implementation Guide :: Version 2, Release: 18 Benchmark Date: 25 Oct 2019
            #The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
            "SV-52157r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "All the members are service accounts and not user accounts."}
            #V-43648
            #Active Directory Domain STIG
            #Separate smart cards must be used for Enterprise Admin (EA) and Domain Admin (DA) accounts from smart cards used for other accounts.
            "SV-56469r2_rule" { 
                #Can't be checked
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}
            #V-57641
            #Windows Server 2012/2012 R2 MS STIG
            #Protection methods such as TLS, encrypted VPNs, or IPSEC must be implemented if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.
            "SV-72051r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "Protection methods are configured."}
            #V-57645
            #Windows Server 2012/2012 R2 MS STIG
            #Systems requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
            "SV-72055r1_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "All systems that we manage have adequate physical protection across the Air Force."}
            #V-57653
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012 / 2012 R2 must automatically remove or disable temporary user accounts after 72 hours.
            "SV-72063r2_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not use temporary accounts in AFNET."}
            #V-57655
            #Windows Server 2012/2012 R2 MS STIG
            #Windows 2012 / 2012 R2 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
            "SV-72065r3_rule" { 
                #Can't be checked
                $ActualStatus = "NotAFinding"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "We do not use emergency administrator accounts."}
            #V-57719
            #Windows Server 2012/2012 R2 MS STIG
            #The operating system must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.
            "SV-72133r1_rule" {
                #Not scriptable check
                $ActualStatus = "Open"
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $POAM}

        ###END Manual Corrections


            default {
                $NotChecked += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_index]
                }
            }

        #And now that we've checked the vulnerability, update the checklist, IF we knew how to check it
        if ($ActualStatus -ne $null) {
            #$STIGs[$STIG_index].STATUS = $ActualStatus
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS = $ActualStatus}

        #reset our flag
        Remove-Variable ActualStatus -EA SilentlyContinue
        }
    else { #If we aren't actually SCAPing, find which Rule_IDs we haven't coded a check for
        $Rule_ID = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_Index]
        if (!($script -match $Rule_ID)) { #If we can find the Rule ID anywhere in the script, then we dont need to add it.
            $Vuln_ID = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]
            $Rule_Title = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_Title_Index]
            $Benchmark = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$STIGRef_Index]
            $CopyToClip += @"

            #$Vuln_ID
            #$Benchmark
            #$Rule_Title
            "$Rule_ID" { 
                #Comments detailing the GPO setting path
                #Comments describing the setting to configure and what to set it to
                if (stigSettingsDontApply) {`$ActualStatus = "Not_Applicable"}
                elseif (SettingAreConfiguredAsDesired) {`$ActualStatus = "NotAFinding"}
                else {`$ActualStatus = "Open"}
                #$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = ""
                #$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = ""
                }
"@

            $ExportSpreadsheet+=[PSCustomObject]@{Vuln_ID=$Vuln_ID;Benchmark=$Benchmark;Rule_Title=$Rule_Title;Rule_ID=$Rule_ID;Status='';Comments=''}
            }
        }
    }

#If we check STIGs, then write our changes to the checklist file
#If not, if we're missing any Rule_IDs from the script, copy the formatted text to clip to be put back into the script
#I don't want to modify the script directly, cause I don't trust myself to handle it
if ($SCAP -eq $true) {
    Out-File -InputObject $checklist.Innerxml -Encoding default "$env:USERPROFILE\desktop\$env:computername.ckl"
    }
elseif($automate -eq $true){
    if(!(Test-Path "\\muhj-fs-001.acc.accroot.ds.af.smil.mil\SCAPTest\$($Quarter)\$($GeoCode)")){New-Item -ItemType Directory "\\muhj-fs-001.acc.accroot.ds.af.smil.mil\SCAPTest\$($Quarter)\$($GeoCode)"}
    Out-File -InputObject $checklist.Innerxml -Encoding default "\\muhj-fs-001.acc.accroot.ds.af.smil.mil\SCAPTest\$($Quarter)\$($GeoCode)\$env:computername.ckl"
    }
else {
    if ($CopyToClip.count -gt 0) {
        Write-Host ("The provided .ckl file had " + $CopyToClip.count + " Rule IDs not handled by this script.")
        $CopyToClip | clip
        $ExportSpreadsheet | Export-Csv -Append -NoTypeInformation "\\zhtx-bs-013v\cyod\07--Cyber 365\02--CCRI\HardCodedSTIGs.csv"
        }
    else {Write-Host "This script contains all Rule_IDs being checked"}
    }

#If there was anything that could not be scripted, let the user know which ones
if ($ManuallyVerify.count -gt 0) {
    Write-Host -ForegroundColor Green "The following Vulns need to be manually verified:"
    $ManuallyVerify | Write-Host
    }

#If there was anything that we don't have a case for, notify the user
if ($NotChecked.count -gt 0) {
    Write-Host -ForegroundColor Cyan "The following Rule IDs are not checked by this script:"
    $NotChecked | Write-Host
    }

    #Calculates the time it took to run the script
    #Really just here for bragging rights
    "This script completed in " + [math]::Round($stopwatch.Elapsed.TotalMinutes,2) + " minutes"

if($automate -eq $true){Stop-Transcript
    Get-ChildItem C:\Windows\Temp | where name -Like "*.ckl" | Remove-Item -Force}
else{
    #Leave the window open so the script runner can read what's there
    Read-Host -Prompt "Press enter to close window"
}