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
12/14/2020 : Michael Calabrese (1468714589) - v4.5.0 DISA released the 3 OS STIGs out of cycle and there were so many changes I didn't even know what to do. Hopefully this works.
12/15/2020 : Michael Calabrese (1468714589) - v4.5.1 Removed depricated STIGs to save space in this script. Reorganized to accomodate the new numbering system.
12/16/2020 : Michael Calabrese (1468714589) - v4.5.2 - Removed ServerRole switches for 2012 STIGs, fixed false positives caused by the switch to new numbering system.
12/17/2020 : Michael Calabrese (1468714589) - v4.5.3 - Minor repairs, fully tested on all supported NIPR systems.
12/21/2020 : Michael Calabrese (1468714589) - v4.5.5 - POAM optimizations, changed the way to search for shares, fixed 6840, 7002 checks.
4/30/2021 : Michael Calabrese (1468714589) - v4.6.0 - DNS STIG Update
6/28/2021 : Michael Calabrese (1468714589) - v5.0.0 - Yuge upgrade, using modules for STIG checks and org settings for manual entries.
#>

#Control if we want to check the STIGs on the machine, or find what Rule_ID's are missing from our script.
$SCAP = $true
$workingDir=$PSScriptRoot
$workingDir="$([Environment]::GetFolderPath("Desktop"))\SCAPer" #uncomment for testing


#If we're going to be check STIGs, then make sure we're elevated to admin creds
#If not, initialize the array to hold our text to copy
if ($SCAP) {
        $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
        $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
        $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
        if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
            $scriptpath = "'" + $MyInvocation.MyCommand.Definition + "'"
            Start-Process -FilePath PowerShell.exe -Verb runAs -ArgumentList "& $scriptPath"
            exit
        }
} else {
    Clear-Host
    $script = Get-Content $MyInvocation.MyCommand.Definition #Load the contents of the current script
    $CopyToClip = @()
}

#region Functions
    #This function returns the requested Registry Value at the provided Registry Key path
    function Global:Check-RegKeyValue {
        #$regPath example: HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria
        #$regValue is the value of the provided Registry Key in $regPath
        #$EA is erroraction, and defaults to Continue (so you can provide SilentlyContinue in case you know it will error out)
        param ($regPath,$regValueName,$EA = "Continue")
        #Return the value of the specified Registry key's $regValueName

        if ($EA -eq "Continue") {$EA = "STOP"}
        try {
        $EA = "SilentlyContinue"
        return (Get-ItemProperty ("Registry::" + $regPath) -Name $regValueName -ErrorAction $EA | select -ExpandProperty $regValueName)
        } catch {write-host ($regpath + " - " + $regValueName + "`n" + $_)}
        }

    #This function is a substitute for the PS7 test-json cmdlet with some extra stuff for neater outputs
    function Validate-OrgSettings { 
        param (
             [Parameter(ValueFromPipeline)]$settings
        )

        $allowedstatusvalues=@('Open','NotAFinding','Not_Applicable')

        $return=@()
        $MFRs = $settings.MFRs | where {$_ -notmatch "^V-"} | %{$_ + " is not a valid MFR Vuln_ID"}
        $POAMS = $settings.POAMS | where {$_ -notmatch "^V-"} | %{$_ + " is not a valid POA&M Vuln_ID"}

        $entries = foreach ($Entry in $settings.Manual_Entries) {
                    if ($Entry.Rule_ID -match "^SV-.*_rule$") {    #Rule ID is Valid, continue

                        if($Entry.Status -in $allowedstatusvalues) { #Status is valid, continue

                        } else {
                            $Entry.Vuln_ID + " has invalid status"
                        }
                    } else {
                        $Entry.Vuln_ID + " has invalid rule"
                    }
                }

        $return+=$MFRs +=$POAMS+=$entries

        Return $return
    }
#endregion Functions

#Start logging, this is going to help in the long run
Start-Transcript $workingDir\Logs\SCAPer.log -Force | Out-Null

#This is here to check the speed of the script
$stopwatch=[system.diagnostics.stopwatch]::StartNew()

#region checklist
    #Default Variables
    $Global:ServerRole = Get-WmiObject Win32_OperatingSystem | select -ExpandProperty ProductType #1 is Workstation, 2 is Domain Controller, 3 is Member Server
    $Global:OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $asciiString = ("43 72 65 61 74 65 64 20 62 79 20 4d 69 63 68 61 65 6c 20 43 61 6c 61 62 72 65 73 65" -split ' ' |ForEach-Object {[char][byte]"0x$_"}) -join ''

    Switch ($OS) {
        'Microsoft Windows Server 2019 Standard'    {$Global:STIG_OS='2019'}
        'Microsoft Windows Server 2012 R2 Standard' {$Global:STIG_OS='2012'}
    }

    Switch ($ServerRole) {
        3 {$Global:STIG_TYPE='MS'}
        2 {$Global:STIG_TYPE='DC'}
        1 {$Global:STIG_TYPE='WS'}
    }

    $checklistname="$STIG_OS $STIG_TYPE Checklist *.ckl"
    $cklFilepath=Get-ChildItem "$workingdir\Checklists" -Filter $checklistname | sort -Descending | select -First 1
    [xml]$Global:checklist = Get-Content $($cklFilepath.fullname) -ErrorVariable $cklfail
    if ($cklfail) {
        Read-Host "Unable to find checklist in folder: $workingdir\Checklists"
        exit
    }
#endregion checklist

#Org Settings Import
$orgsettingfile = Get-Item $workingDir\Org_Settings\*.json | sort LastWriteTime -Descending | select -First 1
$orgsettings = Get-Content $orgsettingfile | ConvertFrom-Json
$validation=$orgsettings | Validate-OrgSettings

#Welcome Message
Write-Host "$asciiString`n`n`n`n`n`n" -ForegroundColor Green
Write-Host "Script Name: $($MyInvocation.MyCommand.Name)" -ForegroundColor DarkCyan
Write-Host "Hostname: $env:computername.$env:USERDNSDOMAIN" -ForegroundColor DarkCyan
Write-Host "Checklist: $($cklFilepath.Name)" -ForegroundColor DarkCyan
Write-Host "Imported org settings file: $($orgsettingfile.Name)" -ForegroundColor DarkCyan

#Display message and stop script if validation fails
if ($validation) {
    Write-Host "`n$validation" -ForegroundColor Red
    Read-Host "Please correct the above errors and relaunch script"
    exit
} else {
    $MFRS=$orgsettings.MFRs
    $POAMS=$orgsettings.POAMS
    $MFR_Location=$orgsettings.Locations.MFRs
    $POAM_Location=$orgsettings.Locations.POAMS
    $Manual_Entries=$orgsettings.Manual_Entries
}

#STIG Module Import
$STIGModules = Get-Item $workingDir\STIGS\*.psm1
$STIGModules | Import-Module -WarningAction SilentlyContinue -Force
Write-Host "`nSuccessfully imported the following STIG Modules:`n$($STIGModules.BaseName -join "`n")" -ForegroundColor DarkCyan
Write-Host "==================================================================" -ForegroundColor DarkCyan

if ($SCAP) {

    ####These checks are for all machines####
    "Loading universal variables..."
    $Global:ServerRole = Get-WmiObject Win32_OperatingSystem | select -ExpandProperty ProductType #1 is Workstation, 2 is Domain Controller, 3 is Member Server
    $Global:DC = Get-ADDomainController | select -ExpandProperty hostname
    $Global:auditpol = auditpol /get /category:*
    $Global:IsServerCore = (Check-RegKeyValue "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion" "InstallationType") -match "Core"
    $Global:OS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $Global:OSArch = 32
    if ([Environment]::Is64BitOperatingSystem) {$Global:OSArch = 64}
    $Global:currDate = Get-Date
    $Global:PartOfDomain = (gwmi win32_computersystem).partofdomain -eq $true
    $Global:Domain = Get-ADDomain
    $Global:IsNIPR = $Domain.DNSRoot -match "afnoapps.usaf.mil"
    $Global:DomainName = $Domain.Name
    $Global:PDC = $Domain.PDCEmulator
    $Global:installedprograms=Get-WmiObject -class Win32Reg_AddRemovePrograms64
    $Global:installedFeatures=Get-WindowsFeature | Where-Object {$_.InstallState -like "Installed"}
    $Global:NetAdapter=Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.DefaultIPGateway -ne $null}
    $NotChecked = @() #An array to hold the Rule ID's we don't have checks for
    $Global:passwordpolicy=Get-ADDefaultDomainPasswordPolicy
    $Global:UserRights=Get-WMIObject RSOP_UserPrivilegeRight -namespace root\rsop\computer | where precedence -eq 1
    $Global:SecSettings=Get-WMIObject RSOP_SecuritySettings -namespace root\rsop\computer | where precedence -eq 1
    $Global:Adminlevelcodes=@('adm','ada','adc','add','ade','adf','adw','adx')
    $Global:LegalNotice = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details.
"@

    ####Fills in Target Data section of the STIG checklist. This is used to sort data from all checklists.####
    "Generating checklist variables..."
    if($ServerRole -eq 2){$checklist.checklist.ASSET.ROLE = "Domain Controller"}
    else{$checklist.checklist.ASSET.ROLE = "Member Server"}
    $checklist.checklist.ASSET.HOST_NAME = "$env:computername"
    $checklist.checklist.ASSET.HOST_IP = ($NetAdapter.IPAddress | select-object -first 1).ToString()
    $checklist.checklist.ASSET.HOST_MAC = ($NetAdapter.MACAddress | select-object -first 1).ToString()
    $checklist.checklist.ASSET.HOST_FQDN = "$env:computername.$($Domain.DNSRoot)"
    $comment=$checklist.'#comment'
    $checklist.'#comment' = $comment + "`n" + $cklfile.Name

    #region ScanDrives
        #This scans all drives for certain files: Soft Certs, Java, 2019 OS STIGs
        #edited to use cmd /c because the old way was causing issues
        "Scanning Drives..."
        $allfiles=@()
        $drives=(Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -ne 0}).name

        foreach($drive in $drives){
            Start-Job -Name $drive -ScriptBlock {$drive=$args[0..($args.count -1)];Get-ChildItem "${drive}:\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object {($_ -like "*Acrobat.exe") -or ($_ -like "*AcroRd32.exe") -or ($_ -like "*chrome.exe") -or ($_ -like "*EXCEL.EXE") -or ($_ -like "*firefox.exe") -or ($_ -like "*FLTLDR.EXE") -or ($_ -like "*GROOVE.EXE") -or ($_ -like "*iexplore.exe") -or ($_ -like "*INFOPATH.EXE") -or ($_ -like "*lync.exe") -or ($_ -like "*MSACCESS.EXE") -or ($_ -like "*MSPUB.EXE") -or ($_ -like "*OIS.EXE") -or ($_ -like "*OneDrive.exe") -or ($_ -like "*OUTLOOK.EXE") -or ($_ -like "*plugin-container.exe") -or ($_ -like "*POWERPNT.EXE") -or ($_ -like "*PPTVIEW.EXE") -or ($_ -like "*VISIO.EXE") -or ($_ -like "*VPREVIEW.EXE") -or ($_ -like "*WINWORD.EXE") -or ($_ -like "*wmplayer.exe") -or ($_ -like "*wordpad.exe") -or ($_ -like "*.p12") -or ($_ -like "*.pfx") -or ($_ -like "*.java") -or ($_ -like "*.jpp")}} -ArgumentList $drive | Out-Null
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
            $allfiles+=$temp
        }
        Get-Job | Remove-Job

        "Scanning drives complete"

        $Global:ProcessMitigationList=$allfiles | Where-Object {($_ -like "*Acrobat.exe") -or ($_ -like "*AcroRd32.exe") -or ($_ -like "*chrome.exe") -or ($_ -like "*EXCEL.EXE") -or ($_ -like "*firefox.exe") -or ($_ -like "*FLTLDR.EXE") -or ($_ -like "*GROOVE.EXE") -or ($_ -like "*iexplore.exe") -or ($_ -like "*INFOPATH.EXE") -or ($_ -like "*lync.exe") -or ($_ -like "*MSACCESS.EXE") -or ($_ -like "*MSPUB.EXE") -or ($_ -like "*OIS.EXE") -or ($_ -like "*OneDrive.exe") -or ($_ -like "*OUTLOOK.EXE") -or ($_ -like "*plugin-container.exe") -or ($_ -like "*POWERPNT.EXE") -or ($_ -like "*PPTVIEW.EXE") -or ($_ -like "*VISIO.EXE") -or ($_ -like "*VPREVIEW.EXE") -or ($_ -like "*WINWORD.EXE") -or ($_ -like "*wmplayer.exe") -or ($_ -like "*wordpad.exe")}
        $Global:softcerts=$allfiles | where {($_ -like "*.p12") -or ($_ -like "*.pfx")}
        $Global:javalist=$allfiles | where {($_ -like "*.java") -or ($_ -like "*.jpp")}
    #endregion ScanDrives
    
    #Server 2019 only checks
    #Yes there are other ways to do this but someone locked the registry key I need so I have to do it manually...
    if($OS -like "Microsoft Windows Server 2019*"){
    "Loading Server 2019 variables..."
        $Global:SysProcessMitigation=Get-ProcessMitigation -System
        $Global:ProcessMitigation=@()
        $Global:ProcessMitigation += Get-ProcessMitigation -Name Acrobat.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name AcroRd32.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name chrome.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name EXCEL.EXE
        $Global:ProcessMitigation += Get-ProcessMitigation -name firefox.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name FLTLDR.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name GROOVE.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name iexplore.exe
        $Global:ProcessMitigation += Get-ProcessMitigation -name INFOPATH.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name java.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name javaw.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name javaws.exe
        $Global:ProcessMitigation += Get-ProcessMitigation -name lync.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name MSACCESS.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name MSPUB.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name OIS.EXE
        $Global:ProcessMitigation += Get-ProcessMitigation -name OneDrive.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name OUTLOOK.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name plugin-container.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name POWERPNT.EXE
        $Global:ProcessMitigation += Get-ProcessMitigation -name PPTVIEW.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name VISIO.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name VPREVIEW.EXE; $Global:ProcessMitigation += Get-ProcessMitigation -name WINWORD.EXE
        $Global:ProcessMitigation += Get-ProcessMitigation -name wmplayer.exe; $Global:ProcessMitigation += Get-ProcessMitigation -name wordpad.exe
        }

    #DNS only checks
    if($installedFeatures.name -contains "DNS"){
    "Loading DNS variables..."
        $Global:dnsdiag = Get-DnsServerDiagnostics
        $Global:ALLDNSZones=Get-DnsServerZone | where {$_.ZoneName -ne "TrustAnchors"}
        $Global:NonDSZones=($ALLDNSZones | where {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).IsDsIntegrated -contains $false
        $Global:Analyticlog=(Get-LogProperties "Microsoft-Windows-DNSServer/Analytical").Enabled
        }

    #DC only checks
    if($ServerRole -eq 2){
    "Loading DC variables..."
        #Using this searchbase makes it faster to find it. Builtin accounts could be moved so this might need to be adjusted if you run into error.
        $Global:Guest=Get-ADUser -Filter * -SearchBase (Get-ADDomain).UsersContainer | where SID -like "*501"
        $Global:Admin=Get-ADUser -Filter * -SearchBase (Get-ADDomain).UsersContainer  -Properties PasswordLastSet| where SID -like "*500"

        #This is for 2012R2 (V-226246 and V-226247)/2019 (V-205658 and V-205700)
        #Could be modified for anything that needs to check the whole domain. Moved to the top to avoid scanning twice.
        $ous = (Get-ADOrganizationalUnit -filter *).distinguishedname
        $users = @()
        [int]$totalscriptcount=4 #I experienced errors when going over this number
        [int]$ousearch = [math]::Truncate($ous.Count/$totalscriptcount)
        for ($i = 1; $i -le $totalscriptcount; $i++)
            {
            [int]$beginarray = $($ousearch*($i-1))
            [int]$endarray = $($ousearch*$i)
            if($i -eq 1){$argument = @($ous[$beginarray..$endarray])
            } else {$argument = @($ous[($beginarray+1)..$endarray])}
            Start-Job -ScriptBlock {$ous= $args[0..($args.count -1)]; foreach($ou in $ous){Get-ADUser -Filter {(Enabled -eq $true -and PasswordNeverExpires -eq $true) -or (Enabled -eq $true -and PasswordNotRequired -eq $true)} -properties PasswordNeverExpires,PasswordNotRequired,extensionAttribute3 -SearchBase $ou -SearchScope OneLevel -Server $env:COMPUTERNAME -EA Stop}} -ArgumentList $argument | Out-Null
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
            $Global:users+=$temp}
        Get-Job | Remove-Job
    
    } else {
    $Global:Guest=Get-LocalUser | where SID -like "*501" -ErrorAction SilentlyContinue
    $Global:Admin=Get-LocalUser | where SID -like "*500" -ErrorAction SilentlyContinue
    }

    "`nBeginning STIG checks"

    ####
    #$STIGs = $checklist.GetElementsByTagName("VULN")
    $Global:STIGS = $checklist.CHECKLIST.stigs.iSTIG.vuln

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
    New-Variable -Name ($_.trim() + "_index") -Value $STIGs[0].STIG_DATA.VULN_ATTRIBUTE.IndexOf($_.trim()) -Force -Scope Global
    }

    #Main loop to parse checklist
    #When trying to edit back into the Checklist, do not use $STIGs; use $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index]
    :main for ($Global:STIG_index = 0; $STIG_index -lt $STIGs.count; $STIG_index++) {

        #Lets only bother checking ones that are marked Not_Reviewed, just in case our checks aren't accurate and to speed up script time
        if ($STIGs[$STIG_index].STATUS -ne "Not_Reviewed") {continue}

        Write-Host ("Checking Vuln " + $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index])

        Try {
            #try to match a Rule_ID to a function in the STIG modules
            $Function=$STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_index]
            $results=Invoke-Expression $Function

            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS = $results.status
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $results.comment
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = $results.Finding_Details
        } Catch {
            #if no function exists, try to match to manual entries
            $rule=$STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_index]
            if ($rule -in $Manual_Entries.Rule_ID) {

                $me=$Manual_Entries | where Rule_ID -eq $rule
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS = $me.status
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = $me.comment
                $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Manual entry based on Org Settings."

            } else {
                #if not checked then add to the array
                $NotChecked += $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_index]
            }
        }

        #reset our flag
        Remove-Variable results -EA SilentlyContinue

        #Add Comments for POAMS
        if ($checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS -eq "Open" -and $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index] -in $POAMS) {
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "This vulnerability is currently POAMed. A copy of the POAM is located on SIPR in the following location: $POAM_Location"
        }

        #Set the comment for MFRs
        if ($STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index] -in $MFRS) {$checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].COMMENTS = "There is an MFR for this vulnerability located: $MFR_Location"}
    }

    #If we check STIGs, then write our changes to the checklist file
    Set-Content -Value $checklist.Innerxml -Path "$workingdir\$env:computername.ckl" -Force

} else {
    #If not checking STIGs
    if ($CopyToClip.count -gt 0) {
        Write-Host ("The provided .ckl file had " + $CopyToClip.count + " Rule IDs not handled by this script.")
        $CopyToClip | clip
    } else {Write-Host "This script contains all Rule_IDs being checked"}
}

#If there was anything that we don't have a case for, notify the user
if ($NotChecked.count -gt 0) {
    Write-Host -ForegroundColor Cyan "The following Rule IDs are not checked by this script:"
    $NotChecked | Write-Host
}

#Calculates the time it took to run the script
#Really just here for bragging rights
"This script completed in " + [math]::Round($stopwatch.Elapsed.TotalMinutes,2) + " minutes"

#Stop log before script exits
Stop-Transcript | Out-Null

#Leave the window open so the script runner can read what's there
Read-Host -Prompt "Press enter to close window"