<#
.SYNOPSIS
  MTO 2021-222-001 user account compliance scans.
.DESCRIPTION
  This script will scan the Bases OU for user objects then compare
  their compliance with the MTO. It then publishes a report to Netlogon.

  ExtensionAttribute10 exempts nothing.
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\UserAccounts_<DomainName>.csv
  Deleted Objects stored in Netlogon\NonCompliance\Compliance Archive\DeletedObjects.csv
.NOTES
  Version:        2.2.1
  Author:         CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
  CoAuthors:      STEELE, CHRISTOPHER M CTR USAF ACC 83 NOS/CYOD
                  Estep, Jonathan K CTR USAF ACC 83 NOS/CYOD
  Creation Date:  1 June 2021
  Edit Date:      25 Jan 2022
  ToDo List: 
    - Better commenting
    - Maybe more logs
    - Handle not-live better
.CHANGELOG
  v2.1.0 - Michael Calabrese - Rev A, date and name change.
  v2.1.1 - Michael Calabrese - Fixed formatting and EA9 flagging
  v2.2.0 - Michael Calabrese - Adding Debugging.
  v2.2.1 - Michael Calabrese - Exempted employeeType Y from this search to force Role and Group accounts to the  role account scans.
#>

Param(
    #If live is not set to true by the Trigger-Scripts.ps1, it defaults to false.
    #Please don't change this behavior.
    [Bool]$Live = $false
)

function Export-Object ([Object[]]$NonCompObj,[String]$FailReasons) {
    
    #Handle the stupid date
    if([String]::IsNullOrEmpty($NonCompObj.lastLogonTimestamp)) {
        $lastlogin = 'Never Logged In'
    } else {
        $lastlogin=([datetime]::FromFileTime($NonCompObj.lastLogonTimestamp)).toshortdatestring()
    }

    #Create object to export information
    $export=[PSCustomObject]@{
    'Display Name'=[string]$NonCompObj.DisplayName
    'Employee Type'=[string]$NonCompObj.EmployeeType
    'Email'=[string]$NonCompObj.mail
    'Location'=[string]$script:BaseName
    'Organization'=[string]$NonCompObj.o
    'SCL Required'=[string]$NonCompObj.SmartcardLogonRequired
    'Last Logon Time'=$lastlogin
    'Non Compliance Date'=$script:EA9date.toshortdatestring()
    'Pending Deletion Date'=$script:EA9date.Adddays($script:deleteGracePeriod).toshortdatestring()
    'Fail Reasons'=$FailReasons
    }

    Return $export
}

##Shows debug when running interactively##
if($host.Name -match 'ISE') {$DebugPreference = "Continue"}
$ErrorActionPreference='SilentlyContinue'

#Shared Script Vars
Write-Debug "Live: $live"
$Global:Domain=Get-ADDomain -Current LocalComputer
[DateTime]$Global:today=Get-Date
[String]$MTOName='MTO 2021-222-001A'
[DateTime]$MTOComplianceDate = (Get-Date 1/11/2022)
[String]$TodayTimeStamp = $today.ToString("yyyyMMdd")
[String]$disableDescription = "Account Disabled for Non-Compliance with $MTOName. Please contact your local Wing IA office or Unit ISSO (formally CSL or IAO) for immediate assistance. DO NOT re-enable account unless all criteria found in $MTOName is met. Re-enabled accounts that do not meet the MTO Criteria will be automatically disabled."
[String]$reportPath="E:\Windows\SYSVOL\domain\scripts\NonCompliance\"
[String]$ACCPath = '\\acc.accroot.ds.af.smil.mil\netlogon\'
[Array]$report=@()
[Array]$statistics=@()
[Array]$Deleted=@()

#Script Specific Vars
$reportname="UserAccounts_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$creationdate=$today.AddDays(-60); Write-Debug ("Creation Date Req: " + $creationdate)
$logondate=$creationdate.ToFileTime(); Write-Debug ("Logon Date Req: " + $logondate)
$VNcreationdate=$today.AddDays(-90); Write-Debug ("Guard/Reserve Creation Date Req: " + $VNcreationdate)
$VNlogondate=$VNcreationdate.ToFileTime(); Write-Debug ("Guard/Reserve Logon Date Req: " + $VNlogondate)
$deleteGracePeriod = 90
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_USER,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

#Control Variables


#Begin Logic
[array]$OUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator
Write-Debug ("OUs Found: " + $OUs.Count)
[Int]$NonCompliantObjectCount = 0
[Int]$CompliantObjectCount = 0
[Int]$ObjectCount = 0

ForEach ($OU in $OUs) {
    #setup counting for compliance stats
    $foundNonCompliantObjectCount = 0
    $foundCompliantObjectCount = 0
    $foundObjectCount = 0

    #setup searchbase and base info
    $baseDN=$OU.distinguishedName; Write-Debug ("Base DN: " + $baseDN)
    $baseName=$OU.Name; Write-Debug ("Base Name: " + $baseName)
    
    #EXTREMELY TEMPORARY
    if ($baseName -eq "SDDC") {continue}
    
    #grab all user accounts that aren't "ROLE accounts"
    [array]$ObjectDE = Get-ADUser -Filter {userPrincipalName -notlike "*.ROLE*"} -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator | Where employeeType -ne 'Y'

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Account: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #Different Criteria for guard and reserve
        Switch ($Object.EmployeeType) {
            {($_ -eq 'V') -or ($_ -eq 'N')} {
                $logondateFT = $VNlogondate
                $logondateDT = $VNcreationdate
            }
            Default {
                $logondateFT = $logondate
                $logondateDT = $creationdate
            }
        }

        #if dormant status attribute populated, check if still dormant
        try {
            #if dormant status attribute populated, check if still dormant
            if($Object.extensionAttribute6 -match "^(TDY|LVE) til [0-9]{8}") {

                $EA6Split = ($Object.extensionAttribute6 -Split " ")[2]
                [datetime]$EA6date = $EA6Split.Substring(4,2) + "/" + $EA6Split.Substring(6,2) + "/" + $EA6Split.Substring(0,4)

                if($EA6date -gt $today) {
                    #still dormant, skip
                    continue
                }
            }

            if( ($Object.lastlogontimestamp -lt $logondateFT) -and ($Object.whencreated -lt $logondateDT) ) {
                $Compliant = $false
                $FailedChecks += "LastLogonTooLongAgo(<$([datetime]::FromFileTime($logondateFT).tostring("MM/dd/yyyy")))"
            }
        } catch {
            Write-Debug $_.Exception.Message
        }

        #SCL Required for User Accounts
        if(!($Object.SmartcardLogonRequired)) {
            $Compliant = $false
            $FailedChecks += "SmartcardLogonRequiredNotSet"
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false 

            #If stamped EA9, remove
            if($Object.extensionAttribute9) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9 
            }

            #If description matches stamped description, remove
            if($Object.description -eq $disableDescription) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear description
            }

            $foundCompliantObjectCount++

        } else {

            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADUser -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9="$TodayTimeStamp"}
                $EA9date = $today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }

            #Calculate DeleteDate based on EA9 Date
            $deletedate = $EA9date.AddDays($deleteGracePeriod)

            #Disable and stamp description
            if($today -ge $MTOComplianceDate -and $live) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Description $disableDescription
                Disable-ADAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator
            }

            #Delete if after timeline
            if($today -ge $deletedate -and $today -ge $MTOComplianceDate  -and $live) {
                Remove-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'User' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA9date,EA6Split,EA6date,EDI,logondateDT,logondateFT -EA SilentlyContinue
    }

    $statistics+=Export-Statistics -Base $baseName -ObjectType 'Users'
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'Users'
}

#publish report to netlogon
Move-Item "$reportpath$reportname" -Destination "$reportpath\Compliance Archive" -Force
$report | Sort-Object Location,'Display Name' | Export-Csv -Path "$reportpath$reportname" -NoTypeInformation -Force

#Log deleted objects
if($Deleted) {
    $Deleted | Export-Csv "$reportpath\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv" -NoTypeInformation -Append
}

#Return the stats to the calling script
Return $statistics