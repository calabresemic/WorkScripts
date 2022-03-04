<#
.SYNOPSIS
  MTO 2021-222-001 Role Account compliance scans.
.DESCRIPTION
  This script will scan the Bases OU for user objects with the filter {UserPrincipalName -like "*.ROLE*"}
  then compare their compliance with the MTO. It then publishes a report to Netlogon.

  ExtensionAttribute10 exempts SCL required but enforces password last set. (Not per TO,
  some legacy accounts are approved this way.Do not add new ones.)
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\RoleAccounts_<DomainName>.csv
  Deleted Objects stored in Netlogon\NonCompliance\Compliance Archive\DeletedObjects.csv
.NOTES
  Version:        2.2
  Author:         CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
  CoAuthors:      STEELE, CHRISTOPHER M CTR USAF ACC 83 NOS/CYOD
                  Estep, Jonathan K CTR USAF ACC 83 NOS/CYOD
  Creation Date:  1 June 2021
  Edit Date:      25 Jan 2022
  Purpose/Change: Adding Debugging.
  ToDo List: 
    - Better commenting
    - Maybe more logs
    - Handle not-live better
    - EA10?
.CHANGELOG
  v2.1.0 - Michael Calabrese - Rev A, date and name change.
  v2.1.1 - Michael Calabrese - Fixed formatting and EA9 flagging
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

    #Redact Logon Workstations
    if ($NonCompObj.LogonWorkstations) {
        $AuthorizedComputers="Populated"
    } else {
        $AuthorizedComputers="Needs to be Populated"
    }

    #Create object to export information
    $export=[PSCustomObject]@{
    'Common Name'=[string]$NonCompObj.CN
    'Location'=[string]$script:BaseName
    'Description'=[string]$NonCompObj.Description
    'Organization'=[string]$NonCompObj.o
    'Office Symbol'=[string]$NonCompObj.physicalDeliveryOfficeName
    'City'=[string]$NonCompObj.l
    'Telephone'=[string]$NonCompObj.telephoneNumber
    'Owner Email'=[string]$NonCompObj.extensionAttribute13
    'Authorized Computers'=$AuthorizedComputers
    'Employee Type'=[string]$NonCompObj.EmployeeType
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
$reportname="RoleAccounts_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$creationdate=$today.AddYears(-1); Write-Debug ("Creation Date Req: " + $creationdate)
$logondate=$creationdate.ToFileTime(); Write-Debug ("Logon Date Req: " + $logondate)
$deleteGracePeriod = 90
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_ROLE,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

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
    
    #grab all groups in OU    
    #[array]$ObjectDE = Get-ADUser -Filter {(userPrincipalName -like "*.ROLE*") -or (employeeType -eq 'Y')} -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator
    [array]$ObjectDE = Get-ADUser -Filter * -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator | where {$_.userPrincipalName -like "*.ROLE*" -or $_.employeeType -eq 'Y'}

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Account: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #TO 00-33D-2001 Section 4.17.1
        if([string]::IsNullOrEmpty($Object.Description)) {
            $Compliant = $false
            $FailedChecks += "DescriptionIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.17.2
        if([string]::IsNullOrEmpty($Object.l)) {
            $Compliant = $false
            $FailedChecks += "CityIsNullOrEmpty"
        } 

        #TO 00-33D-2001 Section 4.17.3
        if([string]::IsNullOrEmpty($Object.o)) {
            $Compliant = $false
            $FailedChecks += "OrgIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.17.4
        if([string]::IsNullOrEmpty($Object.physicalDeliveryOfficeName)) {
            $Compliant = $false
            $FailedChecks += "OfficeIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.17.5
        if($Object.telephoneNumber -notmatch "^\d{3}-\d{3}-\d{4}$") {
            $Compliant = $false
            $FailedChecks += "TelephoneNumberNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.17.6
        if([string]::IsNullOrEmpty($Object.extensionAttribute13)) {
            $Compliant = $false
            $FailedChecks += "EA13EmailNullOrEmpty"
        } elseif($Object.extensionAttribute13 -notmatch "@mail\.smil\.mil$") {
            $Compliant = $false
            $FailedChecks += "EA13EmailIsNotSIPR"
        }

        #TO 00-33D-2001 Section 4.17.7
        #May need to be exempted/ignored due to MS hard limit of 1024 characters in attrib
        if([string]::IsNullOrEmpty($Object.LogonWorkstations)) {
            $Compliant = $false
            $FailedChecks += "LogonWorkstationsNotPopulated"
        }

        #TO 00-33D-2001 Section 4.17.8
        if($Object.employeeType -ne "Y") {
            $Compliant = $false
            $FailedChecks += "EmployeeTypeNotY"
        }

        #SCL Required for Role Accounts
        #Group accounts have been historically granted SCL exemption so we will accommodate
        if($Object.extensionAttribute10 -match "^\d{8}$") {
            
            #If EA10 has a date, calculate it
            [datetime]$EA10date = $Object.extensionAttribute10.Substring(4,2) + "/" + $Object.extensionAttribute10.Substring(6,2) + "/" + $Object.extensionAttribute10.Substring(0,4)
            if(($EA10date -gt $today) -and (!$Object.SmartcardLogonRequired)) {

                #Check is pwd set
                if($Object.pwdLastSet) {
                    $pwdLastSet = [datetime]::FromFileTime($Object.pwdLastSet)
                } else {
                    [string]$pwdLastSet = "Never Set"
                    $Compliant = $false
                    $FailedChecks += "PwdLastSetNever"
                }

                #check if pwd is not compliant
                if($pwdLastSet -lt $pwddate) {
                    $Compliant = $false
                    $FailedChecks += "PwdLastSetTooLongAgo($pwdLastSet<$pwddate)"
                }
            } else {

                #If EA10 date is expired, check if SCL Required
                if(!$Object.SmartcardLogonRequired) {
                    $Compliant = $false
                    $FailedChecks += "SmartcardLogonRequiredNotSet"
                }
            }
        } else {
            
            #If no EA10 date, check if SCL Required
            if(!$Object.SmartcardLogonRequired) {
                $Compliant = $false
                $FailedChecks += "SmartcardLogonRequiredNotSet"
            }
        }

        #Accounts must be logged in within a year
        if (($Object.lastlogontimestamp -lt $logondate) -and ($Object.whencreated -lt $creationdate)){
            $Compliant = $false
            $FailedChecks += "LastLogonTooLongAgo(<$([datetime]::FromFileTime($logondate).tostring("MM/dd/yyyy")))"
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
            if ($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                Remove-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'Role Account' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA9date -EA SilentlyContinue
    }

    $statistics+=Export-Statistics -Base $baseName -ObjectType 'Role Accounts'
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'Role Accounts'
}

#publish report to netlogon
Move-Item "$reportpath$reportname" -Destination "$reportpath\Compliance Archive" -Force
$report | Sort-Object Location,'Common Name' | Export-Csv -Path "$reportpath$reportname" -NoTypeInformation -Force

#Log deleted objects
if($Deleted) {
    $Deleted | Export-Csv "$reportpath\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv" -NoTypeInformation -Append
}

#Return the stats to the calling script
Return $statistics