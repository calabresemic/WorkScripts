<#
.SYNOPSIS
  MTO 2021-222-001 service account compliance scans.
.DESCRIPTION
  This script will scan the Service Accounts OU for user objects then compare
  their compliance with the MTO. It then scans the Managed Service Accounts container
  for service account objects (Get-ADServiceAccount) and compares their compliance 
  with the MTO. THERE ARE TWO SEPARATE LOOPS IN THIS SCRIPT. It publishes a combined
  report to Netlogon.

  ExtensionAttribute10 exempts passwordNeverExpires.

  (G)MSAs are not being struck only warned.
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\SVCAccounts_<DomainName>.csv
  Deleted Objects stored in Netlogon\NonCompliance\Compliance Archive\DeletedObjects.csv
.NOTES
  Version:        2.2
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
  v2.2.1 - Michael Calabrese - Warn for description only, no strike.
#>

Param(
    #If live is not set to true by the Trigger-Scripts.ps1, it defaults to false.
    #Please don't change this behavior.
    [Bool]$Live = $false
)

function Export-Object ([Object[]]$NonCompObj,[String]$FailReasons) {   

    #Create object to export information
    $export=[PSCustomObject]@{
    'Common Name'=[string]$NonCompObj.CN
    'Location'=[string]$script:BaseName
    'Organization'=[string]$NonCompObj.o
    'Office Symbol'=[string]$NonCompObj.physicalDeliveryOfficeName
    'City'=[string]$NonCompObj.l
    'Validation Statement'=[string]$NonCompObj.extensionAttribute7
    'Owner Email'=[string]$NonCompObj.extensionAttribute13
    'Creation CRQ'=[string]$NonCompObj.extensionAttribute8
    'Description Text'=[string]$NonCompObj.Description
    'Telephone'=[string]$NonCompObj.telephoneNumber
    'Employee Type'=[string]$NonCompObj.EmployeeType
    'Exemption Type'=[string]$NonCompObj.extensionAttribute3
    'Password Last Set'=[string]$script:pwdLastSet
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
$reportname="SVCAccounts_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$IAValidationDate=$today.AddDays(-365); Write-Debug ("IA Validation Date Req: " + $IAValidationDate)
$pwddate=$today.AddDays(-60); Write-Debug ("PasswordLastSet Date Req: " + $pwddate)
$deleteGracePeriod = 45
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_SVC,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

#Control Variables


#Begin Logic
if($Domain.Name -eq 'AREA42') {
    #AREA42 doesn't use the correct sub-OUs...
    [array]$OUs=Get-ADOrganizationalUnit "OU=Service Accounts,OU=Administration,$($Domain.DistinguishedName)" -Server $Domain.PDCEmulator

} else {
    [array]$OUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Service Accounts,OU=Administration,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator
}

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
    
    #grab all service accounts in OU
    [array]$ObjectDE = Get-ADUser -Filter * -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Account: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #TO 00-33D-2001 Section 4.15.1
        if([string]::IsNullOrEmpty($Object.Description)) {
            $Compliant = $false
            $FailedChecks += "DescriptionIsNullOrEmpty"
        } elseif($Object.Description -eq $disableDescription) {
            $Compliant = $false
            $FailedChecks += "DescriptionIsDisableMessage"
        }

        #TO 00-33D-2001 Section 4.15.2
        if($Object.extensionAttribute7 -match "^Acct Validated [0-9]{8} by ") {
            $EA7Split = ($Object.extensionAttribute7 -Split " ")[2]
            [datetime]$EA7date = $EA7Split.Substring(4,2) + "/" + $EA7Split.Substring(6,2) + "/" + $EA7Split.Substring(0,4)

            if($EA7date -lt $IAValidationDate) {
                $Compliant = $false
                $FailedChecks += "IAValidationTooLongAgo($EA7date<$IAValidationDate)"
            }
        } else {
            $Compliant = $false
            $FailedChecks += "IAValidationIsNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.15.3
        if([string]::IsNullOrEmpty($Object.l)) {
            $Compliant = $false
            $FailedChecks += "CityIsNullOrEmpty"
        } 

        #TO 00-33D-2001 Section 4.15.4
        if([string]::IsNullOrEmpty($Object.o)) {
            $Compliant = $false
            $FailedChecks += "OrgIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.15.5
        if([string]::IsNullOrEmpty($Object.physicalDeliveryOfficeName)) {
            $Compliant = $false
            $FailedChecks += "OfficeIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.15.6
        if($Object.telephoneNumber -notmatch "^\d{3}-\d{3}-\d{4}$") {
            $Compliant = $false
            $FailedChecks += "TelephoneNumberNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.15.7
        if($Object.extensionAttribute8 -notmatch "CRQ\d{12}|WO\d{13}") {
            $Compliant = $false
            $FailedChecks += "EA8CRQNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.15.8
        if([string]::IsNullOrEmpty($Object.extensionAttribute13)) {
            $Compliant = $false
            $FailedChecks += "EA13EmailNullOrEmpty"
        } elseif($Object.extensionAttribute13 -notmatch "@mail\.smil\.mil$") {
            $Compliant = $false
            $FailedChecks += "EA13EmailIsNotSIPR"
        }

        #TO 00-33D-2001 Section 4.15.10
        if($Object.employeeType -ne "S") {
            $Compliant = $false
            $FailedChecks += "EmployeeTypeNotS"
        }

        #TO 00-33D-2001 Section 4.15.11
        if($Object.extensionAttribute3 -ne "SVC") {
            $Compliant = $false
            $FailedChecks += "EA3ExemptionTypeNotSVC"
        }

        #Password set more than 60 days ago
        if($Object.extensionAttribute10 -eq 0) {
            #User must change passord on next login
            Continue
        } elseif($Object.extensionAttribute10 -match "[0-9]{8}"){
            [datetime]$EA10date = $Object.extensionAttribute10.Substring(4,2) + "/" + $Object.extensionAttribute10.Substring(6,2) + "/" + $Object.extensionAttribute10.Substring(0,4)
            if($EA10date -gt $today) {
                #still exempt, skip
                Continue
            }
        } else {
            #Check if password is set
            if($Object.pwdLastSet) {
                $pwdLastSet = [datetime]::FromFileTime($Object.pwdLastSet)
            } else {
                [string]$pwdLastSet = "NeverSet"
                $Compliant = $false
                $FailedChecks += "PwdLastSetNever"
            }

            if($pwdLastSet -lt $pwddate) {
                $Compliant = $false
                $FailedChecks += "PwdLastSetTooLongAgo($pwdLastSet<$pwddate)"
            }
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
                $clearedExtensionAttribute9++
            }

            #If description matches stamped description, remove
            if ($Object.description -eq $disableDescription) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear description
            }

            $foundCompliantObjectCount++

            

        } else {
        
            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADUser -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9=$TodayTimeStamp}
                $EA9date=$today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }

            #Calculate DeleteDate based on EA9 Date
            $deletedate = $EA9date.AddDays($deleteGracePeriod)

            if(!([string]$failedchecks -eq "DescriptionIsDisableMessage")) {
                #Disable and stamp description
                if($today -ge $MTOComplianceDate -and $live) {
                    Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Description $disableDescription
                    Disable-ADAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator
                }

                #Delete if after timeline
                if($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                    Remove-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                    $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'Service Account' -DeleteReason ($FailedChecks -join ", ")
                }
            }

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA7Split,EA7date,EA9date,EA6Split,EA6date,pwdLastSet -EA SilentlyContinue
    }

    if($Domain.Name -ne 'AREA42') {
        $statistics+=Export-Statistics -Base $BaseName -ObjectType 'Service Accounts'
    }

    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'Service Accounts'
}

#Managed Service Accounts
try{
    $managedSVCOU=Get-ADObject "CN=Managed Service Accounts,$($Domain.DistinguishedName)" -Server $Domain.PDCEmulator
    [Int]$NonCompliantObjectCount = 0
    [Int]$CompliantObjectCount = 0
    [Int]$ObjectCount = 0
    
    #setup counting for compliance stats
    $foundNonCompliantObjectCount = 0
    $foundCompliantObjectCount = 0
    $foundObjectCount = 0
    
    $baseName = $managedSVCOU.Name; Write-Debug ("Base Name: " + $baseName)

    #grab all service accounts in OU
    [array]$ObjectDE = Get-ADServiceAccount -Filter * -SearchBase $managedSVCOU.DistinguishedName -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Account: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #TO 00-33D-2001 Section 4.16.1
        if([string]::IsNullOrEmpty($Object.Description)) {
            $Compliant = $false
            $FailedChecks += "DescriptionIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.16.2
        if($Object.extensionAttribute7 -match "^Acct Validated [0-9]{8} by ") {
            $EA7Split = ($Object.extensionAttribute7 -Split " ")[2]
            [datetime]$EA7date = $EA7Split.Substring(4,2) + "/" + $EA7Split.Substring(6,2) + "/" + $EA7Split.Substring(0,4)

            if($EA7date -lt $IAValidationDate) {
                $Compliant = $false
                $FailedChecks += "IAValidationTooLongAgo($EA7date<$IAValidationDate)"
            }
        } else {
            $Compliant = $false
            $FailedChecks += "EA7ValidationIsNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.16.3
        if([string]::IsNullOrEmpty($Object.l)) {
            $Compliant = $false
            $FailedChecks += "CityIsNullOrEmpty"
        } 

        #TO 00-33D-2001 Section 4.16.4
        if([string]::IsNullOrEmpty($Object.o)) {
            $Compliant = $false
            $FailedChecks += "OrgIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.16.5
        if([string]::IsNullOrEmpty($Object.physicalDeliveryOfficeName)) {
            $Compliant = $false
            $FailedChecks += "OfficeIsNullOrEmpty"
        }

        #TO 00-33D-2001 Section 4.16.6
        if($Object.telephoneNumber -notmatch "^\d{3}-\d{3}-\d{4}$") {
            $Compliant = $false
            $FailedChecks += "TelephoneNumberNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.16.7
        if($Object.extensionAttribute8 -notmatch "CRQ\d{12}|WO\d{13}") {
            $Compliant = $false
            $FailedChecks += "EA8CRQNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.16.8
        if($Object.extensionAttribute13 -notmatch "@mail\.smil\.mil$") {
            $Compliant = $false
            $FailedChecks += "EA13EmailNullOrEmptyOrInvalidFormat"
        }

        #TO 00-33D-2001 Section 4.16.9
        if(!($Object.PrincipalsAllowedToRetrieveManagedPassword)) {
            $Compliant = $false
            $FailedChecks += "PrincipalsAllowedToRetrieveManagedPasswordFalse"
        }

        #TO 00-33D-2001 Section 4.16.10
        if($Object.employeeType -ne "S") {
            $Compliant = $false
            $FailedChecks += "EmployeeTypeNotS"
        }

        #TO 00-33D-2001 Section 4.16.11
        if($Object.extensionAttribute3 -ne "SVC") {
            $Compliant = $false
            $FailedChecks += "EA3ExemptionTypeNotSVC"
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if($Object.extensionAttribute9) {
                Set-ADServiceAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
                $clearedExtensionAttribute9++
            }

            #If description matches stamped description, remove
            if($Object.description -eq $disableDescription) {
                Set-ADServiceAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear description
            }

            $foundCompliantObjectCount++

        } else {
        
            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADServiceAccount -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9=$TodayTimeStamp}
                $EA9date=$today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }

            #Calculate DeleteDate based on EA9 Date
            $deletedate = $EA9date.AddDays($script:deleteGracePeriod)

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA7Split,EA7date,EA9date,EA6Split,EA6date -EA SilentlyContinue
    }
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount

    $statistics+=Export-EnterpriseStats -ObjectType 'Managed Service Accounts'
} catch {
    Write-Warning 'Managed Service Accounts container does not exist.'
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