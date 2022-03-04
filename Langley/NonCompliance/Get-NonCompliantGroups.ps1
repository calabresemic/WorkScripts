<#
.SYNOPSIS
  MTO 2021-222-001 group compliance scans.
.DESCRIPTION
  This script will scan the Bases OU for group objects then compare
  their compliance with the MTO. It then scans the Administrative Groups OU
  for group objects and compares their compliance with the MTO. THERE ARE TWO
  SEPARATE LOOPS IN THIS SCRIPT. It publishes a combined report to Netlogon.

  ExtensionAttribute10 exempts nothing.
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\Groups_<DomainName>.csv
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

    #Create object to export information
    $export=[PSCustomObject]@{
    'Common Name'=[string]$NonCompObj.CN
    'Display Name'=[string]$NonCompObj.DisplayName
    'Manager'=[string]$NonCompObj.ManagedBy
    'Member Count'=[string]$NonCompObj.members.Count
    'Location'=[string]$script:BaseName
    'Group Type'=$script:GroupType
    'Group Scope'=$NonCompObj.GroupScope
    'Group Category'=$NonCompObj.GroupCategory
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
$reportname="Groups_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$deleteGracePeriod = 90
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_GRP,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

#Control Variables
$ExemptGroupNames = "_IAO_AdminVerification$|_CFP-CSA$|_DHCP$|ScriptAdmins$|AdminUser_STIG_Preview$"
$ExemptOUNames = "^_Enterprise$|^_ESU Groups$|^_INOSC Groups$|PMO"

#Begin Logic
[Array]$OUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator
[String]$GroupType = 'BaseLevel Groups'
Write-Debug ($GroupType + " OUs Found: " + $OUs.Count)
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
    [array]$ObjectDE = Get-ADGroup -Filter * -searchbase $baseDN -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Group: " + $Object.CN)
        
        if(($Object.Name -match $ExemptGroupNames) -or ($Object.SamAccountName -match $ExemptGroupNames)) {
            #if group exempted, skip 
            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
            }
            continue
        }

        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount ++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #No Manager
        if(!$Object.ManagedBy) {
            $Compliant = $false
            $FailedChecks += "NoManager"
        }

        #No Members
        if(!$Object.Members) {
            $Compliant = $false
            $FailedChecks += "NoMembers"
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
            }

            $foundCompliantObjectCount++

        } else {
        
            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADGroup -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9="$TodayTimeStamp"}
                $EA9date = $today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }
            #Calculate DeleteDate based on EA9 Date
            $deletedate = $EA9date.AddDays($deleteGracePeriod)

            #Delete if after timeline
            if ($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                Remove-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'BaseLevel Group' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA9date -EA SilentlyContinue
    }

    $statistics+=Export-Statistics -Base $baseName -ObjectType 'BaseLevel Groups'
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'BaseLevel Groups'
}

[Array]$admOUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator | Where-Object {$_.Name -notmatch $ExemptOUNames}
[String]$GroupType = 'AdminLevel Groups'
Write-Debug ($GroupType + " OUs Found: " + $OUs.Count)
[Int]$NonCompliantObjectCount = 0
[Int]$CompliantObjectCount = 0
[Int]$ObjectCount = 0

ForEach ($OU in $admOUs) {
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
    [array]$ObjectDE = Get-ADGroup -Filter * -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Group: " + $Object.CN)

        if(($Object.Name -match $ExemptGroupNames) -or ($Object.SamAccountName -match $ExemptGroupNames)){
            #if group exempted, skip 
            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
            }
            continue
        }

        $Compliant = $true
        $FailedChecks=@()
        $foundObjectCount ++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        #No Manager
        if(!$Object.ManagedBy) {
            $Compliant = $false
            $FailedChecks += "NoManager"
        }

        #No Members
        if(!$Object.Members) {
            $Compliant = $false
            $FailedChecks += "NoMembers"
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if($Object.extensionAttribute9) {
                Set-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
            }

            $foundCompliantObjectCount++

            }
        Else {
        
            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADGroup -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9="$TodayTimeStamp"}
                $EA9date = $today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }
            #Calculate DeleteDate based on EA9 Date
            $deletedate = $EA9date.AddDays($deleteGracePeriod)

            #Delete if after timeline
            if($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                Remove-ADGroup -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'AdminLevel Group' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA9date -EA SilentlyContinue
    }
    
    $statistics+=Export-Statistics -Base $baseName -ObjectType 'AdminLevel Groups'
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'AdminLevel Groups'
}

#publish report to netlogon
Move-Item "$reportpath$reportname" -Destination "$reportpath\Compliance Archive" -Force
$report | Sort-Object Location,'Group Type','Common Name' | Export-Csv -Path "$reportpath$reportname" -NoTypeInformation -Force

#Log deleted objects
if($Deleted) {
    $Deleted | Export-Csv "$reportpath\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv" -NoTypeInformation -Append
}

#Return the stats to the calling script
Return $statistics