<#
.SYNOPSIS
  MTO 2021-222-001 computer compliance scans.
.DESCRIPTION
  This script will scan the Bases OU for computer objects then compare
  their compliance with the MTO. It then publishes a report to Netlogon.
  Currently exempting PMO systems for SDC version.

  ExtensionAttribute10 exempts SDC Ver only.
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\Computers_<DomainName>.csv
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
  v2.0.0 - Chris Steele - Added 30 day grace period for workstations build version
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

    #Ever Domain Joined?
    if ($NonCompObj.lastLogonTimestamp) {
        $domainjoined="Yes"
    } else {
        $domainjoined="No"
    }

    #Create object to export information
    $export=[PSCustomObject]@{
    'Common Name'=[string]$NonCompObj.CN
    'Location'=[string]$script:BaseName
    'Last Logon'=$lastlogin
    'Joined to Domain'=[string]$domainjoined
    'Possible Physical Location'=[string]$NonCompObj.Location
    'Build Version'=[string]$NonCompObj.info
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
$reportname="Computers_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$creationdate=$today.AddDays(-90); Write-Debug ("Creation Date Req: " + $creationdate)
$logondate=$creationdate.ToFileTime(); Write-Debug ("Logon Date Req: " + $logondate)
$domjoingrace=$today.AddDays(-30); Write-Debug ("Domain Join Date Req: " + $domjoingrace)
$deleteGracePeriod = 90
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_COMP,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

#Control Variables
[version]$requiredbuildver="10.0.18363"
[String]$MinSDCName = 'SDC 10.1909'

#Begin Logic
[Array]$OUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Bases,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator
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
    $global:baseName=$OU.Name; Write-Debug ("Base Name: " + $baseName)
    
    #EXTREMELY TEMPORARY
    if ($baseName -eq "SDDC") {continue}
    
    #grab all computers in OU
    [array]$ObjectDE=Get-ADComputer -Filter * -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Computer: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########
        
        #Created 30+ days ago
        if ($Object.whenCreated -le $domjoingrace) {
            #And not joined to the domain
            if (!$Object.lastLogonTimestamp) {
                $Compliant = $false
                $FailedChecks += "ComputerCreatedAndNotDomainJoined"
            }

            #Last logged in 90+ days ago
            if (($Object.lastLogonTimestamp -le $logondate) -and ($Object.whencreated -le $creationdate)) {
                $Compliant = $false
                $FailedChecks += "LastLogonTooLongAgo(<$([datetime]::FromFileTime($logondate).tostring("MM/dd/yyyy")))"
            }

            #Build Version < Required Version
            if($Object.extensionAttribute10 -match "[0-9]{8}") {
                [datetime]$EA10date = $Object.extensionAttribute10.Substring(4,2) + "/" + $Object.extensionAttribute10.Substring(6,2) + "/" + $Object.extensionAttribute10.Substring(0,4)
                if($EA10date -gt $today) {
                    #still exempt, skip
                    Continue
                }
            } elseif( $($Object.distinguishedName) -notmatch "OU=PMO") {
                [version]$initialVersion=$object.OperatingSystemVersion.Replace(' ','.').Replace('(','').Replace(')','')
                [version]$putBuildVersion=$Object.info

                if($null -eq $putBuildVersion) {
                    #If there's no data populated by GPO-DO-C-AFNET S-Populate Computer Build Number, check OSV attribute only.
                    if($initialVersion -lt $requiredbuildver) {
                        $Compliant = $false
                        $FailedChecks += "SDCVersionTooOld(<$MinSDCName)"
                    }
                } elseif($putBuildVersion -lt $requiredbuildver) {
                    #If there is data, we should assume this is more up to date
                    $Compliant = $false
                    $FailedChecks += "SDCVersionTooOld(<$MinSDCName)"
                }
            }
        }

        ######### END NONCOMPLIANT CRITERIA #########

        if ($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADComputer -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
            }

            #If stamped description, remove
            if ($Object.description -eq $disableDescription) {
                Set-ADComputer -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear description
            }

            $foundCompliantObjectCount++

        } else {
        
            #Add object to the group
            Add-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator
        
            #Check if EA9 is already stamped
            if ([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

                #Stamp EA9
                Set-ADComputer -Identity $($Object.DistinguishedName) -Server $Domain.PDCEmulator -Add @{extensionAttribute9="$TodayTimeStamp"}
                $EA9date = $today
            } else {
                #Grab the date in EA9
                $EA9date=[datetime]::ParseExact($($Object.extensionAttribute9),"yyyyMMdd",$null)
            }

            #Calculate the deletedate based on EA9 Date
            $deletedate = $EA9date.AddDays($deleteGracePeriod)

            #Disable and stamp description
            if($today -ge $MTOComplianceDate -and $live) {
                Set-ADComputer -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Description $disableDescription
                Disable-ADAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator
            }

            #Delete if after timeline
            if($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                Remove-ADComputer -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'Computer' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object -NonCompObj $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA9date -EA SilentlyContinue
    }

    $statistics+=Export-Statistics -Base $baseName -ObjectType Computers
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType Computers
}

#publish report to netlogon
Move-Item "$reportpath$reportname" -Destination "$reportpath\Compliance Archive" -Force
$report |Sort-Object Location,'Common Name' | Export-Csv -Path "$reportpath$reportname" -NoTypeInformation -Force

#Log deleted objects
if($Deleted) {
    $Deleted | Export-Csv "$reportpath\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv"-NoTypeInformation -Append
}

#Return the stats to the calling script
Return $statistics