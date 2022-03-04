<#
.SYNOPSIS
  MTO 2021-222-001 admin account compliance scans.
.DESCRIPTION
  This script will scan the Administrative Accounts OU for user objects then compare
  their compliance with the MTO. It then publishes a report to Netlogon.

  ExtensionAttribute10 exempts SCL required but enforces password last set.
.PARAMETER Live
  Allows us to tell the scripts to run in live mode or not. Live will disable/delete.
.INPUTS
  None
.OUTPUTS
  NonCompliant Objects stored in Netlogon\NonCompliance\AdminAccounts_<DomainName>.csv
  Deleted Objects stored in Netlogon\NonCompliance\Compliance Archive\DeletedObjects.csv
.NOTES
  Version:        2.3
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
  v2.1 Updated the variables to be worded better, updated the MTO Name to be a variable to account for changes in rev.
  v2.2 - Michael Calabrese - MTO Rev A, date and name change.
  v2.2.1 - Michael Calabrese - ^38 ES$|^AFNIC$ were added to exemptedusermatch to fix area42 accounts.
  v2.2.2 - Michael Calabrese - Fixed formatting and EA9 flagging
#>

Param(
    #If live is not set to true by the Trigger-Scripts.ps1, it defaults to false.
    #Please don't change this behavior.
    [Bool]$Live = $false
)

function Export-Object ($NonCompObj,[String]$FailReasons) {
    
    #Check if Admin is NOS/COS User exempted
    if($script:BaseName -match $script:ExemptedUserMatch){
        $userCommonName="Exempted User Account Criteria"
        $userLoc="Exempted User Account Criteria"
    } else {
        $userCommonName=$script:userCN
        $userLoc=$script:UserLocation
    }
    
    #Handle the default 12/31/1600 date
    if([String]::IsNullOrEmpty($NonCompObj.lastLogonTimestamp)) {
        $lastlogin = 'Never Logged In'
    } else {
        $lastlogin=([datetime]::FromFileTime($NonCompObj.lastLogonTimestamp)).toshortdatestring()
    }

    #Create object to export information
    $export=[PSCustomObject]@{
        'User Common Name' = $userCommonName
        'User Location' = $userLoc
        'Admin Common Name' = $NonCompObj.CN
        'Admin UPN' = [string]$NonCompObj.UserPrincipalName
        'Admin Sam' = [string]$NonCompObj.samAccountName
        'Admin Location' = [string]$script:BaseName
        'Admin Last Logon' = $lastlogin
        'Admin Validation' = [string]$NonCompObj.extensionAttribute7
        'Admin SCL Required' = [string]$NonCompObj.SmartcardLogonRequired
        'Admin SCL Exemption' = [String]$NonCompObj.extensionAttribute10
        'Admin Password Last Set' = [string]$script:pwdLastSet
        'Non Compliance Date' = $script:EA9date.toshortdatestring()
        'Pending Deletion Date' = $script:EA9date.Adddays($script:deleteGracePeriod).toshortdatestring()
        'Fail Reasons' = $FailReasons
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
$reportname="AdminAccounts_$($Domain.Name.ToUpper()).csv"; Write-Debug ("Report Name: " + $reportname)
$pwddate=$today.AddDays(-60); Write-Debug ("PasswordLastSet Date Req: " + $pwddate)
$creationdate=$today.AddDays(-45); Write-Debug ("Creation Date Req: " + $creationdate)
$logondate=$creationdate.ToFileTime(); Write-Debug ("Logon Date Req: " + $logondate)
$IAValidationDate=$today.AddDays(-365); Write-Debug ("IA Validation Date Req: " + $IAValidationDate)
$deleteGracePeriod = 45
$nonCompliantGroup = "CN=$($Domain.Name)_NONCOMPLIANT_ADM,OU=_ESU Groups,OU=Administrative Groups,OU=Administration,$($Domain.DistinguishedName)"

#Control Variables
$ExemptedUserMatch="^83 NOS$|^561 NOS$|^690 COS$|^691 COS$|^38 ES$|^AFNIC$"

#Begin Logic
[Array]$OUs=Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Administrative Accounts,OU=Administration,$($Domain.DistinguishedName)" -SearchScope OneLevel -Server $Domain.PDCEmulator
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
    
    #grab all accounts in OU
    [array]$ObjectDE = Get-ADUser -Filter * -SearchBase $baseDN -Properties * -Server $Domain.PDCEmulator

    foreach ($Object in $ObjectDE) {
        Write-Debug ("Account: " + $Object.CN)
        $Compliant = $true
        $FailedChecks=@()
        $NextRevisionChecks=@()
        $foundObjectCount++

        ######### BEGIN NONCOMPLIANT CRITERIA #########

        if($baseName -notmatch $ExemptedUserMatch) {

            <# Reserved for MTO 2021-222-001B

            #Match to same role at same base
            $gigID=($Object.CN.Split('.') | Select-Object -First 2 -Skip 3) -join ''
            [array]$user=Get-ADUser -Filter {gigID -eq $gigID} -SearchBase "OU=Bases,$($Domain.DistinguishedName)" -Properties CN

            if($user.Count -gt 1) {

                #If more than one account with the same gigID, non-compliant
                $userlocation=($user | %{ ($user.distinguishedname.Split(',') | where {$_ -like "OU*"} | select -Last 1 -Skip 1).replace("OU=","")}) -join ','
                $userCN=$user.cn -join ','
                $Compliant = $false
                $FailedChecks += "MoreThan1AccountWithUserGigID"

            } elseif($user.count -eq 1) {

                $userlocation=($user.distinguishedname.Split(',') | where {$_ -like "OU*"} | select -Last 1 -Skip 1).replace("OU=","")
                $userCN=$user.cn
                if($userlocation -ne $BaseName) {
                    $Compliant = $false
                    $FailedChecks += "UserAccountNotAtSameBaseAsAdminAccount($userlocation <> $BaseName)"
                }
            } else {
                $UserLocation=$userCN="No User Found"
            }
            #>

            #Matching User Accounts to Admin Accounts the hard way for now

            #grab the first 10 numbers from UPN
            $EDI = [regex]::match($Object.UserPrincipalName,"^1\d{9}").value + "*"

            #if no EDI then unable to find user
            if($EDI -eq '*') {
                $Compliant = $false
                $FailedChecks += "NoMatchingUserAccountFound"
                $UserLocation=$userCN="No User Found"
                Remove-Variable user -ErrorAction SilentlyContinue
            } else {

                #Find User Account at same base
                #Grab PCC from name, but remember some users won't have Middle Initials
                if ($Object.name -match "^\w+\.\w+\.(\w\.)??(\w+\.)??1\d{9}\.\w") {
                    $PCC = $Object.name.split(".")[3..99] | where {$_ -match "^\w$"}
                }
                #If name not configured right, make sure samaccountname is in <EDIPIPCC>.AD<role> format, and grab the PCC
                if (!$PCC -and $Object.samaccountname -match "^1\d{9}\w\.AD") {
                    $PCC = $Object.samaccountname[10]
                }
                try {
                    $user=Get-ADUser -Filter {UserPrincipalName -like $EDI} -SearchBase "OU=$($basename) Users,OU=$($basename),OU=Bases,$($Domain.DistinguishedName)" -Properties CN -Server $Domain.PDCEmulator -ErrorAction Stop |
                        Where-Object {$_.userprincipalname.split("@")[0] -Match $PCC} | Select-Object -First 1
                    #$userlocation=(($user.DistinguishedName).Split(',') | where {$_ -like "OU=*"} | select -First 1 -Skip 1).replace('OU=','')
                    #$userlocation=($user.DistinguishedName).Split(',')[2].split("=")[1].split(" ")[0]
                    $userlocation=($user.DistinguishedName).replace(",OU=Bases,$($Domain.DistinguishedName)","").split("=") | select -Last 1
                    $userCN=$user.cn
                } catch {

                    #No Corresponding User Account
                    $Compliant = $false
                    $FailedChecks += "NoMatchingUserAccountFound"
                    $UserLocation=$userCN="No User Found"
                }
            }
        }

        # Last Logon
        if (($Object.lastlogontimestamp -lt $logondate) -and ($Object.whencreated -lt $creationdate)) {
            $Compliant = $false
            $FailedChecks += "LastLogonTooLongAgo(<$([datetime]::FromFileTime($logondate).tostring("MM/dd/yyyy")))"
        }

        #IA Validation
        if($Object.extensionAttribute7 -match "^Acct Validated \d{8} by ") { 
            
            #If EA7 is properly populated, calculate the date
            $EA7Split = ($Object.extensionAttribute7 -Split " ")[2]
            [datetime]$EA7date = $EA7Split.Substring(4,2) + "/" + $EA7Split.Substring(6,2) + "/" + $EA7Split.Substring(0,4)

            #Compare the date to the criteria
            if($EA7date -lt $IAValidationDate) {
                $Compliant = $false
                $FailedChecks += "IAValidationTooLongAgo($EA7date<$IAValidationDate)"
            }
        } else {

            #EA7 doesn't match or isn't formatted correctly
            $Compliant = $false
            $FailedChecks += "IAValidationNullOrEmptyOrInvalidFormat"
        }

        #SCL Exemption
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

        ######### END NONCOMPLIANT CRITERIA ##########

        if ($Compliant) {

            #Remove the object from the group
            Remove-ADGroupMember -Identity $nonCompliantGroup -Members $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false

            #If stamped EA9, remove
            if ($Object.extensionAttribute9) {
                Set-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Clear extensionAttribute9
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
            if ([string]::IsNullOrEmpty($Object.extensionAttribute9)) {

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
                Set-ADUser -Identity $($Object.distinguishedName) -Description $disableDescription -Server $Domain.PDCEmulator
                Disable-ADAccount -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator
            }

            #Delete if after timeline
            if($today -ge $deletedate -and $today -ge $MTOComplianceDate -and $live) {
                Remove-ADUser -Identity $($Object.distinguishedName) -Server $Domain.PDCEmulator -Confirm:$false
                $Deleted+=Export-DeletedObject -CN $Object.CN -Base $baseName -ObjectType 'Admin Account' -DeleteReason ($FailedChecks -join ", ")
            }

            $report+=Export-Object -NonCompObj $Object -FailReasons ($FailedChecks -join ", ")
            $foundNonCompliantObjectCount++
        }
        Remove-Variable deletedate,EA7Split,EA7date,EA9date,EA10date,EA6Split,EA6date,EDI,user,userlocation,usercn,pwdLastSet,PCC,Object -EA SilentlyContinue
    }

    $statistics+=Export-Statistics -Base $baseName -ObjectType 'Admin Accounts'
    $NonCompliantObjectCount += $foundNonCompliantObjectCount
    $CompliantObjectCount += $foundCompliantObjectCount
    $ObjectCount += $foundObjectCount
}

#publish overall stats to report
if($Domain.ParentDomain -ne 'pacaf.ds.af.smil.mil') {
    $statistics+=Export-EnterpriseStats -ObjectType 'Admin Accounts'
}

#publish report to netlogon
Move-Item "$reportpath$reportname" -Destination "$reportpath\Compliance Archive" -Force
$report | Sort-Object 'Admin Location','Admin Common Name' | Export-Csv -Path "$reportpath$reportname" -NoTypeInformation -Force

#Log deleted objects
if($Deleted) {
    $Deleted | Export-Csv "$reportpath\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv" -NoTypeInformation -Append
}

#Return the stats to the calling script
Return $statistics