<#
.SYNOPSIS
  Initial script for launching MTO 2021-222-001 compliance scans.
.DESCRIPTION
  This script will load all global functions and variables, mirror the scripts on the ACC
  Netlogon to maintain the most up to date version then call the other scripts. Once the
  other scripts finish the returned results are published in the overall compliance stats
  report.
.INPUTS
  None
.OUTPUTS
  Overall Compliance Stats report stored in Netlogon\NonCompliance\
.NOTES
  Version:        1.2
  Author:         CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
  CoAuthors:      STEELE, CHRISTOPHER M CTR USAF ACC 83 NOS/CYOD
                  Estep, Jonathan K CTR USAF ACC 83 NOS/CYOD
  Creation Date:  15 June 2021
  Edit Date:      25 Jan 2022
  Purpose/Change: Added Debugging, added a "fail mode" to prevent accidental strikes and alert us when a problem occurs.
  ToDo List: 
    - Maybe more logs
.CHANGELOG
  8/26/2021 - Michael Calabrese - Updated to only keep one Compliance Stats report a day
  12/6/2021 - Michael Calabrese - Merged update scripts with trigger scripts.
  1/10/2022 - Michael Calabrese - Changed the regex that moves daily compliance numbers
    to allow 00-02 for scans that run long.
  1/12/2022 - Michael Calabrese - Major cleanup, centralized and standardized functions.
    Centralized some variables. Added FailReason column as requested by Eric Fong.
#>

##Shows debug when running interactively##
if($host.Name -match 'ISE') {
    $Global:DebugPreference = "Continue"
    $ThisScriptPath = $psISE.CurrentFile.FullPath
} else {
    $ThisScriptPath = $PSCommandPath
}

#region Functions
function Execute-Scans ([Bool]$Live) {
    <#This function handles the scans and the reports. 
    Loses a little granularity since all forms are either on or off but it seems the 616 wants it that way.#>

    <#Move the first compliance stat of the day. Regex matching a report with the hours
    of 0-2 to account for extremely long running scans (ACC mostly).#>
    Get-ChildItem "E:\Windows\SYSVOL\domain\scripts\NonCompliance\*.csv" |
        Where-Object {$_.Name -match "0[0-2]\d{2} Compliance\ Stats\.csv$"} |
        Copy-Item -Destination "E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive" -Force

    #Find old compliance stats report and hold for later.
    $oldreport=Get-ChildItem "E:\Windows\SYSVOL\domain\scripts\NonCompliance\*Compliance Stats.csv"

    Set-Location E:\Windows\SYSVOL\domain\scripts\NonCompliance\Scripts
    [Array]$complianceStatsReport=@()

    #Trigger scripts that run on all domains.
    $complianceStatsReport+=.\Get-NonCompliantAdminAccounts.ps1 -Live $live
    $complianceStatsReport+=.\Get-NonCompliantServiceAccounts.ps1 -Live $live

    <#Trigger scripts that run outside of AREA42. These objects currently don't exist on that domain.
    If that changes, move the line to the block above.#>
    if($Domain.Name -ne 'AREA42'){
        $complianceStatsReport+=.\Get-NonCompliantComputers.ps1 -Live $live
        $complianceStatsReport+=.\Get-NonCompliantGroups.ps1 -Live $live
        $complianceStatsReport+=.\Get-NonCompliantRoleAccounts.ps1 -Live $live
        $complianceStatsReport+=.\Get-NonCompliantUserAccounts.ps1 -Live $live
    }

    #Export the overall compliance report
    $complianceStatsReport | Sort-Object -Property Base,'Object Type' | 
        Export-Csv -NoTypeInformation "$script:reportPath$(Get-Date -Format "yyyyMMdd HHmm") Compliance Stats.csv"

    #Remove the old report from the folder.
    $oldreport | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Global:Export-DeletedObject ([String]$CN,[String]$Base,[String]$ObjectType,[String]$DeleteReason) {
    #This function returns information on objects that are deleted for logging purposes.

    #Create object to export information
    $export = [PSCustomObject]@{
    'Object CN' = $CN
    'Base' = $Base
    'Object Type' = $ObjectType
    'Deletion Date' = $today.ToShortDateString()
    'Deletion Reason' = $DeleteReason
    }

    return $export
}

function Global:Export-EnterpriseStats ([String]$ObjectType) {
    #This function returns the domain level compliance percentage for a given object type.

    #Calculate percentage compliant
    if($script:ObjectCount -eq 0){
        $percentage="N/A"
    } else {
        $percentage="{0:N2}" -f (($script:CompliantObjectCount / $script:ObjectCount) * 100) + "%"
    }

    #Create object to export information
    $statline = [PSCustomObject]@{
    'Base'="$($Domain.name.ToUpper()) Overall"
    'Object Type'=$ObjectType
    'Total'="{0:N0}" -f $script:ObjectCount
    'Compliant'="{0:N0}" -f $script:CompliantObjectCount
    'Percent Compliant'=$percentage
    }

    return $statline
}

function Global:Export-Statistics ([String]$Base,[String]$ObjectType) {
    #This function returns the base level compliance percentage for a given object type.

    #Calculate percentage compliant
    if($script:foundObjectCount -eq 0){
        $percentage="N/A"
    } else {
        $percentage="{0:N2}" -f (($script:foundCompliantObjectCount / $script:foundObjectCount) * 100) + "%"
    }

    #Create object to export information
    $statline = [PSCustomObject]@{
    'Base'=$Base
    'Object Type'=$ObjectType
    'Total'="{0:N0}" -f $script:foundObjectCount
    'Compliant'="{0:N0}" -f $script:foundCompliantObjectCount
    'Percent Compliant'=$percentage
    }

    return $statline
}
#endregion Functions

#Variables
$Global:Domain=Get-ADDomain -Current LocalComputer
[String]$MTOName='MTO 2021-222-001A'
[String]$ACCPath = '\\acc.accroot.ds.af.smil.mil\netlogon\'
[String]$reportPath="E:\Windows\SYSVOL\domain\scripts\NonCompliance\"

<#This try loop is to allow the scripts to run in a "fail mode" when communication to ACC fails.
This prevents the scripts from continuing to strike if we have turned it off and the update fails to replicate.
This also prevents striking based on old criteria if scripts cannot be updated.#>
try {

    #Get the authoritative copy from ACC and compare to this script
    $TriggerScriptAuth = Get-FileHash (Join-Path $ACCPath 'NonCompliance\Scripts\Trigger-Scripts.ps1') -Algorithm SHA256 -ErrorAction Stop
    $ThisScript = Get-FileHash $ThisScriptPath -Algorithm SHA256
    $compareThisResult = $TriggerScriptAuth.Hash -eq $ThisScript.Hash

    if ($Domain.Name -ne 'ACC') {

        #Update the administration scripts on Non-ACC domains
        $ADMscriptsrc=$ACCPath + "Administration_Scripts"
        $ADMscriptpath="E:\Windows\SYSVOL\domain\scripts\Administration_Scripts"
        Robocopy.exe $ADMscriptsrc $ADMscriptpath /MIR

        #Update the NonCompliance scripts on Non-ACC domains
        $NCscriptSRC=$ACCPath + "NonCompliance\Scripts"
        $NCscriptpath="E:\Windows\SYSVOL\domain\scripts\NonCompliance\Scripts"
        Robocopy.exe $NCscriptSRC $NCscriptpath /MIR

        if ($domain.Name -ne 'AREA42') {

            #Update the IAO scripts on Non-ACC domains
            $IAOscriptsrc=$ACCPath + "IAO_Scripts"
            $IAOscriptpath="E:\Windows\SYSVOL\domain\scripts\IAO_Scripts"
            Robocopy.exe $IAOscriptsrc $IAOscriptpath /MIR
        }
    }

    if(!($compareThisResult)) {
        #Script did not match authoritative copy. Close and run authoritative copy.
        Write-Warning 'Script did not match the source!'
        Start-Process powershell.exe -ArgumentList "-File $ThisScriptPath"
        Exit
    }

    $Success=$true
} catch {

    <#If the script fails to run the above commands it will fail to this section.
    An email will be sent warning of the failure and giving a brief description of the error.
    The scripts will be run without live mode enabled to prevent accidental strikes.#>
    
    #Send email to the DS OrgBox
    Send-MailMessage -Body "PDC: $env:COMPUTERNAME`nDomain: $($domain.DNSRoot)`nBaseName:$BaseName`nError Message:`n$($_ | Out-String)" `
        -From "$MTOName Reports Error_Notifier@mail.smil.mil" `
        -SmtpServer "smtp.mail.smil.mil" `
        -Subject "$MTOName Script Error!! $env:COMPUTERNAME.$($domain.DNSRoot)" `
        -To 'usaf.jble.83nos.mbx.83-nos-cyod-dir-srvs@mail.smil.mil', 'usaf.jble.83nos.list.directory-services-operators@mail.smil.mil' `
        -Priority High
}

if($Success) {
    #Check AD Delegation Version
    $delegationScript = Get-ChildItem -Path "E:\Windows\SYSVOL\domain\scripts\NonCompliance\Scripts\Set-Delegation*.ps1"
    $DelegationLog = Get-Content "E:\Windows\SYSVOL\domain\scripts\delegation.version" -ErrorAction SilentlyContinue
    if($null -eq $DelegationLog -or $DelegationLog -ne $delegationScript.BaseName) {
        Invoke-Expression $delegationScript.FullName
    }

    #Temp, fix deletedObjects.csv
    if(Test-Path 'E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive\DeletedObjects.csv') {
        $CSV = Import-Csv 'E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive\DeletedObjects.csv'
        $CSV | Export-Csv "E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive\!DeletedObjects_$($Domain.Name.ToUpper()).csv" -NoTypeInformation -Force

        Remove-Item 'E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive\DeletedObjects.csv' -Force
        Remove-Item "E:\Windows\SYSVOL\domain\scripts\NonCompliance\Compliance Archive\DeletedObjects_$($Domain.Name.ToUpper()).csv" -Force
    }

    if ($live) {.\Cleanup-TransientUsers.ps1}

    Execute-Scans -Live $true
    #Execute-Scans -Live $false #If we need to disable the strikes again.
} else {
    Execute-Scans -Live $false
}