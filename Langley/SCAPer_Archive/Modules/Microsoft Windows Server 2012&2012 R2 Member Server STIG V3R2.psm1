<#
Module Created by Michael Calabrese (1468714589)
Designed to be used with SCAPer script v5+

Microsoft Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide :: Version 3, Release: 2 Benchmark Date: 04 May 2021
#>

#V-225243
#Windows 2012/2012 R2 password for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.
Function SV-225243r569185_rule { 
    if($Global:Admin.PasswordLastSet -gt (Get-Date).AddYears(-1)){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Technician should change the local admin password.'}
        }
    }

#V-225245
#Members of the Backup Operators group must be documented.
Function SV-225245r569185_rule { 
    #We shouldn't have any one in our groups. I will adjust accordingly if needed.
    if(!(Get-LocalGroupmember 'Backup Operators')){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225246
#Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.
Function SV-225246r569185_rule { 
    #We shouldn't have any one in our groups. I will adjust accordingly if needed.
    if(!(Get-LocalGroupmember 'Backup Operators')){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225255
#The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
Function SV-225255r569185_rule { 
    #Manual review required, even if AppLocker is used
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225258
#The Windows 2012 / 2012 R2 system must use an anti-virus program.
Function SV-225258r569185_rule { 
    if ($Global:installedprograms.displayname -contains "mcafee agent") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225259
#The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2.
Function SV-225259r569185_rule { 
    $Value1 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
    $Value2 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\" "DependOnService"
    if ($Value1 -eq "4" -and $value2.Count -eq 3 -and $value2 -contains "Bowser" -and $value2 -contains "MRxSmb20" -and $value2 -contains "NSI") {$73523 = $true}

    $Value3 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
    if ($Value3 -eq "0") {$73519 = $true}

    if($73523 -eq $true -and $73519 -eq $true){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225260
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.
Function SV-225260r569185_rule { 
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Configure SMBv1 Server" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225261
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.
Function SV-225261r569185_rule { 
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Configure SMBv1 client (extra setting needed for pre-Win8.1/2012R2)" to "Enabled" with the following three lines of text entered for "Configure LanmanWorkstation Dependencies":
    #Bowser
    #MRxSmb20
    #NSI
    $Value1 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
    $Value2 = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\" "DependOnService"
    if ($Value1 -eq "4" -and $value2.Count -eq 3 -and $value2 -contains "Bowser" -and $value2 -contains "MRxSmb20" -and $value2 -contains "NSI") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225262
#Orphaned security identifiers (SIDs) must be removed from user rights on Windows 2012 / 2012 R2.
Function SV-225262r569185_rule { 
    #Check RSOP for deleted accounts
    if($Global:UserRights.Accountlist -match "S-\d-\d+-(\d+-){1,14}\d+"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225263
#Windows PowerShell must be updated to a version that supports script block logging on Windows 2012/2012 R2.
Function SV-225263r569185_rule { 
    #If this script is running this is PowerShell v5+
    return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
    }

#V-225264
#PowerShell script block logging must be enabled on Windows 2012/2012 R2.
Function SV-225264r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell
    #"Turn on PowerShell Script Block Logging" to "Enabled". 
    #Install patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 on systems with PowerShell 4.0. 
    #PowerShell 5.x does not require the installation of an additional patch.
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" "EnableScriptBlockLogging" "SilentlyContinue"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225265
#Windows PowerShell 2.0 must not be installed on Windows 2012/2012 R2.
Function SV-225265r569185_rule { 
    if($Global:installedFeatures.name -contains "Powershell-v2"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Technician should uninstall Powershell-v2'}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225266
#Windows 2012 account lockout duration must be configured to 15 minutes or greater.
Function SV-225266r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy
    #"Account lockout duration" to "15" minutes or greater, or 0.
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.LockoutDuration -ge [timespan]"00:15" -or $Global:passwordpolicy.LockoutDuration -eq [timespan]0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225267
#The number of allowed bad logon attempts must meet minimum requirements.
Function SV-225267r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
    #"Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable). 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.LockoutThreshold -le 3 -and $Global:passwordpolicy.LockoutThreshold -gt 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225268
#The reset period for the account lockout counter must be configured to 15 minutes or greater on Windows 2012.
Function SV-225268r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy
    #"Reset account lockout counter after" to at least "60" minutes. 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.LockoutObservationWindow -ge [timespan]"1:00"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225269
#The password history must be configured to 24 passwords remembered.
Function SV-225269r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy
    #"Enforce password history" to "24" passwords remembered. 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.PasswordHistoryCount -ge 24){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225270
#The maximum password age must meet requirements.
Function SV-225270r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Maximum password age" to "60" days or less (excluding "0" which is unacceptable). 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.MaxPasswordAge -le [timespan]"60.00:00:00"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225271
#The minimum password age must meet requirements.
Function SV-225271r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Minimum password age" to at least "1" day. 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.MinPasswordAge -ge [timespan]"1.00:00:00"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225272
#Passwords must, at a minimum, be 14 characters.
Function SV-225272r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Minimum password length" to "14" characters. 
    #This is set in default domain policy
    if($Global:passwordpolicy.MinPasswordLength -eq 14){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225273
#The built-in Windows password complexity policy must be enabled.
Function SV-225273r569185_rule { 
    #Computer Configuration >> Windows Settings -> Security Settings >> Account Policies >> Password Policy 
    #"Password must meet complexity requirements" to "Enabled". 
    if($Global:passwordpolicy.ComplexityEnabled -eq $true){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225274
#Reversible password encryption must be disabled.
Function SV-225274r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Store passwords using reversible encryption" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225275
#The system must be configured to audit Account Logon - Credential Validation successes.
Function SV-225275r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
    #"Audit Credential Validation" with "Success" selected. 
    if (($Global:auditpol -match "Credential Validation") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Credential Validation") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225276
#The system must be configured to audit Account Logon - Credential Validation failures.
Function SV-225276r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon
    #"Audit Credential Validation" with "Failure" selected. 
    if (($Global:auditpol -match "Credential Validation") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Credential Validation") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225277
#The system must be configured to audit Account Management - Other Account Management Events successes.
Function SV-225277r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
    #"Audit Other Account Management Events" with "Success" selected.  
    if (($Global:auditpol -match "Other Account Management Events") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Other Account Management Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225278
#The system must be configured to audit Account Management - Security Group Management successes.
Function SV-225278r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
    #"Audit Security Group Management" with "Success" selected.  
    if (($Global:auditpol -match "Security Group Management") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Security Group Management") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225279
#The system must be configured to audit Account Management - User Account Management successes.
Function SV-225279r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
    #"Audit User Account Management" with "Success" selected.  
    if (($Global:auditpol -match "User Account Management") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "User Account Management") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225280
#The system must be configured to audit Account Management - User Account Management failures.
Function SV-225280r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
    #"Audit User Account Management" with "Failure" selected.  
    if (($Global:auditpol -match "User Account Management") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "User Account Management") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225281
#The system must be configured to audit Detailed Tracking - Process Creation successes.
Function SV-225281r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Detailed Tracking
    #"Audit Process Creation" with "Success" selected.  
    if (($Global:auditpol -match "Process Creation") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Process Creation") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225282
#Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout successes.
Function SV-225282r569185_rule { 
    #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Account Lockout" with "Success" selected. 
    if (($Global:auditpol -match "Account Lockout") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Account Lockout") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225283
#Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout failures.
Function SV-225283r569185_rule { 
    #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Account Lockout" with "Failure" selected. 
    if (($Global:auditpol -match "Account Lockout") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Account Lockout") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225284
#The system must be configured to audit Logon/Logoff - Logoff successes.
Function SV-225284r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Logoff" with "Success" selected.  
    if (($Global:auditpol -match "^(\s)+Logoff") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "^(\s)+Logoff") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225285
#The system must be configured to audit Logon/Logoff - Logon successes.
Function SV-225285r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Logon" with "Success" selected.  
    if (($Global:auditpol -match "^(\s)+Logon") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "^(\s)+Logon") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225286
#The system must be configured to audit Logon/Logoff - Logon failures.
Function SV-225286r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Logon" with "Failure" selected.  
    if (($Global:auditpol -match "^(\s)+Logon") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "^(\s)+Logon") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225287
#The system must be configured to audit Logon/Logoff - Special Logon successes.
Function SV-225287r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff
    #"Audit Special Logon" with "Success" selected.  
    if (($Global:auditpol -match "Special Logon") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Special Logon") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225288
#The system must be configured to audit Object Access - Central Access Policy Staging successes.
Function SV-225288r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access
    #"Audit Central Access Policy Staging" with "Success" selected. 
    if (($Global:auditpol -match "Central Policy Staging") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Central Policy Staging") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225289
#The system must be configured to audit Object Access - Central Access Policy Staging failures.
Function SV-225289r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Object Access
    #"Audit Central Access Policy Staging" with "Failure" selected. 
    if (($Global:auditpol -match "Central Policy Staging") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Central Policy Staging") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225290
#The system must be configured to audit Object Access - Removable Storage successes.
Function SV-225290r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
    #"Audit Removable Storage" with "Success" selected. 
    if (($Global:auditpol -match "Removable Storage") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Removable Storage") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225291
#The system must be configured to audit Object Access - Removable Storage failures.
Function SV-225291r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Object Access
    #"Audit Removable Storage" with "Failure" selected. 
    if (($Global:auditpol -match "Removable Storage") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Removable Storage") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225292
#The system must be configured to audit Policy Change - Audit Policy Change successes.
Function SV-225292r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
    #"Audit Audit Policy Change" with "Success" selected. 
    if (($Global:auditpol -match "Audit Policy Change") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Audit Policy Change") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225293
#The system must be configured to audit Policy Change - Audit Policy Change failures.
Function SV-225293r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
    #"Audit Audit Policy Change" with "Failure" selected. 
    if (($Global:auditpol -match "Audit Policy Change") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Audit Policy Change") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225294
#The system must be configured to audit Policy Change - Authentication Policy Change successes.
Function SV-225294r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
    #"Audit Authentication Policy Change" with "Success" selected. 
    if (($Global:auditpol -match "Authentication Policy Change") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Authentication Policy Change") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225295
#The system must be configured to audit Policy Change - Authorization Policy Change successes.
Function SV-225295r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Policy Change
    #"Audit Authorization Policy Change" with "Success" selected. 
    if (($Global:auditpol -match "Authorization Policy Change") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Authorization Policy Change") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225296
#The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.
Function SV-225296r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
    #"Audit Sensitive Privilege Use" with "Success" selected. 
    if (($Global:auditpol -match "Sensitive Privilege Use") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225297
#The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.
Function SV-225297r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Privilege Use
    #"Audit Sensitive Privilege Use" with "Failure" selected. 
    if (($Global:auditpol -match "Sensitive Privilege Use") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Sensitive Privilege Use") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225298
#The system must be configured to audit System - IPsec Driver successes.
Function SV-225298r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit IPsec Driver" with "Success" selected. 
    if (($Global:auditpol -match "IPsec Driver") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "IPsec Driver") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225299
#The system must be configured to audit System - IPsec Driver failures.
Function SV-225299r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit IPsec Driver" with "Failure" selected. 
    if (($Global:auditpol -match "IPsec Driver") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "IPsec Driver") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225300
#Windows Server 2012/2012 R2 must be configured to audit System - Other System Events successes.
Function SV-225300r569185_rule { 
    #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
    #"Audit Other System Events" with "Success" selected.
    if (($Global:auditpol -match "Other System Events") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Other System Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225301
#Windows Server 2012/2012 R2 must be configured to audit System - Other System Events failures.
Function SV-225301r569185_rule { 
    #Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System
    #"Audit Other System Events" with "Failure" selected.
    if (($Global:auditpol -match "Other System Events") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Other System Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225302
#The system must be configured to audit System - Security State Change successes.
Function SV-225302r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit Security State Change" with "Success" selected. 
    if (($Global:auditpol -match "Security State Change") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Security State Change") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225303
#The system must be configured to audit System - Security System Extension successes.
Function SV-225303r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit Security State Extension" with "Success" selected. 
    if (($Global:auditpol -match "Security System Extension") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Security System Extension") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225304
#The system must be configured to audit System - System Integrity successes.
Function SV-225304r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit System Integrity" with "Success" selected. 
    if (($Global:auditpol -match "System Integrity") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "System Integrity") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225305
#The system must be configured to audit System - System Integrity failures.
Function SV-225305r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> System
    #"Audit System Integrity" with "Failure" selected. 
    if (($Global:auditpol -match "System Integrity") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "System Integrity") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }
                        
#V-225310
#Permissions for the Application event log must prevent access by nonprivileged accounts.
Function SV-225310r569185_rule { 
    $FSR=@('FullControl','Modify','Modify, Synchronize')
    $IR=@('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\EventLog')
    $badaccounts=@()
                
    $ACL=(Get-Acl C:\Windows\System32\winevt\Logs\Application.evtx).access
    [array]$accounts=($ACL | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}).IdentityReference.Value
                
    if ($accounts.count -eq 0) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        if($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Orphaned SID(s) found in the ACL.'}
            }
        else{
            foreach($account in $accounts){
                if($account.split('.')[-1] -notin $Global:Adminlevelcodes -and $account.split('\')[0] -ne 'AFNOAPPS'){
                    $badaccounts+=$account
                    }
                }
            }

        if($badaccounts.count -ge 0){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-225311
#Permissions for the Security event log must prevent access by nonprivileged accounts.
Function SV-225311r569185_rule { 
    $FSR=@('FullControl','Modify','Modify, Synchronize')
    $IR=@('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\EventLog')
    $badaccounts=@()
                
    $ACL=(Get-Acl C:\Windows\System32\winevt\Logs\Security.evtx).access
    [array]$accounts=($ACL | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}).IdentityReference.Value
                
    if ($accounts.count -eq 0) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        if($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Orphaned SID(s) found in the ACL.'}
            }
        else{
            foreach($account in $accounts){
                if($account.split('.')[-1] -notin $Global:Adminlevelcodes -and $account.split('\')[0] -ne 'AFNOAPPS'){
                    $badaccounts+=$account
                    }
                }
            }

        if($badaccounts.count -ge 0){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-225312
#Permissions for the System event log must prevent access by nonprivileged accounts.
Function SV-225312r569185_rule { 
    $FSR=@('FullControl','Modify','Modify, Synchronize')
    $IR=@('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\EventLog')
    $badaccounts=@()
                
    $ACL=(Get-Acl C:\Windows\System32\winevt\Logs\System.evtx).access
    [array]$accounts=($ACL | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}).IdentityReference.Value
                
    if ($accounts.count -eq 0) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        if($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Orphaned SID(s) found in the ACL.'}
            }
        else{
            foreach($account in $accounts){
                if($account.split('.')[-1] -notin $Global:Adminlevelcodes -and $account.split('\')[0] -ne 'AFNOAPPS'){
                    $badaccounts+=$account
                    }
                }
            }

        if($badaccounts.count -ge 0){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-225313
#Event Viewer must be protected from unauthorized modification and deletion.
Function SV-225313r569185_rule { 
    #Checks that trusted installer is the only one with modify or full control
    $FSR=@('FullControl','268435456','Modify','-536805376')
    $IR=@('NT SERVICE\TrustedInstaller')

    $eventvwrAcl =(Get-Acl C:\Windows\System32\eventvwr.exe).Access
    if($eventvwrAcl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225314
#The Mapper I/O network protocol (LLTDIO) driver must be disabled.
Function SV-225314r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery
    #"Turn on Mapper I/O (LLTDIO) driver" to "Disabled". 
    $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowLLTDIOOndomain"
    $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowLLTDIOOnPublicNet"
    $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "EnableLLTDIO"
    $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "ProhibitLLTDIOOnPrivateNet"
    if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225315
#The Responder network protocol driver must be disabled.
Function SV-225315r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Link-Layer Topology Discovery
    #"Turn on Responder (RSPNDR) driver" to "Disabled". 
    $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowRspndrOndomain"
    $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "AllowRspndrOnPublicNet"
    $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "EnableRspndr"
    $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LLTD\" "ProhibitRspndrOnPrivateNet"
    if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225316
#Windows Peer-to-Peer networking services must be turned off.
Function SV-225316r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services
    #"Turn off Microsoft Peer-to-Peer Networking Services" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Peernet\" "Disabled"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225317
#Network Bridges must be prohibited in Windows.
Function SV-225317r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Network Connections
    #"Prohibit installation and configuration of Network Bridge on your DNS domain network" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" "NC_AllowNetBridge_NLA"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225318
#Domain users must be required to elevate when setting a networks location.
Function SV-225318r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Network Connections
    #"Require domain users to elevate when setting a network's location" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Network Connections\" "NC_StdDomainUserSetLocation"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225319
#All Direct Access traffic must be routed through the internal network.
Function SV-225319r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Network Connections
    #"Route all traffic through the internal network" to "Enabled: Enabled State". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "Force_Tunneling"
    if ($Value -eq "Enabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225320
#The 6to4 IPv6 transition technology must be disabled.
Function SV-225320r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
    #"Set 6to4 State" to "Enabled: Disabled State". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "6to4_State" "SilentlyContinue"
    if ($Value -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225321
#The IP-HTTPS IPv6 transition technology must be disabled.
Function SV-225321r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
    #"Set IP-HTTPS State" to "Enabled: Disabled State".
    #Note: "IPHTTPS URL:" must be entered in the policy even if set to Disabled State. Enter "about:blank". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\" "IPHTTPS_ClientState" "SilentlyContinue"
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225322
#The ISATAP IPv6 transition technology must be disabled.
Function SV-225322r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
    #"Set ISATAP State" to "Enabled: Disabled State". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "ISATAP_State" "SilentlyContinue"
    if ($Value -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225323
#The Teredo IPv6 transition technology must be disabled.
Function SV-225323r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies
    #"Set Teredo State" to "Enabled: Disabled State". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\" "Teredo_State"
    if ($Value -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225324
#IP stateless autoconfiguration limits state must be enabled.
Function SV-225324r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters
    #"Set IP Stateless Autoconfiguration Limits State" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnableIPAutoConfigurationLimits"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225325
#The configuration of wireless devices using Windows Connect Now must be disabled.
Function SV-225325r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now
    #"Configuration of wireless settings using Windows Connect Now" to "Disabled". 
    $Value1 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableFlashConfigRegistrar"
    $Value2 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableInBand802DOT11Registrar"
    $Value3 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableUPnPRegistrar"
    $Value4 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "DisableWPDRegistrar"
    $Value5 = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\Registrars\" "EnableRegistrars"
    if ($Value1 -eq "0" -and $Value2 -eq "0" -and $Value3 -eq "0" -and $Value4 -eq "0" -and $Value5 -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225326
#The Windows Connect Now wizards must be disabled.
Function SV-225326r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now
    #"Prohibit access of the Windows Connect Now wizards" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WCN\UI\" "DisableWcnUi"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225327
#Windows Update must be prevented from searching for point and print drivers.
Function SV-225327r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Printers
    #"Extend Point and Print connection to search Windows Update" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DoNotInstallCompatibleDriverFromWindowsUpdate"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225328
#Optional component installation and component repair must be prevented from using Windows Update.
Function SV-225328r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System
    #"Specify settings for optional component installation and component repair" to "Enabled" and with "Never attempt to download payload from Windows Update" selected. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\" "UseWindowsUpdate"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225329
#Remote access to the Plug and Play interface must be disabled for device installation.
Function SV-225329r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation 
    #"Allow remote access to the Plug and Play interface" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "AllowRemoteRPC"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225330
#An Error Report must not be sent when a generic device driver is installed.
Function SV-225330r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation
    #"Do not send a Windows error report when a generic driver is installed on a device" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSendGenericDriverNotFoundToWER"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225331
#A system restore point must be created when a new device driver is installed.
Function SV-225331r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation
    #"Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSystemRestore"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225332
#Device metadata retrieval from the Internet must be prevented.
Function SV-225332r569185_rule { 
    #Computer Configuration >> Administrative Templates >> System >> Device Installation
    #"Prevent device metadata retrieval from the Internet" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Device Metadata\" "PreventDeviceMetadataFromNetwork"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225333
#Windows must be prevented from sending an error report when a device driver requests additional software during installation.
Function SV-225333r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation
    #"Prevent Windows from sending an error report when a device driver requests additional software during installation" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\" "DisableSendRequestAdditionalSoftwareToWER"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225334
#Device driver searches using Windows Update must be prevented.
Function SV-225334r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation
    #"Specify search order for device driver source locations" to "Enabled: Do not search Windows Update".
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "SearchOrderConfig"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225335
#Device driver updates must only search managed servers, not Windows Update.
Function SV-225335r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Device Installation
    #"Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected. 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "DriverServerSelection"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225336
#Users must not be prompted to search Windows Update for device drivers.
Function SV-225336r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Driver Installation
    #"Turn off Windows Update device driver search prompt" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching\" "DontPromptForWindowsUpdate"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225337
#Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.
Function SV-225337r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware
    #"Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected. 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Policies\EarlyLaunch\" "DriverLoadPolicy"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225338
#Group Policy objects must be reprocessed even if they have not changed.
Function SV-225338r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Group Policy
    #"Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" "NoGPOListChanges"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225339
#Group Policies must be refreshed in the background if the user is logged on.
Function SV-225339r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Group Policy
    #"Turn off background refresh of Group Policy" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableBkGndGroupPolicy"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225340
#Access to the Windows Store must be turned off.
Function SV-225340r569185_rule { 
    #If the \Windows\WinStore directory exists:
    #Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings
    #"Turn off access to the Store" to "Enabled".

    #Alternately, uninstall the "Desktop Experience" feature from Windows 2012. 
    #This is located under "User Interfaces and Infrastructure" in the "Add Roles and Features Wizard". 
    #The \Windows\WinStore directory may need to be manually deleted after this. 
    if (Test-Path "C:\Windows\WinStore") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\" "NoUseStoreOpenWith"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225341
#Downloading print driver packages over HTTP must be prevented.
Function SV-225341r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off downloading of print drivers over HTTP" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableWebPnPDownload"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225342
#Event Viewer Events.asp links must be turned off.
Function SV-225342r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off Event Viewer "Events.asp" links" to "Enabled"
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\EventViewer\" "MicrosoftEventVwrDisableLinks"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225343
#Errors in handwriting recognition on tablet PCs must not be reported to Microsoft.
Function SV-225343r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off handwriting recognition error reporting" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports\" "PreventHandwritingErrorReports"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225344
#The Internet File Association service must be turned off.
Function SV-225344r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off Internet File Association service" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoInternetOpenWith"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225345
#Printing over HTTP must be prevented.
Function SV-225345r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off printing over HTTP" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableHTTPPrinting"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225346
#The Windows Customer Experience Improvement Program must be disabled.
Function SV-225346r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings 
    #"Turn off Windows Customer Experience Improvement Program" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\SQMClient\Windows" "CEIPEnable"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225347
#Windows must be prevented from using Windows Update to search for drivers.
Function SV-225347r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off Windows Update device driver searching" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" "DontSearchWindowsUpdate"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225348
#Copying of user input methods to the system account for sign-in must be prevented.
Function SV-225348r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Locale Services
    #"Disallow copying of user input methods to the system account for sign-in" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Control Panel\International\" "BlockUserInputMethodsForSignIn"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225349
#Local users on domain-joined computers must not be enumerated.
Function SV-225349r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Logon
    #"Enumerate local users on domain-joined computers" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "EnumerateLocalUsers"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225350
#App notifications on the lock screen must be turned off.
Function SV-225350r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Logon
    #"Turn off app notifications on the lock screen" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "DisableLockScreenAppNotifications"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225351
#Users must be prompted to authenticate on resume from sleep (on battery).
Function SV-225351r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
    #"Require a password when a computer wakes (on battery)" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "DCSettingIndex"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225352
#The user must be prompted to authenticate on resume from sleep (plugged in).
Function SV-225352r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
    #"Require a password when a computer wakes (plugged in)" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" "ACSettingIndex"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225353
#The system must be configured to prevent unsolicited remote assistance offers.
Function SV-225353r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
    #"Configure Offer Remote Assistance" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fAllowUnsolicited"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225354
#Solicited Remote Assistance must not be allowed.
Function SV-225354r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
    #"Configure Solicited Remote Assistance" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fAllowToGetHelp"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225355
#Remote Assistance log files must be generated.
Function SV-225355r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Remote Assistance
    #"Turn on session logging" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "LoggingEnabled"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225356
#Unauthenticated RPC clients must be restricted from connecting to the RPC server.
Function SV-225356r569185_rule {
    #Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call
    #"Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" "RestrictRemoteClients"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225357
#The detection of compatibility issues for applications and drivers must be turned off.
Function SV-225357r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Application Compatibility Diagnostics
    #"Detect compatibility issues for applications and drivers" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" "DisablePcaUI"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225358
#Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft must be prevented.
Function SV-225358r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Microsoft Support Diagnostic Tool
    #"Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" "DisableQueryRemoteServer"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225359
#Access to Windows Online Troubleshooting Service (WOTS) must be prevented.
Function SV-225359r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics
    #"Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via the Windows Online Troubleshooting Service - WOTS)" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\" "EnableQueryRemoteServer"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225360
#Responsiveness events must be prevented from being aggregated and sent to Microsoft.
Function SV-225360r569185_rule { 
    #Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Windows Performance PerfTrack
    #"Enable/Disable PerfTrack" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\" "ScenarioExecutionEnabled"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225361
#The time service must synchronize with an appropriate DoD time source.
Function SV-225361r569185_rule { 
    #Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers
    #"Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.
    #If PDC and time set to NTP this assumes that the source is correct. If anything else, it should be NT5DS.
    $timeSettings = W32tm /query /configuration
    $type = ($timeSettings -match "Type: ").trim().split(":")[1].trim().split(" ")[0].trim()
    if($type -eq "NT5DS") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225362
#Trusted app installation must be enabled to allow for signed enterprise line of business apps.
Function SV-225362r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment
    #"Allow all trusted apps to install" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Appx\" "AllowAllTrustedApps"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225363
#The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
Function SV-225363r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility
    #"Turn off Inventory Collector" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\AppCompat\" "DisableInventory"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225364
#Autoplay must be turned off for non-volume devices.
Function SV-225364r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
    #"Disallow Autoplay for non-volume devices" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoAutoplayfornonVolume"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225365
#The default Autorun behavior must be configured to prevent Autorun commands.
Function SV-225365r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies
    #"Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoAutorun"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225366
#Autoplay must be disabled for all drives.
Function SV-225366r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies 
    #"Turn off AutoPlay" to "Enabled:All Drives". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" "NoDriveTypeAutoRun"
    if ($Value -eq "255") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225367
#The use of biometrics must be disabled.
Function SV-225367r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Biometrics
    #"Allow the use of biometrics" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\" "Enabled"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225368
#The password reveal button must not be displayed.
Function SV-225368r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface
    #"Do not display the password reveal button" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CredUI\" "DisablePasswordReveal"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225369
#Administrator accounts must not be enumerated during elevation.
Function SV-225369r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface
    #"Enumerate administrator accounts on elevation" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" "EnumerateAdministrators"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225370
#The Application event log size must be configured to 32768 KB or greater.
Function SV-225370r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application 
    #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" "MaxSize"
    if ($Value -ge 32768) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225371
#The Security event log size must be configured to 196608 KB or greater.
Function SV-225371r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security 
    #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" "MaxSize"
    if ($Value -ge 196608) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225372
#The Setup event log size must be configured to 32768 KB or greater.
Function SV-225372r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Setup 
    #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\" "MaxSize"
    if ($Value -ge 32768) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225373
#The System event log size must be configured to 32768 KB or greater.
Function SV-225373r569185_rule { 
    #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System 
    #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\" "MaxSize"
    if ($Value -ge 32768) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225374
#Windows SmartScreen must be enabled on Windows 2012/2012 R2.
Function SV-225374r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface
    #"Do not display the password reveal button" to "Enabled". 
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CredUI\" "DisablePasswordReveal"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225375
#Explorer Data Execution Prevention must be enabled.
Function SV-225375r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off Data Execution Prevention for Explorer" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoDataExecutionPrevention"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225376
#Turning off File Explorer heap termination on corruption must be disabled.
Function SV-225376r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off heap termination on corruption" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoHeapTerminationOnCorruption"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225377
#File Explorer shell protocol must run in protected mode.
Function SV-225377r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off shell protocol protected mode" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "PreXPSP2ShellProtocolBehavior"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225378
#The location feature must be turned off.
Function SV-225378r569185_rule { 
    #Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Location and Sensors
    #"Turn off location" to "Enabled".
    #If location services are approved by the organization for a device, this must be documented. 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors\" "DisableLocation"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225379
#Passwords must not be saved in the Remote Desktop Client.
Function SV-225379r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client
    #"Do not allow passwords to be saved" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "DisablePasswordSaving"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225380
#Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).
Function SV-225380r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
    #"Do not allow drive redirection" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCdm"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225381
#Remote Desktop Services must always prompt a client for passwords upon connection.
Function SV-225381r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security 
    #"Always prompt for password upon connection" to "Enabled". 
    $Value = Check-RegKeyValue "hklm\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225382
#Remote Desktop Services must be configured with the client connection encryption set to the required level.
Function SV-225382r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
    #"Set client connection encryption level" to "Enabled" and "High Level". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "MinEncryptionLevel"
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225383
#Remote Desktop Services must delete temporary folders when a session is terminated.
Function SV-225383r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders
    #"Do not delete temp folder upon exit" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "DeleteTempDirsOnExit"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225384
#Remote Desktop Services must be configured to use session-specific temporary folders.
Function SV-225384r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders
    #"Do not use temporary folders per session" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "PerSessionTempDir"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225385
#Attachments must be prevented from being downloaded from RSS feeds.
Function SV-225385r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
    #"Prevent downloading of enclosures" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "DisableEnclosureDownload"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225386
#Basic authentication for RSS feeds over HTTP must be turned off.
Function SV-225386r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
    #"Turn on Basic feed authentication over HTTP" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "AllowBasicAuthInClear"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225387
#Automatic download of updates from the Windows Store must be turned off.
Function SV-225387r569185_rule { 
    #The Windows Store is not installed by default. If the \Windows\WinStore directory does not exist, this is NA.
    #Windows 2012 R2 split the original policy that configures this setting into two separate ones. Configuring either one to "Enabled" will update the registry value as identified in the Check section.
    #Computer Configuration -> Administrative Templates -> Windows Components -> Store
    #"Turn off Automatic Download of updates on Win8 machines" or "Turn off Automatic Download and install of updates" to "Enabled".

    #Windows 2012:
    #Computer Configuration -> Administrative Templates -> Windows Components -> Store 
    #"Turn off Automatic Download of updates" to "Enabled". 
    if (Test-Path "C:\Windows\WinStore") {
        if ($Global:OS -match "Server 2012 R2") {
            $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\" "AutoDownload"
            }
        elseif ($Global:OS -match "Server 2012" -and $Global:OS -notmatch "Server 2012 R2") {
            $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\" "AutoDownload"
            }
        if ($Value -eq "2") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="C:\Windows\WinStore folder exists and registry values incorrectly configured"}
            }
        }
    else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225388
#The Windows Store application must be turned off.
Function SV-225388r569185_rule { 
    #If the \Windows\WinStore directory does not exist, this is NA.
    #Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store
    #"Turn off the Store application" to "Enabled". 
    if (Test-Path "C:\Windows\WinStore") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\" "RemoveWindowsStore"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details='C:\Windows\WinStore folder exists and registry values incorrectly configured'}
            }
        }
    else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225389
#Users must be prevented from changing installation options.
Function SV-225389r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
    #"Allow user control over installs" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "EnableUserControl"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225390
#The Windows Installer Always install with elevated privileges option must be disabled.
Function SV-225390r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
    #"Always install with elevated privileges" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "AlwaysInstallElevated"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225391
#Users must be notified if a web-based program attempts to install software.
Function SV-225391r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
    #"Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "SafeForScripting"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225392
#Nonadministrators must be prevented from applying vendor-signed updates.
Function SV-225392r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
    #"Prohibit non-administrators from applying vendor signed updates" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "DisableLUAPatching"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225393
#Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet.
Function SV-225393r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management
    #"Prevent Windows Media DRM Internet Access" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WMDRM\" "DisableOnline"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225394
#Users must not be presented with Privacy and Installation options on first use of Windows Media Player.
Function SV-225394r569185_rule { 
    #If no Windows Media Player, NA
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player
    #"Do Not Show First Use Dialog Boxes" to "Enabled".
    #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}} #Get-WindowsOptionalFeature is PSv4+
    if ((Get-WmiObject Win32_OptionalFeature -Filter "name = 'WindowsMediaPlayer'").InstallState -ne 1) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" "GroupPrivacyAcceptance"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225395
#Windows Media Player must be configured to prevent automatic checking for updates.
Function SV-225395r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player
    #"Prevent Automatic Updates" to "Enabled". 
    #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}} #Get-WindowsOptionalFeature is PSv4+
    if ((Get-WmiObject Win32_OptionalFeature -Filter "name = 'WindowsMediaPlayer'").InstallState -ne 1) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer\" "DisableAutoupdate"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225396
#The Windows Remote Management (WinRM) client must not use Basic authentication.
Function SV-225396r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
    #"Allow Basic authentication" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowBasic"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225397
#The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
Function SV-225397r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
    #"Allow unencrypted traffic" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowUnencryptedTraffic"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225398
#The Windows Remote Management (WinRM) client must not use Digest authentication.
Function SV-225398r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client
    #"Disallow Digest authentication" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client\" "AllowDigest"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225399
#The Windows Remote Management (WinRM) service must not use Basic authentication.
Function SV-225399r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
    #"Allow Basic authentication" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "AllowBasic"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225400
#The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
Function SV-225400r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
    #"Allow unencrypted traffic" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" "AllowUnencryptedTraffic"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225401
#The Windows Remote Management (WinRM) service must not store RunAs credentials.
Function SV-225401r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service
    #"Disallow WinRM from storing RunAs credentials" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\" "DisableRunAs"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225402
#The Remote Desktop Session Host must require secure RPC communications.
Function SV-225402r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security
    #"Require secure RPC communication" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fEncryptRPCTraffic"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225404
#Users must be prevented from mapping local COM ports and redirecting data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop Services Role).
Function SV-225404r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
    #"Do not allow COM port redirection" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableCcm"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225405
#Users must be prevented from mapping local LPT ports and redirecting data from the Remote Desktop Session Host to local LPT ports.  (Remote Desktop Services Role).
Function SV-225405r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
    #"Do not allow LPT port redirection" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisableLPT"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225406
#The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session.  (Remote Desktop Services Role).
Function SV-225406r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
    #"Do not allow smart card device redirection" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fEnableSmartCard"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225407
#Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host.  (Remote Desktop Services Role).
Function SV-225407r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection
    #"Do not allow supported Plug and Play device redirection" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fDisablePNPRedir"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225408
#Only the default client printer must be redirected to the Remote Desktop Session Host.  (Remote Desktop Services Role).
Function SV-225408r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Printer Redirection
    #"Redirect only the default client printer" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\" "RedirectOnlyDefaultClientPrinter"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225409
#The display of slide shows on the lock screen must be disabled (Windows 2012 R2).
Function SV-225409r569185_rule { 
    #Computer Configuration -> Administrative Templates -> Control Panel -> Personalization
    #"Prevent enabling lock screen slide show" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\" "NoLockScreenSlideshow"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225410
#Windows 2012 R2 must include command line data in process creation events.
Function SV-225410r569185_rule { 
    #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
    #Computer Configuration -> Administrative Templates -> System -> Audit Process Creation
    #"Include command line in process creation events" to "Enabled". 
    if ($Global:OS -match "Server 2012 R2") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" "ProcessCreationIncludeCmdLine_Enabled"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    Else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225411
#The network selection user interface (UI) must not be displayed on the logon screen (Windows 2012 R2).
Function SV-225411r569185_rule { 
    #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
    #Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled". 
    if ($Global:OS -match "Server 2012 R2") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "DontDisplayNetworkSelectionUI"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    Else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225412
#The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2).
Function SV-225412r569185_rule { 
    #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
    #Computer Configuration -> Administrative Templates -> Windows Components -> App Runtime -> "Allow Microsoft accounts to be optional" to "Enabled". 
    if ($Global:OS -match "Server 2012 R2") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    Else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225413
#The Windows Explorer Preview pane must be disabled for Windows 2012.
Function SV-225413r569185_rule { 
    #checks reg keys
    $Value1 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoPreviewPane" -EA SilentlyContinue
    $Value2 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\explorer\" "NoReadingPane" -EA SilentlyContinue
    if ($Value1 -eq "1" -and $value2 -eq "1" ) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details='This registry key is incorrectly configured.'}
        }
    }

#V-225414
#Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2).
Function SV-225414r569185_rule { 
    #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options
    #"Sign-in last interactive user automatically after a system-initiated restart" to "Disabled". 
    if ($Global:OS -match "Server 2012 R2") {
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableAutomaticRestartSignOn"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    Else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225415
#WDigest Authentication must be disabled.
Function SV-225415r569185_rule { 
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"WDigest Authentication (disabling may require KB2871997)" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" "UseLogonCredential"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225416
#A host-based firewall must be installed and enabled on the system.
Function SV-225416r569185_rule { 
    if ($Global:installedprograms.displayname -contains "McAfee Endpoint Security Firewall") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225417
#Systems must be maintained at a supported service pack level.
Function SV-225417r569185_rule { 
    #Running with a literal interpretation here. Version greater than or equal to the version 6.2 build 9200.
    if ((Get-WmiObject -Class win32_operatingsystem).version -ge 6.2.9200) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225419
#Local volumes must use a format that supports NTFS attributes.
Function SV-225419r569185_rule { 
    #All local volumes must be NTFS or ReFS
    #Check to see if there's any local volumes that AREN'T compliant
    #if (Get-WMIObject -Class Win32_Volume | Where {$_.DriveType -eq 3 -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    if (Get-Volume | Where {$_.DriveType -eq "Fixed" -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225420
#Permissions for system drive root directory (usually C:\) must conform to minimum requirements.
Function SV-225420r569185_rule { 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
    if ($Value -eq "0") {
        $FSR=@('FullControl','268435456','Modify','-536805376')
        $IR=@('CREATOR OWNER','NT AUTHORITY\SYSTEM','BUILTIN\Administrators')

        $Cacl=(Get-Acl C:\).Access
        if($Cacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225421
#Permissions for program file directories must conform to minimum requirements.
Function SV-225421r569185_rule { 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
    if ($Value -eq "0") {
        $badacl=@()
        $FSR=@('FullControl','268435456','Modify','-536805376')
        $IR=@('CREATOR OWNER','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\TrustedInstaller')

        $programfilesacl=(Get-Acl 'C:\Program Files').Access
        $programfiles86acl=(Get-Acl 'C:\Program Files (x86)').Access
        if($programfilesacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files'}
        if($programfiles86acl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){$badacl+='Program Files (x86)'}
        if($badacl.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following folder(s) contain a bad ACL entry: $badacl"}
            }
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225422
#Permissions for Windows installation directory must conform to minimum requirements.
Function SV-225422r569185_rule { 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
    if ($Value -eq "0") {
        $FSR=@('FullControl','268435456','Modify','-536805376')
        $IR=@('CREATOR OWNER','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\TrustedInstaller')

        $windowsacl=(Get-Acl C:\Windows).Access
        if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225423
#The system must not boot into multiple operating systems (dual-boot).
Function SV-225423r569185_rule { 
    $BootableDisks = @()
    $BootableDisks += Get-Disk | Where {$_.bootfromdisk -eq $true}
    if ($BootableDisks.count -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225424
#Nonadministrative user accounts or groups must only have print permissions on printer shares.
Function SV-225424r569185_rule { 
    $printShares = get-printer * -full -EA SilentlyContinue | Where {$_.shared -eq $true}
    if ($printShares.count -eq 0) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225425
#Outdated or unused accounts must be removed from the system or disabled.
Function SV-225425r569185_rule { 
    #If more than the default accounts, technician should review
    if((Get-LocalUser).count -gt 2){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225426
#Windows 2012/2012 R2 accounts must be configured to require passwords.
Function SV-225426r569185_rule { 
    $nopwd = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount
    if($nopwd.count -eq 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225427
#Windows 2012/2012 R2 passwords must be configured to expire.
Function SV-225427r569185_rule { 
    if((Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' and PasswordExpires='False'").count -eq 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225428
#System files must be monitored for unauthorized changes.
Function SV-225428r569268_rule { 
    if($Global:installedprograms.displayname -contains "McAfee Agent"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225429
#Non system-created file shares on a system must limit access to groups that require it.
Function SV-225429r569185_rule { 
    #Check all non system shares to see if theres Everyone permission with allow.  If not, it's sure constrained permissions
    $BaseDFS=$(Get-ADComputer $env:COMPUTERNAME).distinguishedName.Split(',')[1].trim('OU=').replace(' ','_')
    $Builtinshares=@("ADMIN$","IPC$","C$","D$","E$","F$","S$")
    $allowedshares=@("NETLOGON","SYSVOL","EMIE","logonscripts","scripts","startupscripts","DHCP$")
    $Shares = (Get-SmbShare).Name
    $NAShares=$shares | Where-Object {$_ -notin $builtinshares}
    $NFShares=$shares | Where-Object {$_ -notin $builtinshares -and $_ -notin $allowedshares -and $_ -ne $basedfs}
                
    if($NAShares.count -eq 0){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif($NFShares.count -eq 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details="Review the following shares:`n" + ($NFShares -join "`n")}
        }
    }

#V-225430
#The HBSS McAfee Agent must be installed.
Function SV-225430r569185_rule { 
    if ($Global:installedprograms.displayname -contains "McAfee Agent") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225431
#Software certificate installation files must be removed from Windows 2012/2012 R2.
Function SV-225431r569185_rule { 
    if($Global:softcerts.count -eq 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        $badcerts=@()
        foreach($cert in $Global:softcerts){
            if($cert -ne "C:\Program Files\Quest\Recovery Manager for Active Directory Forest Edition\RecoveryAgent.pfx" -or $cert -notlike "C:\`$Recycle.Bin*"){$badcerts+=$cert}
            }
        if($badcerts.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following files caused this to be a finding: $badcerts"}
            }
        }
    }

#V-225433
#Servers must have a host-based Intrusion Detection System.
Function SV-225433r569185_rule { 
    if ($Global:installedprograms.displayname -contains "McAfee Endpoint Security Firewall") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225434
#Windows Server 2012 / 2012 R2 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).
Function SV-225434r569185_rule { 
    if($Global:installedprograms.displayname -contains "McAfee Agent") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225435
#The system must support automated patch management tools to facilitate flaw remediation.
Function SV-225435r569185_rule { 
    #SCCM does this
    if ((Get-Process -name "CcmExec" -EA SilentlyContinue) -ne $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225436
#The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.
Function SV-225436r569185_rule { 
    #axway
    if ($Global:installedprograms.DisplayName -contains "Axway Desktop Validator") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225437
#File Transfer Protocol (FTP) servers must be configured to prevent anonymous logons.
Function SV-225437r569185_rule { 
    if($Global:installedFeatures.name -notcontains "web-ftp-server"){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225438
#File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive.
Function SV-225438r569185_rule { 
    if($Global:installedFeatures.name -notcontains "web-ftp-server"){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-225441
#The DoD Root CA certificates must be installed in the Trusted Root Store.
Function SV-225441r569248_rule { 
    Remove-Variable certs,HasDodRoot2,HasDodRoot3,HasDodRoot4,HasDodRoot5 -EA SilentlyContinue
    $certs = Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*"
    $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" -and $_.NotAfter -gt $Global:currDate}
    $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "D73CA91102A2204A36459ED32213B467D7CE97FB" -and $_.NotAfter -gt $Global:currDate}
    $HasDodRoot4 = $certs | Where {$_.subject -eq "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "B8269F25DBD937ECAFD4C35A9838571723F2D026" -and $_.NotAfter -gt $Global:currDate}
    $HasDodRoot5 = $certs | Where {$_.subject -eq "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "4ECB5CC3095670454DA1CBD410FC921F46B8564B" -and $_.NotAfter -gt $Global:currDate}
    if ($HasDodRoot2 -and $HasDodRoot3 -and $HasDodRoot4 -and $HasDodRoot5) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225442
#The DoD Interoperability Root CA cross-certificates must be installed into the Untrusted Certificates Store on unclassified systems.
Function SV-225442r569255_rule { 
    [datetime]$NotAfterDate="1/22/2022"
    if($NotAfterDate -gt $Global:currDate){
        if ($Global:IsNIPR) {
            Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
            $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}
            $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "AC06108CA348CC03B53795C64BF84403C1DBD341"}
            if ($HasDodRoot3) {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        else {
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-225443
#The US DoD CCEB Interoperability Root CA cross-certificates must be installed into the Untrusted Certificates Store on unclassified systems.
Function SV-225443r569252_rule { 
    #This date is from the STIG. The cert does not have to be in the store after it expires.
    [datetime]$NotAfterDate="9/27/2019"
    if($Global:currDate -gt $NotAfterDate){return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else{
        if ($Global:IsNIPR) {
            Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
            $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*CCEB Interoperability*"}
            $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "929BF3196896994C0A201DF4A5B71F603FEFBF2E"}
            if ($HasDodRoot3) {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        else {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
        }
    }

#V-225444
#Standard user accounts must only have Read permissions to the Winlogon registry key.
Function SV-225444r569185_rule { 
    $FCIR=@('BUILTIN\Administrators','NT AUTHORITY\SYSTEM','NT SERVICE\TrustedInstaller')
    $RIR=@('BUILTIN\Users','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES')
    $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
                
    if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225445
#Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.
Function SV-225445r569185_rule { 
    $FCIR=@('BUILTIN\Administrators','NT AUTHORITY\SYSTEM')
    $RIR=@('BUILTIN\Users','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES')

    #Make sure 32 bit version of registry key has default permissions
    $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
    if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$32bitFine = $false}
    else{$32bitFine = $true}

    #If 64-bit, do it all again
    if ($Global:OSArch -eq 64) {
        $regAcl = (Get-Acl "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\").Access | Where-Object {$_.PropagationFlags -ne 'InheritOnly'}
        if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){$64bitFine = $false}
        else{$64bitFine = $true}
        }

    #If its not 64 bit, then we dont need to bother with it
    else {$64bitFine = $true}

    if ($32bitFine -eq $true -and $64bitFine -eq $true) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225446
#Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.
Function SV-225446r569185_rule {
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Apply UAC restrictions to local accounts on network logons" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LocalAccountTokenFilterPolicy"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225447
#Anonymous access to the registry must be restricted.
Function SV-225447r569185_rule { 
    $regpath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\"
    $reg = Get-Item $regpath
    if ($reg -eq $null) {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        $FCIR=@('BUILTIN\Administrators')
        $RIR=@('NT AUTHORITY\LOCAL SERVICE','BUILTIN\Backup Operators')

        $regAcl = (Get-Acl $regpath).Access
        if($regacl | Where-Object {($_.RegistryRights -eq 'FullControl' -and $_.IdentityReference -notin $FCIR) -or ($_.RegistryRights -eq 'ReadKey' -and $_.IdentityReference -notin $RIR)}){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-225448
#The built-in guest account must be disabled.
Function SV-225448r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Guest account status" to "Disabled".
    if(($Global:Guest).Enabled -eq $false){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225449
#Local accounts with blank passwords must be restricted to prevent access from the network.
Function SV-225449r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Limit local account use of blank passwords to console logon only" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225450
#The built-in administrator account must be renamed.
Function SV-225450r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Rename administrator account" to a name other than "Administrator". 
    if(($Global:Admin).Name -match "Administrator"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225451
#The built-in guest account must be renamed.
Function SV-225451r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Rename guest account" to a name other than "Guest".
    if(($Global:Guest).Name -eq "Guest"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-225452
#Auditing the Access of Global System Objects must be turned off.
Function SV-225452r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Audit: Audit the access of global system objects" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "AuditBaseObjects"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225453
#Auditing of Backup and Restore Privileges must be turned off.
Function SV-225453r569185_rule { 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "FullPrivilegeAuditing"
    if ($Value -eq "00") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225454
#Audit policy using subcategories must be enabled.
Function SV-225454r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "SCENoApplyLegacyAuditPolicy"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225455
#Ejection of removable NTFS media must be restricted to Administrators.
Function SV-225455r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Devices: Allowed to format and eject removable media" to "Administrators". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225456
#Outgoing secure channel traffic must be encrypted or signed.
Function SV-225456r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain member: Digitally encrypt or sign secure channel data (always)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireSignOrSeal"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225457
#Outgoing secure channel traffic must be encrypted when possible.
Function SV-225457r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Domain member: Digitally encrypt secure channel data (when possible)" to "SealSecureChannel". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SealSecureChannel"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225458
#Outgoing secure channel traffic must be signed when possible.
Function SV-225458r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Domain member: Digitally sign secure channel data (when possible)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" "SignSecureChannel"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225459
#The computer account password must not be prevented from being reset.
Function SV-225459r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain member: Disable machine account password changes" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "DisablePasswordChange"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225460
#The maximum age for machine account passwords must be set to requirements.
Function SV-225460r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable). 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "MaximumPasswordAge"
    if ($Value -gt 0 -and $value -le 30) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225461
#The system must be configured to require a strong session key.
Function SV-225461r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireStrongKey"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225462
#The system must be configured to prevent the display of the last username on the logon screen.
Function SV-225462r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive logon: Do not display last user name" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DontDisplayLastUserName"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225463
#The Ctrl+Alt+Del security attention sequence for logons must be enabled.
Function SV-225463r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive Logon: Do not require CTRL+ALT+DEL" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableCAD"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225464
#The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.
Function SV-225464r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive logon: Machine inactivity limit" to "900" seconds" or less. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "InactivityTimeoutSecs"
    if ($Value -le "900") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225465
#The required legal notice must be configured to display before console logon.
Function SV-225465r569185_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #“Interactive Logon: Message text for users attempting to log on” as outlined in the check. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeText"
    if ($Value -eq $Global:LegalNotice) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225466
#The Windows dialog box title for the legal banner must be configured.
Function SV-225466r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive Logon: Message title for users attempting to log on" one of the following:
    #"DoD Notice and Consent Banner"
    #"US Department of Defense Warning Statement"
    #A site-defined equivalent.
    #    If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-226288. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeCaption"
    if ($Value -eq "DoD Notice and Consent Banner" -or $Value -eq "US Department of Defense Warning Statement") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225467
#Caching of logon credentials must be limited.
Function SV-225467r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "4" logons or less. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "CachedLogonsCount"
    if ($Value -le 4) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225468
#Users must be warned in advance of their passwords expiring.
Function SV-225468r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive Logon: Prompt user to change password before expiration" to "14" days or more. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "PasswordExpiryWarning"
    if ($Value -eq "14") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225469
#The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Function SV-225469r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Interactive logon: Smart card removal behavior" to "Lock Workstation" or "Force Logoff". 
    #Documentable Explanation: This can be left not configured or set to “No action” on workstations with the following conditions. This will be documented with the IAO.
    #    •The setting can't be configured due to mission needs, interferes with applications.
    #    •Policy must be in place that users manually lock workstations when leaving them unattended.
    #    •Screen saver requirement is properly configured to lock as required in V0001122. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "SCRemoveOption"
    if ($Value -eq "1" -or $Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225470
#The Windows SMB client must be configured to always perform SMB packet signing.
Function SV-225470r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network client: Digitally sign communications (always)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "RequireSecuritySignature"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225471
#The Windows SMB client must be enabled to perform SMB packet signing when possible.
Function SV-225471r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network client: Digitally sign communications (if server agrees)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters\" "EnableSecuritySignature"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225472
#Unencrypted passwords must not be sent to third-party SMB Servers.
Function SV-225472r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled". 
    $Value = Check-RegKeyValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225473
#The amount of idle time required before suspending a session must be properly set.
Function SV-225473r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Microsoft Network Server: Amount of idle time required before suspending session" to "15" minutes or less. 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "autodisconnect"
    if ($Value -le 15) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225474
#The Windows SMB server must be configured to always perform SMB packet signing.
Function SV-225474r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network server: Digitally sign communications (always)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" "RequireSecuritySignature"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225475
#The Windows SMB server must perform SMB packet signing when possible.
Function SV-225475r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network server: Digitally sign communications (if client agrees)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableSecuritySignature"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225476
#Users must be forcibly disconnected when their logon hours expire.
Function SV-225476r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network server: Disconnect clients when logon hours expire" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableForcedLogoff"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225477
#The service principal name (SPN) target name validation level must be turned off.
Function SV-225477r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Microsoft network server: Server SPN target name validation level" to "Off". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\" "SmbServerNameHardeningLevel"
    if ($Value -eq "0") {
    return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225478
#Automatic logons must be disabled.
Function SV-225478r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "AutoAdminLogon"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225479
#IPv6 source routing must be configured to the highest protection level.
Function SV-225479r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\" "DisableIpSourceRouting"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225480
#The system must be configured to prevent IP source routing.
Function SV-225480r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "DisableIPSourceRouting"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225481
#The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.
Function SV-225481r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnableICMPRedirect"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225482
#The system must be configured to limit how often keep-alive packets are sent.
Function SV-225482r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "KeepAliveTime"
    if ($Value -eq "300000") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225483
#IPSec Exemptions must be limited.
Function SV-225483r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Only ISAKMP is exempt (recommended for Windows Server 2003)".
    #See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\IPSEC\" "NoDefaultExempt"
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225484
#The system must be configured to ignore NetBIOS name release requests except from WINS servers.
Function SV-225484r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\" "NoNameReleaseOnDemand"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225485
#The system must be configured to disable the Internet Router Discovery Protocol (IRDP).
Function SV-225485r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\" "PerformRouterDiscovery"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225486
#The system must be configured to use Safe DLL Search Mode.
Function SV-225486r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "SafeDllSearchMode"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225487
#The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.
Function SV-225487r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "ScreenSaverGracePeriod"
    if ($Value -le 5) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225488
#IPv6 TCP data retransmissions must be configured to prevent resources from becoming exhausted.
Function SV-225488r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less.
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" "TcpMaxDataRetransmissions"
    if ($Value -le 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225489
#The system must limit how many times unacknowledged TCP data is retransmitted.
Function SV-225489r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)" to "3" or less. 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "TcpMaxDataRetransmissions"
    if ($Value -le 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225490
#The system must generate an audit event when the audit log reaches a percentage of full threshold.
Function SV-225490r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning" to "90" or less.
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Eventlog\Security\" "WarningLevel"
    if ($Value -eq "90") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225491
#Anonymous SID/Name translation must not be allowed.
Function SV-225491r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Allow anonymous SID/Name translation" to "Disabled".
    $value = $Global:SecSettings | Where-Object {$_.KeyName -eq "LSAAnonymousNameLookup"} | select -ExpandProperty Setting
    if ($Value -eq $false) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225492
#Anonymous enumeration of SAM accounts must not be allowed.
Function SV-225492r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictAnonymousSAM"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225493
#Anonymous enumeration of shares must be restricted.
Function SV-225493r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "RestrictAnonymous"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225494
#The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
Function SV-225494r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options 
    #"Network access: Let everyone permissions apply to anonymous users" to "Disabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225495
#Named pipes that can be accessed anonymously must be configured to contain no values on member servers.
Function SV-225495r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Named pipes that can be accessed anonymously" to be defined but containing no entries (blank). 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionPipes"
    if ($value -eq "") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225496
#Unauthorized remotely accessible registry paths must not be configured.
Function SV-225496r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Remotely accessible registry paths" with the following entries:
    #System\CurrentControlSet\Control\ProductOptions
    #System\CurrentControlSet\Control\Server Applications
    #Software\Microsoft\Windows NT\CurrentVersion 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" "Machine"
    if ($Value.count -eq 3 -and $value -contains "System\CurrentControlSet\Control\ProductOptions" -and $value -contains "System\CurrentControlSet\Control\Server Applications" -and $value -contains "Software\Microsoft\Windows NT\CurrentVersion") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225497
#Unauthorized remotely accessible registry paths and sub-paths must not be configured.
Function SV-225497r569185_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Remotely accessible registry paths and sub-paths" with the following entries:
    $badpaths=@()
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
        if ($value -notcontains $item) {
            $badpaths+=$item
            }
        }
    if ($badpaths.count -eq 0 -and $Value.count -eq 11) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif ($badpaths.count -gt 0 -and $Value.count -gt 11) {
        $title = "ISSO documented?"
        $message = "Do we have documentation with the ISSO for the following paths (per V-226320)?`n" + ($value | Where {$paths -notcontains $_} -join "`n")
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","No"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($No, $Yes)
        $result = $host.ui.PromptForChoice($title, $message, $options, 0)
                    
        if ($result -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225498
#Anonymous access to Named Pipes and Shares must be restricted.
Function SV-225498r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "RestrictNullSessAccess"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225499
#Network shares that can be accessed anonymously must not be allowed.
Function SV-225499r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Shares that can be accessed anonymously" contains no entries (blank). 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionShares"
    if ($Value -eq "") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225500
#The system must be configured to use the Classic security model.
Function SV-225500r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "ForceGuest"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225501
#Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.
Function SV-225501r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Allow Local System to use computer identity for NTLM" to "Enabled".
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\" "UseMachineId"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225502
#NTLM must be prevented from falling back to a Null session.
Function SV-225502r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Allow LocalSystem NULL session fallback" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\LSA\MSV1_0\" "allownullsessionfallback"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225503
#PKU2U authentication using online identities must be prevented.
Function SV-225503r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" "AllowOnlineID"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225504
#Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
Function SV-225504r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Network security: Configure encryption types allowed for Kerberos" is configured, only the following selections are allowed:
    #AES128_HMAC_SHA1
    #AES256_HMAC_SHA1
    #Future encryption types 

    #This value is stored in bits.  The 1 bit is DES_CBC_CRC, the 2 bit is DES_CBC_MD5, the 4 bit is RC4_HMAC_MD5, the 8 bit is AES128_HMAC_SHA1, the 16 bit is AES256_HMAC_SHA1, and for "Future encryption types" they just turn on every other bit.
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes"
    #These checks make sure each bit flag is set properly.  I'm an idiot in trying to be smart by doing this complicated, because checking for every other bit is stupid
    if ($value -eq "2147483640") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225505
#The system must be configured to prevent the storage of the LAN Manager hash of passwords.
Function SV-225505r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Do not store LAN Manager hash value on next password change" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "NoLMHash"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225506
#The system must be configured to force users to log off when their allowed logon hours expire.
Function SV-225506r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Force logoff when logon hours expire" to "Enabled".
    $value = $Global:SecSettings | Where-Object {$_.KeyName -eq "ForceLogoffWhenHourExpire"} | select -ExpandProperty Setting
    if($value -eq $true){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225507
#The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
Function SV-225507r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\" "LmCompatibilityLevel"
    if ($Value -eq "5") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225508
#The system must be configured to the required LDAP client signing level.
Function SV-225508r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum. 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\LDAP\" "LDAPClientIntegrity"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225509
#The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.
Function SV-225509r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinClientSec"
    if ($Value -eq "537395200") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225510
#The system must be configured to meet the minimum session security requirement for NTLM SSP-based servers.
Function SV-225510r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected). 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinServerSec"
    if ($Value -eq "537395200") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225511
#The shutdown option must not be available from the logon dialog box.
Function SV-225511r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Shutdown: Allow system to be shutdown without having to log on" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ShutdownWithoutLogon"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225512
#The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
Function SV-225512r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" "Enabled"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225513
#The system must be configured to require case insensitivity for non-Windows subsystems.
Function SV-225513r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"System objects: Require case insensitivity for non-Windows subsystems" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" "ObCaseInsensitive"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225514
#The default permissions of global system objects must be increased.
Function SV-225514r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\" "ProtectionMode"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225515
#User Account Control approval mode for the built-in Administrator must be enabled.
Function SV-225515r569185_rule { 
    #Not Applicable if Server Core
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled". 
    if ($Global:IsServerCore) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "FilterAdministratorToken"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225516
#User Account Control must, at minimum, prompt administrators for consent.
Function SV-225516r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".
    #More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop). 
    if ($Global:IsServerCore) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorAdmin"
        if ($Value -le 4 -and $Value -gt 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225517
#User Account Control must automatically deny standard user requests for elevation.
Function SV-225517r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests". 
    if ($Global:IsServerCore) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorUser"
        if ($Value -eq 0) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225518
#User Account Control must be configured to detect application installations and prompt for elevation.
Function SV-225518r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Detect application installations and prompt for elevation" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableInstallerDetection"
        if ($Value -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225519
#Windows must elevate all applications in User Account Control, not just signed ones.
Function SV-225519r569185_rule { 
    #NA if server core
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Only elevate executables that are signed and validated" to "Disabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ValidateAdminCodeSignatures"
        if ($Value -eq 0) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225520
#User Account Control must only elevate UIAccess applications that are installed in secure locations.
Function SV-225520r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableSecureUIAPaths"
        if ($Value -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225521
#User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
Function SV-225521r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Run all administrators in Admin Approval Mode" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableLUA"
        if ($Value -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225522
#User Account Control must switch to the secure desktop when prompting for elevation.
Function SV-225522r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Switch to the secure desktop when prompting for elevation" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "PromptOnSecureDesktop"
        if ($Value -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225523
#User Account Control must virtualize file and registry write failures to per-user locations.
Function SV-225523r569185_rule { 
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableVirtualization"
        if ($Value -eq 1) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225524
#UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.
Function SV-225524r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableUIADesktopToggle"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225525
#Optional Subsystems must not be permitted to operate on the system.
Function SV-225525r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"System settings: Optional subsystems" to "Blank" (Configured with no entries). 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems\" "Optional"
    if ($Value -eq "") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225526
#The print driver installation privilege must be restricted to administrators.
Function SV-225526r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Devices: Prevent users from installing printer drivers" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\" "AddPrinterDrivers"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225527
#Users must be required to enter a password to access private keys stored on the computer.
Function SV-225527r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"System cryptography: Force strong key protection for user keys stored on the computer" to "User must enter a password each time they use a key". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\" "ForceKeyProtection"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225528
#The Fax service must be disabled if installed.
Function SV-225528r569185_rule { 
    $service = Get-Service -Name fax -EA SilentlyContinue
    if ($service -eq $null -or $service.StartType -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225529
#The Microsoft FTP service must not be installed unless required.
Function SV-225529r569185_rule { 
    $service = Get-Service -Name FTPSVC -EA SilentlyContinue
    if ($service -eq $null -or $service.StartType -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225530
#The Peer Networking Identity Manager service must be disabled if installed.
Function SV-225530r569185_rule { 
    $service = Get-Service -Name p2pimsvc -EA SilentlyContinue
    if ($service -eq $null -or $service.StartType -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225531
#The Simple TCP/IP Services service must be disabled if installed.
Function SV-225531r569185_rule { 
    $service = Get-Service -Name simptcp -EA SilentlyContinue
    if ($service -eq $null -or $service.StartType -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225532
#The Telnet service must be disabled if installed.
Function SV-225532r569185_rule { 
    $service = Get-Service -Name tlntsvr -EA SilentlyContinue
    if ($service -eq $null -or $service.StartType -eq "Disabled") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225533
#The Smart Card Removal Policy service must be configured to automatic.
Function SV-225533r569185_rule { 
    if ((Get-Service -DisplayName "Smart Card Removal Policy").StartType -eq "Automatic") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225534
#A screen saver must be enabled on the system.
Function SV-225534r569185_rule { 
    #User Configuration -> Administrative Templates -> Control Panel -> Personalization
    #"Enable screen saver" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaveActive"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225535
#The screen saver must be password protected.
Function SV-225535r569185_rule { 
    #User Configuration -> Administrative Templates -> Control Panel -> Personalization
    #"Password protect the screen saver" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" "ScreenSaverIsSecure"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225536
#Notifications from Windows Push Network Service must be turned off.
Function SV-225536r569185_rule { 
    #User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications
    #"Turn off notifications network usage" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoCloudApplicationNotification"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225537
#Toast notifications to the lock screen must be turned off.
Function SV-225537r569185_rule { 
    #User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications
    #"Turn off toast notifications on the lock screen" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" "NoToastApplicationNotificationOnLockScreen"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225538
#The Windows Help Experience Improvement Program must be disabled.
Function SV-225538r569185_rule { 
    #User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings
    #"Turn off Help Experience Improvement Program" to "Enabled".
    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0\" "NoImplicitFeedback" "SilentlyContinue"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225539
#Windows Help Ratings feedback must be turned off.
Function SV-225539r569185_rule { 
    #User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings
    #"Turn off Help Ratings" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0\" "NoExplicitFeedback" "SilentlyContinue"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225540
#Zone information must be preserved when saving attachments.
Function SV-225540r569185_rule { 
    #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
    #"Do not preserve zone information in file attachments" to "Disabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "SaveZoneInformation"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225541
#Mechanisms for removing zone information from file attachments must be hidden.
Function SV-225541r569185_rule { 
    #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
    #"Hide mechanisms to remove zone information" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "HideZoneInfoOnProperties"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225542
#The system must notify antivirus when file attachments are opened.
Function SV-225542r569185_rule { 
    #User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager
    #"Notify antivirus programs when opening attachments" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "ScanWithAntiVirus"
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225543
#Users must be prevented from sharing files in their profiles.
Function SV-225543r569185_rule { 
    #User Configuration -> Administrative Templates -> Windows Components -> Network Sharing
    #"Prevent users from sharing files within their profile" to "Enabled". 
    $Value = Check-RegKeyValue "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "NoInPlaceSharing"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225544
#Media Player must be configured to prevent automatic Codec downloads.
Function SV-225544r569185_rule { 
    #User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback
    #"Prevent Codec Download" to "Enabled". 
    #if ((Get-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online).State -eq "Disabled") {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}} #Get-WindowsOptionalFeature is PSv4+
    $Value = Check-RegKeyValue "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer\" "PreventCodecDownload"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225545
#The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.
Function SV-225545r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Access Credential Manager as a trusted caller" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeTrustedCredManAccessPrivilege"){
        $value = $Global:UserRights | Where-Object {$_.UserRight -eq "SeTrustedCredManAccessPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225547
#The Act as part of the operating system user right must not be assigned to any groups or accounts.
Function SV-225547r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Act as part of the operating system" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeTcbPrivilege"){
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeTcbPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225548
#The Allow log on locally user right must only be assigned to the Administrators group.
Function SV-225548r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Allow log on locally" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeInteractiveLogonRight"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225549
#The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.
Function SV-225549r569185_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Allow log on through Remote Desktop Services" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    } 

#V-225550
#The Back up files and directories user right must only be assigned to the Administrators group.
Function SV-225550r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Back up files and directories" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeBackupPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225551
#The Create a pagefile user right must only be assigned to the Administrators group.
Function SV-225551r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Create a pagefile" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeCreatePagefilePrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225552
#The Create a token object user right must not be assigned to any groups or accounts.
Function SV-225552r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Create a token object" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeCreateTokenPrivilege"){
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeCreateTokenPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225553
#The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Function SV-225553r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Create global objects" to only include the following accounts or groups:
    #Administrators
    #Service
    #Local Service
    #Network Service 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeCreateGlobalPrivilege"} | select -ExpandProperty AccountList
    if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225554
#The Create permanent shared objects user right must not be assigned to any groups or accounts.
Function SV-225554r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Create permanent shared objects" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeCreatePermanentPrivilege"){
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeCreatePermanentPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225555
#The Create symbolic links user right must only be assigned to the Administrators group.
Function SV-225555r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
    #"Create symbolic links" to only include the following accounts or groups:
    #Administrators
    #Systems that have the Hyper-V role will also have "Virtual Machines" given this user right. If this needs to be added manually, enter it as "NT Virtual Machine\Virtual Machines". 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeCreateSymbolicLinkPrivilege"} | select -ExpandProperty AccountList
    if ($value.Count -eq 1 -and $value -contains "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif ($value.Count -eq 2 -and $value -contains "Administrators" -and $value -contains "NT Virtual Machine\\Virtual Machines" -and ($Global:installedFeatures.Name -contains "Hyper-V")) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225556
#The Debug programs user right must only be assigned to the Administrators group.
Function SV-225556r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Debug programs" to only include the following accounts or groups:
    #Administrators 
    $value = $Global:UserRights | Where-Object {$_.UserRight -eq "SeDebugPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators" -or $value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225557
#The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems.
Function SV-225557r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny access to this computer from the network" to include the following: Guests Group
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
    if ($value -eq "Guests") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225558
#The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.
Function SV-225558r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on as a batch job" to include the following:
    #Domain Systems Only:
    #Enterprise Admins Group
    #Domain Admins Group
    #
    #All Systems:
    #Guests Group 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
    if ($Global:PartOfDomain) {
            if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
    else {
        if ($value -eq "Guests"){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225559
#The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.
Function SV-225559r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on as a service" to include the following for domain-joined systems:
    #Enterprise Admins Group
    #Domain Admins Group
    #
    #Configure the "Deny log on as a service" for nondomain systems to include no entries (blank). 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
    if ($Global:PartOfDomain) {
        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        if ($value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225560
#The Deny log on locally user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.
Function SV-225560r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on locally" to include the following:
    #Domain Systems Only:
    #Enterprise Admins Group
    #Domain Admins Group
    #
    #All Systems:
    #Guests Group 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
    if ($Global:PartOfDomain) {
        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        if ($value -eq "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225561
#The Deny log on through Remote Desktop Services user right on member servers must be configured to prevent access from highly privileged domain accounts and all local accounts on domain systems, and from unauthenticated access on all systems.
Function SV-225561r569185_rule { 
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
    #"Deny log on through Remote Desktop Services" to include the following:
    #Domain Systems Only:
    #Enterprise Admins group
    #Domain Admins group
    #Local account (see Note below)
    #
    #All Systems:
    #Guests group
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
    if ($Global:PartOfDomain) {
        if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Local account" -and $value -match "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        if ($value -eq "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-225562
#Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.
Function SV-225562r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeEnableDelegationPrivilege"){
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225563
#The Force shutdown from a remote system user right must only be assigned to the Administrators group.
Function SV-225563r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Force shutdown from a remote system" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeRemoteShutdownPrivilege"} | select -ExpandProperty AccountList
    if ($value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225564
#The Generate security audits user right must only be assigned to Local Service and Network Service.
Function SV-225564r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Generate security audits" to only include the following accounts or groups:
    #Local Service
    #Network Service 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeAuditPrivilege"} | select -ExpandProperty AccountList
    if ($value.Count -eq 2 -and $value -contains "Local Service" -and $value -contains "Network Service") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225565
#The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Function SV-225565r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Impersonate a client after authentication" to only include the following accounts or groups:
    #Administrators
    #Service
    #Local Service
    #Network Service 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeImpersonatePrivilege"} | select -ExpandProperty AccountList
    if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225566
#The Increase scheduling priority user right must only be assigned to the Administrators group.
Function SV-225566r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Increase scheduling priority" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeIncreaseBasePriorityPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225567
#The Load and unload device drivers user right must only be assigned to the Administrators group.
Function SV-225567r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Load and unload device drivers" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeLoadDriverPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225568
#The Lock pages in memory user right must not be assigned to any groups or accounts.
Function SV-225568r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Lock pages in memory" to be defined but containing no entries (blank). 
    if($Global:UserRights.UserRight -contains "SeLockMemoryPrivilege"){
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeLockMemoryPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225569
#The Manage auditing and security log user right must only be assigned to the Administrators group.
Function SV-225569r569185_rule { 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225570
#The Modify firmware environment values user right must only be assigned to the Administrators group.
Function SV-225570r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Modify firmware environment values" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeSystemEnvironmentPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225571
#The Perform volume maintenance tasks user right must only be assigned to the Administrators group.
Function SV-225571r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Perform volume maintenance tasks" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeManageVolumePrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225572
#The Profile single process user right must only be assigned to the Administrators group.
Function SV-225572r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Profile single process" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeProfileSingleProcessPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225573
#The Restore files and directories user right must only be assigned to the Administrators group.
Function SV-225573r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Restore files and directories" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeRestorePrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-225574
#The Take ownership of files or other objects user right must only be assigned to the Administrators group.
Function SV-225574r569185_rule { 
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Take ownership of files or other objects" to only include the following accounts or groups:
    #Administrators 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeTakeOwnershipPrivilege"} | select -ExpandProperty AccountList
    if ($Value -eq "Administrators") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }