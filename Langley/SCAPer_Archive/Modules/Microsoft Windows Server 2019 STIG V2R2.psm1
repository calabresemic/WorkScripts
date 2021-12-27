<#
Module Created by Michael Calabrese (1468714589)
Designed to be used with SCAPer script v5+

Microsoft Windows Server 2019 Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 04 May 2021
#>

#V-205625
#Windows Server 2019 must be configured to audit Account Management - Security Group Management successes.
Function SV-205625r569188_rule {
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

#V-205626
#Windows Server 2019 must be configured to audit Account Management - User Account Management successes.
Function SV-205626r569188_rule {
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

#V-205627
#Windows Server 2019 must be configured to audit Account Management - User Account Management failures.
Function SV-205627r569188_rule {
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

#V-205628
#Windows Server 2019 must be configured to audit Account Management - Computer Account Management successes.
Function SV-205628r569188_rule {
    #Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management
    #"Audit Computer Account Management" with "Success" selected.  
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if (($Global:auditpol -match "Computer Account Management") -match "Success") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205629
#Windows Server 2019 must have the number of allowed bad logon attempts configured to three or less.
Function SV-205629r569188_rule {
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


#V-205630
#Windows Server 2019 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater.
Function SV-205630r569188_rule {
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

#V-205631
#Windows Server 2019 required legal notice must be configured to display before console logon.
Function SV-205631r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #“Interactive Logon: Message text for users attempting to log on” as outlined in the check. 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeText"
    if ($Value -eq $LegalNotice) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
}

#V-205632
#Windows Server 2019 title for legal banner dialog box must be configured with the appropriate text.
Function SV-205632r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "LegalNoticeCaption"
    if ($Value -eq "DoD Notice and Consent Banner" -or $Value -eq "US Department of Defense Warning Statement") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205633
#Windows Server 2019 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.
Function SV-205633r569188_rule {
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

#V-205634
#Windows Server 2019 must be configured to audit logon successes.
Function SV-205634r569188_rule {
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

#V-205635
#Windows Server 2019 must be configured to audit logon failures.
Function SV-205635r569188_rule {
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

#V-205636
#Windows Server 2019 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.
Function SV-205636r569188_rule {
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

#V-205637
#Windows Server 2019 Remote Desktop Services must be configured with the client connection encryption set to High Level.
Function SV-205637r569188_rule {
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

#V-205638
#Windows Server 2019 command line data must be included in process creation events.
Function SV-205638r569188_rule {
    #This requirement is NA for the initial release of Windows 2012. It is applicable to Windows 2012 R2.
    #Computer Configuration -> Administrative Templates -> System -> Audit Process Creation
    #"Include command line in process creation events" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" "ProcessCreationIncludeCmdLine_Enabled"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205639
#Windows Server 2019 PowerShell script block logging must be enabled.
Function SV-205639r569188_rule {
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

#V-205640
#Windows Server 2019 permissions for the Application event log must prevent access by non-privileged accounts.
Function SV-205640r569188_rule {
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

#V-205641
#Windows Server 2019 permissions for the Security event log must prevent access by non-privileged accounts.
Function SV-205641r569188_rule {
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

#V-205642
#Windows Server 2019 permissions for the System event log must prevent access by non-privileged accounts.
Function SV-205642r569188_rule {
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

#V-205643
#Windows Server 2019 Manage auditing and security log user right must only be assigned to the Administrators group.
Function SV-205643r569188_rule {
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment 
    #"Manage auditing and security log" to only include the following accounts or groups:
    #Administrators 
    #Auditors groups is allowed
    #Applications can have this right, but only with documentation
    if($Global:ServerRole -eq 2){
        $value=($Global:UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList) -join ","
        Switch ($Global:DomainName) {
            AREA52        {$compare="Administrators,AFNOAPPS\Exchange Servers,AREA52\Exchange Enterprise Servers,LOCAL SERVICE"}
            AFNOAPPS      {$compare="Administrators,AFNOAPPS\Exchange Servers"}
            Default       {$compare="Administrators"}
            }

        if ($Value -eq $compare) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq "Administrators") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205644
#Windows Server 2019 must force audit policy subcategory settings to override audit policy category settings.
Function SV-205644r569188_rule {
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

#V-205645
#Windows Server 2019 domain controllers must have a PKI server certificate.
Function SV-205645r569188_rule {
    if($Global:ServerRole -eq 3){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        if ((Get-ChildItem Cert:\LocalMachine\my) -ne $null) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205646
#Windows Server 2019 domain Controller PKI certificates must be issued by the DoD PKI or an approved External Certificate Authority (ECA).
Function SV-205646r569188_rule {
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
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
        if ($DoDorECA -contains $issuer) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
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
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        }
    }
            
#V-205647
#Windows Server 2019 PKI certificates associated with user accounts must be issued by a DoD PKI or an approved External Certificate Authority (ECA).
Function SV-205647r569188_rule {
    #This requires manual validation
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        throw
        }
    }

#V-205648
#Windows Server 2019 must have the DoD Root Certificate Authority (CA) certificates installed in the Trusted Root Store.
Function SV-205648r569280_rule {
    Remove-Variable certs,HasDodRoot2,HasDodRoot3,HasDodRoot4,HasDodRoot5 -EA SilentlyContinue
    $certs = Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*"
    $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" -and $_.NotAfter -gt $currDate}
    $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "D73CA91102A2204A36459ED32213B467D7CE97FB" -and $_.NotAfter -gt $currDate}
    $HasDodRoot4 = $certs | Where {$_.subject -eq "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "B8269F25DBD937ECAFD4C35A9838571723F2D026" -and $_.NotAfter -gt $currDate}
    $HasDodRoot5 = $certs | Where {$_.subject -eq "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "4ECB5CC3095670454DA1CBD410FC921F46B8564B" -and $_.NotAfter -gt $currDate}
    if ($HasDodRoot2 -and $HasDodRoot3 -and $HasDodRoot4 -and $HasDodRoot5) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205649
#Windows Server 2019 must have the DoD Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems.
Function SV-205649r573795_rule {
    if ($Global:IsNIPR) {
        Remove-Variable certs,ExpCert,HasDodRoot2,HasDodRoot3 -EA SilentlyContinue
        $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}
        $ExpCert = $certs | Where {$_.NotAfter -lt $currDate}
        $HasDodRoot2 = $certs | Where {$_.subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "22BBE981F0694D246CC1472ED2B021DC8540A22F"}
        $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "AC06108CA348CC03B53795C64BF84403C1DBD341"}
        if ($ExpCert -and $HasDodRoot2 -and $HasDodRoot3) {
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

#V-205650
#Windows Server 2019 must have the US DoD CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems.
Function SV-205650r573797_rule {
    if ($Global:IsNIPR) {
        Remove-Variable certs,ExpCert,HasDodRoot3 -EA SilentlyContinue
        $certs = Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*CCEB Interoperability*"}
        $ExpCert = $certs | Where {$_.NotAfter -lt $currDate}
        $HasDodRoot3 = $certs | Where {$_.subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" -and $_.Thumbprint -eq "929BF3196896994C0A201DF4A5B71F603FEFBF2E"}
        if ($ExpCert -and $HasDodRoot3) {
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

#V-205651
#Windows Server 2019 users must be required to enter a password to access private keys stored on the computer.
Function SV-205651r569188_rule {
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

#V-205652
#Windows Server 2019 must have the built-in Windows password complexity policy enabled.
Function SV-205652r569188_rule {
    #Computer Configuration >> Windows Settings -> Security Settings >> Account Policies >> Password Policy 
    #"Password must meet complexity requirements" to "Enabled". 
    if($Global:passwordpolicy.ComplexityEnabled -eq $true){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205653
#Windows Server 2019 reversible password encryption must be disabled.
Function SV-205653r569188_rule {
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

#V-205654
#Windows Server 2019 must be configured to prevent the storage of the LAN Manager hash of passwords.
Function SV-205654r569188_rule {
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

#V-205655
#Windows Server 2019 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers.
Function SV-205655r569188_rule {
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

#V-205656
#Windows Server 2019 minimum password age must be configured to at least one day.
Function SV-205656r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Minimum password age" to at least "1" day. 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.MinPasswordAge -ge [timespan]"1.00:00"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205657
#Windows Server 2019 passwords for the built-in Administrator account must be changed at least every 60 days.
Function SV-205657r569188_rule {
    #Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet
    if($Global:ServerRole -eq 3){
        if($Global:Admin.PasswordLastSet -gt (Get-Date).AddYears(-1)){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="Technician should change the local admin password."}
            }
        }
    elseif($Global:ServerRole -eq 2){
        if($Global:Admin.PasswordLastSet -gt (get-date).AddYears(-1)) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The password was last set: $($Global:Admin.PasswordLastSet)"}
            }
        }
    }

#V-205658
#Windows Server 2019 passwords must be configured to expire.
Function SV-205658r569188_rule {
    if($Global:ServerRole -eq 2){
        $SCLFalse=$users | where {$_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true -and $_.smartcardlogonrequired -eq $false -and $_.extensionAttribute3 -ne "SVC"}
        if($SCLFalse.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following accounts were found: `n$SCLFalse"}
            }
        }
    else{
        if(((Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' and PasswordExpires='False'").Name).count -eq 0) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205659
#Windows Server 2019 maximum password age must be configured to 60 days or less.
Function SV-205659r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy
    #"Maximum password age" to "60" days or less (excluding "0" which is unacceptable). 
    #This is set in the default domain policy, but the STIG says to check locally.
    if($Global:passwordpolicy.MaxPasswordAge -le [timespan]"60.00:00:00" -and $Global:passwordpolicy.MaxPasswordAge -gt [timespan]0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205660
#Windows Server 2019 password history must be configured to 24 passwords remembered.
Function SV-205660r569188_rule {
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

#V-205662
#Windows Server 2019 minimum password length must be configured to 14 characters.
Function SV-205662r569188_rule {
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

#V-205663
#Windows Server 2019 local volumes must use a format that supports NTFS attributes.
Function SV-205663r569188_rule {
    #All local volumes must be NTFS or ReFS
    #Check to see if there's any local volumes that AREN'T compliant
    #if (Get-WMIObject -Class Win32_Volume | Where {$_.DriveType -eq 3 -and ($_.FileSystem -ne "NTFS" -and $_.FileSystem -ne "ReFS")}) {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    if ([System.IO.DriveInfo]::getdrives() | Where-Object {$_.drivetype -eq "fixed" -and $_.driveformat -ne "NTFS" -and $_.driveformat -ne "ReFS"}) {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205664
#Windows Server 2019 non-administrative accounts or groups must only have print permissions on printer shares.
Function SV-205664r569188_rule {
    $printShares = get-printer * -full -EA SilentlyContinue | Where {$_.shared -eq $true}
    if ($printShares.count -eq 0) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205665
#Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers.
Function SV-205665r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $Global:UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
        if ($value.count -eq 3 -and $value -contains "Administrators" -and $value -contains "Authenticated Users" -and $value -contains "Enterprise Domain Controllers") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        elseif ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205666
#Windows Server 2019 Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group on domain controllers.
Function SV-205666r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Allow log on through Remote Desktop Services" to only include the following accounts or groups:
    #Administrators 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
        if ($Value -eq "Administrators") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205667
#Windows Server 2019 Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.
Function SV-205667r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny access to this computer from the network" to include the following: Guests Group
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
        if ($value -eq "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205668
#Windows Server 2019 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.
Function SV-205668r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on as a batch job" to include the following:
    #Guests Group 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyBatchLogonRight"} | select -ExpandProperty AccountList
        if ($value -eq "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205669
#Windows Server 2019 Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.
Function SV-205669r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on as a service" to include no entries (blank). 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:UserRights.UserRight -contains "SeDenyServiceLogonRight"){
            $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyServiceLogonRight"} | select -ExpandProperty AccountList
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
    }

#V-205670
#Windows Server 2019 Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.
Function SV-205670r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on locally" to include the following:
    #Guests Group 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList
        if ($value -contains "Guests") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205671
#Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and standalone systems.
Function SV-205671r569188_rule {
#Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Access this computer from the network" to only include the following accounts or groups:
    #Administrators
    #Authenticated Users
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $Global:UserRights | Where-Object {$_.UserRight -eq "SeNetworkLogonRight"} | select -ExpandProperty AccountList
        if ($value.count -eq 2 -and $value -contains "Administrators" -and $value -contains "Authenticated Users") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205672
#Windows Server 2019 Deny access to this computer from the network user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems.
Function SV-205672r569188_rule {
#Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList
        if($Global:PartOfDomain){
            if($value -contains "Local account and member of Administrators group" -and $Value -match "\\Enterprise Admins" -and $Value -match "\\Domain Admins"){
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
                }
        else{
            if ($value -eq "Guests") {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        }
    }

#V-205673
#Windows Server 2019 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.
Function SV-205673r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
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
    }

#V-205674
#Windows Server 2019 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.
Function SV-205674r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
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
    }

#V-205675
#Windows Server 2019 Deny log on locally user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.
Function SV-205675r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
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
    }

#V-205676
#Windows Server 2019 Allow log on locally user right must only be assigned to the Administrators group.
Function SV-205676r569188_rule {
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

#V-205678
#Windows Server 2019 must not have the Fax Server role installed.
Function SV-205678r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "Fax"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205679
#Windows Server 2019 must not have the Peer Name Resolution Protocol installed.
Function SV-205679r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "PNRP"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205680
#Windows Server 2019 must not have Simple TCP/IP Services installed.
Function SV-205680r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "Simple-TCPIP"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205681
#Windows Server 2019 must not have the TFTP Client installed.
Function SV-205681r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "TFTP-Client"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205682
#Windows Server 2019 must not the Server Message Block (SMB) v1 protocol installed.
Function SV-205682r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "FS-SMB1"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205683
#Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.
Function SV-205683r569188_rule {
    #if 73523 and 73519 are configured this is not a finding. No way to guarantee they go before this so I'll just check twice.
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" "SMB1"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205684
#Windows Server 2019 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.
Function SV-205684r569188_rule {
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure MrxSmb10 driver".

    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Configure SMBv1 client (extra setting needed for pre-Win8.1/2012R2)" to "Enabled" with the following three lines of text entered for "Configure LanmanWorkstation Dependencies":
    #Bowser
    #MRxSmb20
    #NSI
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" "Start"
    if ($Value -eq "4") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205685
#Windows Server 2019 must not have Windows PowerShell 2.0 installed.
Function SV-205685r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "PowerShell-v2"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205686
#Windows Server 2019 must prevent the display of slide shows on the lock screen.
Function SV-205686r569188_rule {
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

#V-205687
#Windows Server 2019 must have WDigest Authentication disabled.
Function SV-205687r569188_rule {
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

#V-205688

#Windows Server 2019 downloading print driver packages over HTTP must be turned off.
Function SV-205688r569188_rule {
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

#V-205689
#Windows Server 2019 printing over HTTP must be turned off.
Function SV-205689r569188_rule {
    #Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings
    #"Turn off printing over HTTP" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows NT\Printers\" "DisableHTTPPrinting"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205690
#Windows Server 2019 network selection user interface (UI) must not be displayed on the logon screen.
Function SV-205690r569188_rule {
    #Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not display network selection UI" to "Enabled". 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "DontDisplayNetworkSelectionUI"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205691
#Windows Server 2019 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
Function SV-205691r569188_rule {
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

#V-205692
#Windows Server 2019 Windows Defender SmartScreen must be enabled.
Function SV-205692r569188_rule {
    if(!($Global:IsNIPR)){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\" "EnableSmartScreen"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205693
#Windows Server 2019 must disable Basic authentication for RSS feeds over HTTP.
Function SV-205693r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds
    #"Turn on Basic feed authentication over HTTP" to "Disabled". 
    if(Get-ItemProperty -Name AllowBasicAuthInClear -Path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds' -ErrorAction SilentlyContinue){
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\" "AllowBasicAuthInClear"
        if ($Value -eq "0") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205694
#Windows Server 2019 must prevent Indexing of encrypted files.
Function SV-205694r569188_rule {
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" "AllowIndexingEncryptedStoresOrItems"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205695
#Windows Server 2019 domain controllers must run on a machine dedicated to that function.
Function SV-205695r569188_rule {
    #Can't be checked
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details='No other application-related components are listed in services.'}
        }
    }

#V-205696
#Windows Server 2019 local users on domain-joined member servers must not be enumerated.
Function SV-205696r569188_rule {
    #Computer Configuration -> Administrative Templates -> System -> Logon
    #"Enumerate local users on domain-joined computers" to "Disabled". 
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\System\" "EnumerateLocalUsers"
        if ($Value -eq "0") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205697
#Windows Server 2019 must not have the Microsoft FTP service installed unless required by the organization.
Function SV-205697r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "Web-Ftp-Service"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205698
#Windows Server 2019 must not have the Telnet Client installed.
Function SV-205698r569188_rule {
    #If the Web-DAV-Publishing role is not installed this is not a finding
    if($Global:installedFeatures.name -notcontains "Telnet-Client"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Not_Reviewed';Comment='';Finding_Details=''}
        }
    }

#V-205700
#Windows Server 2019 accounts must require passwords.
Function SV-205700r569188_rule {
    if($Global:ServerRole -eq 2){
        $PWDRQ=$Global:users | where {$_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true}
        if($PWDRQ.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following accounts were found: `n$PWDRQ"}
            }
    }
    else{
        $nopwd = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount
        if($nopwd.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205702
#Windows Server 2019 Kerberos user logon restrictions must be enforced.
Function SV-205702r569188_rule {
    #Default Domain Policy
    #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
    #"Enforce user logon restrictions" to "Enabled".
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $secsettings | Where-Object {$_.KeyName -eq "TicketValidateClient"} | select -ExpandProperty Setting
        if ($Value -eq $true) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205703
#Windows Server 2019 Kerberos service ticket maximum lifetime must be limited to 600 minutes or less.
Function SV-205703r569188_rule {
    #Default Domain Policy
    #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
    #"Maximum lifetime for service ticket" to a maximum of 600 minutes, but not 0 which equates to "Ticket doesn't expire". 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $secsettings | Where-Object {$_.KeyName -eq "MaxServiceAge"} | select -ExpandProperty Setting
        if ($value -le "600"-and $value -gt 0) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205704
#Windows Server 2019 Kerberos user ticket lifetime must be limited to 10 hours or less.
Function SV-205704r569188_rule {
    #Default Domain Policy
    #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
    #"Maximum lifetime for user ticket" to a maximum of 10 hours, but not 0 which equates to "Ticket doesn't expire".
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $secsettings | Where-Object {$_.KeyName -eq "MaxTicketAge"} | select -ExpandProperty Setting
        if ($value -le "10"-and $value -gt 0) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205705
#Windows Server 2019 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less.
Function SV-205705r569188_rule {
    #Default Domain Policy
    #Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
    #"Maximum lifetime for user ticket renewal" to a maximum of 7 days or less. 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $secsettings | Where-Object {$_.KeyName -eq "MaxRenewAge"} | select -ExpandProperty Setting
        if ($value -le "7") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205706
#Windows Server 2019 computer clock synchronization tolerance must be limited to five minutes or less.
Function SV-205706r569188_rule {
    #Default Domain Policy
    #Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
    #"Maximum tolerance for computer clock synchronization" to a maximum of 5 minutes or less.
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value = $secsettings | Where-Object {$_.KeyName -eq "MaxClockSkew"} | select -ExpandProperty Setting
        if ($value -le "5") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205707
#Windows Server 2019 outdated or unused accounts must be removed or disabled.
Function SV-205707r569188_rule {  
    #Can't be checked
    if($Global:ServerRole -eq 3){
        if((Get-LocalUser).enabled -contains $true){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
    } else {
        Throw
        }
    }

#V-205708
#Windows Server 2019 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
Function SV-205708r569188_rule {
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Network security: Configure encryption types allowed for Kerberos" is configured, only the following selections are allowed:
    #AES128_HMAC_SHA1
    #AES256_HMAC_SHA1
    #Future encryption types 

    #This value is stored in bits.  The 1 bit is DES_CBC_CRC, the 2 bit is DES_CBC_MD5, the 4 bit is RC4_HMAC_MD5, the 8 bit is AES128_HMAC_SHA1, the 16 bit is AES256_HMAC_SHA1, and for "Future encryption types" they just turn on every other bit.
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes"
    #if (!($Value -band 1) -and !($value -band 2) -and !($value -band 4) -and $value -band 8 -and $value -band 16) {return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}} #These checks make sure each bit flag is set properly.  I'm an idiot in trying to be smart by doing this complicated, because checking for every other bit is stupid
    if ($value -eq "2147483640") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205709
#Windows Server 2019 must have the built-in guest account disabled.
Function SV-205709r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Guest account status" to "Disabled".
    if(($Global:Guest).Enabled -eq $false){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205711
#Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication.
Function SV-205711r569188_rule {
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

#V-205712
#Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication.
Function SV-205712r569188_rule {
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

#V-205713
#Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication.
Function SV-205713r569188_rule {
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

#V-205714
#Windows Server 2019 administrator accounts must not be enumerated during elevation.
Function SV-205714r569188_rule {
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

#V-205715
#Windows Server 2019 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers.
Function SV-205715r569188_rule {
    #Computer Configuration >> Administrative Templates >> MS Security Guide
    #"Apply UAC restrictions to local accounts on network logons" to "Enabled".
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "LocalAccountTokenFilterPolicy"
        if ($Value -eq "0") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }
                
#V-205716
#Windows Server 2019 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.
Function SV-205716r569188_rule {
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

#V-205717
#Windows Server 2019 User Account Control must, at a minimum, prompt administrators for consent on the secure desktop.
Function SV-205717r569188_rule {
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent".
    #More secure options for this setting would also be acceptable (e.g., Prompt for credentials, Prompt for consent (or credentials) on the secure desktop). 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
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

#V-205718
#Windows Server 2019 User Account Control must be configured to detect application installations and prompt for elevation.
Function SV-205718r569188_rule {
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

#V-205719
#Windows Server 2019 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations.
Function SV-205719r569188_rule {
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

#V-205720
#Windows Server 2019 User Account Control (UAC) must virtualize file and registry write failures to per-user locations.
Function SV-205720r569188_rule {
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

#V-205721
#Windows Server 2019 non-system-created file shares must limit access to groups that require it.
Function SV-205721r569188_rule {
    #Check all non system shares to see if theres Everyone permission with allow.  If not, it's sure constrained permissions
    $BaseDFS=$(Get-ADComputer $env:COMPUTERNAME).distinguishedName.Split(',')[1].trim('OU=').replace(' ','_')
    $Builtinshares=@("ADMIN$","IPC$","C$","D$","E$","F$","S$")
    $allowedshares=@("NETLOGON","SYSVOL","EMIE","logonscripts","scripts","startupscripts")
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

#V-205722
#Windows Server 2019 Remote Desktop Services must prevent drive redirection.
Function SV-205722r569188_rule {
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

#V-205723
#Windows Server 2019 data files owned by users must be on a different logical partition from the directory server data files.
Function SV-205723r569188_rule {
    #Can't be checked
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details='We do not keep user shares on Domain Controllers.'}
        }
    }

#V-205724
#Windows Server 2019 must not allow anonymous enumeration of shares.
Function SV-205724r569188_rule {
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

#V-205725
#Windows Server 2019 must restrict anonymous access to Named Pipes and Shares.
Function SV-205725r569188_rule {
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

#V-205726
#Windows Server 2019 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity.
Function SV-205726r569188_rule {
    #I figured it out - Calabrese
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $LDAPAdminLimits=dsquery * "cn=Default Query Policy,cn=Query-Policies,cn=Directory Service, cn=Windows NT,cn=Services,$((Get-ADRootDSE).configurationNamingContext)" -attr LDAPAdminLimits
        $MaxConnIdleTime=($LDAPAdminLimits.Split(";") | Select-String -Pattern MaxConnIdleTime).ToString().TrimStart(" MaxConnIdleTime=")
        if([int]$MaxConnIdleTime -le 300){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="This is set to $MaxConnIdleTime"}
            }
        }
    }

#V-205728
#Windows Server 2019 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where Host Based Security System (HBSS) is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).
Function SV-205728r569188_rule {
    if($Global:installedprograms.displayname -contains "McAfee Agent"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205729
#Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout successes.
Function SV-205729r569188_rule {
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

#V-205730
#Windows Server 2019 must be configured to audit Logon/Logoff - Account Lockout failures.
Function SV-205730r569188_rule {
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

#V-205731
#Windows Server 2019 Event Viewer must be protected from unauthorized modification and deletion.
Function SV-205731r569188_rule {
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

#V-205732
#Windows Server 2019 Deny log on through Remote Desktop Services user right on domain controllers must be configured to prevent unauthenticated access.
Function SV-205732r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Deny log on through Remote Desktop Services" to include the following:
    #Guests Group 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
        if ($value -eq "Guests"){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205733
#Windows Server 2019 Deny log on through Remote Desktop Services user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems.
Function SV-205733r569188_rule {
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment
    #"Deny log on through Remote Desktop Services" to include the following:
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if ($Global:PartOfDomain) {
            $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList
            if ($value -match "\\Enterprise Admins" -and $value -match "\\Domain Admins" -and $value -match "Local account" -and $value -match "Guests") {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        else{
            if ($value -eq "Guests") {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        }
    }

#V-205734
#Windows Server 2019 permissions for the system drive root directory (usually C:\) must conform to minimum requirements.
Function SV-205734r569188_rule {
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

#V-205735
#Windows Server 2019 permissions for program file directories must conform to minimum requirements.
Function SV-205735r569188_rule {
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
                
#V-205736
#Windows Server 2019 permissions for the Windows installation directory must conform to minimum requirements.
Function SV-205736r569188_rule {
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

#V-205737
#Windows Server 2019 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
Function SV-205737r569188_rule {
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

    if($securityperms -and $softwareperms -and $systemperms){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205738
#Windows Server 2019 must only allow administrators responsible for the domain controller to have Administrator rights on the system.
Function SV-205738r569188_rule {
    #Can't be checked
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        throw
        }
    }
            
#V-205739
#Windows Server 2019 permissions on the Active Directory data files must only allow System and Administrators access.
Function SV-205739r569188_rule {
    #Since anyone that opens the NTDS folder gets added with full control, this check makes sure that any extra accounts are admin accounts based on the level codes in the naming convention TO.
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $NTDSacl=(Get-Acl E:\Windows\NTDS).Access
        $accounts=($NTDSacl | Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators"}).IdentityReference.Value
                
        if($accounts.count -eq 0){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        elseif($accounts -match "S-\d-\d+-(\d+-){1,14}\d+"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="Orphaned SIDs found in the ACL."}
            }
        else{
            foreach($account in $accounts){
                if($account.split('.')[-1] -notin $Global:Adminlevelcodes){
                    return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                    }
                }
            }
        }
    }

#V-205740
#Windows Server 2019 Active Directory SYSVOL directory must have the proper access control permissions.
Function SV-205740r569188_rule {
if($Global:ServerRole -eq 3){
    return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
    }
else{
        $FSR=@('FullControl','268435456','Modify','-536805376')
        $IR=@('CREATOR OWNER','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','NT SERVICE\TrustedInstaller')
                    
        $sysvolacl=(Get-Acl E:\Windows\SYSVOL).Access
        if($windowsacl | Where-Object {$_.FileSystemRights -in $FSR -and $_.IdentityReference -notin $IR}){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205744
#Windows Server 2019 Add workstations to domain user right must only be assigned to the Administrators group on domain controllers.
Function SV-205744r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Add workstations to domain" to only include the following accounts or groups:
    #Administrators 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeMachineAccountPrivilege"} | select -ExpandProperty AccountList
        if ($Value -eq "Administrators") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205745
#Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must only be assigned to the Administrators group on domain controllers.
Function SV-205745r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Enable computer and user accounts to be trusted for delegation" to include the following:
    #Administrators 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeEnableDelegationPrivilege"} | select -ExpandProperty AccountList
        if ($value -contains "Administrators") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205746
#Windows Server 2019 must only allow administrators responsible for the member server or standalone system to have Administrator rights on the system.
Function SV-205746r569188_rule {
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205747
#Windows Server 2019 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone systems.
Function SV-205747r569188_rule {
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" "RestrictRemoteSAM"
        if ($Value -eq "O:BAG:BAD:(A;;RC;;;BA)") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205748
#Windows Server 2019 Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts on domain-joined member servers and standalone systems.
Function SV-205748r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank). 
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
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
    }

#V-205749
#Windows Server 2019 Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.
Function SV-205749r569188_rule {
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

#V-205750
#Windows Server 2019 Act as part of the operating system user right must not be assigned to any groups or accounts.
Function SV-205750r569188_rule {
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
                
#V-205751
#Windows Server 2019 Back up files and directories user right must only be assigned to the Administrators group.
Function SV-205751r569188_rule {
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
                
#V-205752
#Windows Server 2019 Create a pagefile user right must only be assigned to the Administrators group.
Function SV-205752r569188_rule {
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
                
#V-205753
#Windows Server 2019 Create a token object user right must not be assigned to any groups or accounts.
Function SV-205753r569188_rule {
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
                
#V-205754
#Windows Server 2019 Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Function SV-205754r569188_rule {
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

#V-205755
#Windows Server 2019 Create permanent shared objects user right must not be assigned to any groups or accounts.
Function SV-205755r569188_rule {
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

#V-205756
#Windows Server 2019 Create symbolic links user right must only be assigned to the Administrators group.
Function SV-205756r569188_rule {
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

#V-205757
#Windows Server 2019 Debug programs: user right must only be assigned to the Administrators group.
Function SV-205757r569188_rule {
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
                
#V-205758
#Windows Server 2019 Force shutdown from a remote system user right must only be assigned to the Administrators group.
Function SV-205758r569188_rule {
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
                
#V-205759
#Windows Server 2019 Generate security audits user right must only be assigned to Local Service and Network Service.
Function SV-205759r569188_rule {
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

#V-205760
#Windows Server 2019 Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.
Function SV-205760r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment
    #"Impersonate a client after authentication" to only include the following accounts or groups:
    #Administrators
    #Service
    #Local Service
    #Network Service 
    $value=$Global:UserRights | Where-Object {$_.UserRight -eq "SeImpersonatePrivilege"} | select -ExpandProperty AccountList as
    if ($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "Network Service") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif($Global:DomainName -eq "AFNOAPPS"){
        if($value.Count -eq 4 -and $value -contains "Administrators" -and $value -contains "Service" -and $value -contains "Local Service" -and $value -contains "AFNOAPPS\IIS_WPG") {
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

#V-205761
#Windows Server 2019 Increase scheduling priority: user right must only be assigned to the Administrators group.
Function SV-205761r569188_rule {
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

#V-205762
#Windows Server 2019 Load and unload device drivers user right must only be assigned to the Administrators group.
Function SV-205762r569188_rule {
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

#V-205763
#Windows Server 2019 Lock pages in memory user right must not be assigned to any groups or accounts.
Function SV-205763r569188_rule {
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
                
#V-205764
#Windows Server 2019 Modify firmware environment values user right must only be assigned to the Administrators group.
Function SV-205764r569188_rule {
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

#V-205765
#Windows Server 2019 Perform volume maintenance tasks user right must only be assigned to the Administrators group.
Function SV-205765r569188_rule {
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

#V-205766
#Windows Server 2019 Profile single process user right must only be assigned to the Administrators group.
Function SV-205766r569188_rule {
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
                
#V-205767
#Windows Server 2019 Restore files and directories user right must only be assigned to the Administrators group.
Function SV-205767r569188_rule {
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
                
#V-205768
#Windows Server 2019 Take ownership of files or other objects user right must only be assigned to the Administrators group.
Function SV-205768r569188_rule {
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
                
#V-205769
#Windows Server 2019 must be configured to audit Account Management - Other Account Management Events successes.
Function SV-205769r569188_rule {
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

#V-205770
#Windows Server 2019 must be configured to audit Detailed Tracking - Process Creation successes.
Function SV-205770r569188_rule {
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

#V-205771
#Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change successes.
Function SV-205771r569188_rule {
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

#V-205772
#Windows Server 2019 must be configured to audit Policy Change - Audit Policy Change failures.
Function SV-205772r569188_rule {
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

#V-205773
#Windows Server 2019 must be configured to audit Policy Change - Authentication Policy Change successes.
Function SV-205773r569188_rule {
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

#V-205774
#Windows Server 2019 must be configured to audit Policy Change - Authorization Policy Change successes.
Function SV-205774r569188_rule {
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

#V-205775
#Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use successes.
Function SV-205775r569188_rule {
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

#V-205776
#Windows Server 2019 must be configured to audit Privilege Use - Sensitive Privilege Use failures.
Function SV-205776r569188_rule {
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

#V-205777
#Windows Server 2019 must be configured to audit System - IPsec Driver successes.
Function SV-205777r569188_rule {
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

#V-205778
#Windows Server 2019 must be configured to audit System - IPsec Driver failures.
Function SV-205778r569188_rule {
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

#V-205779
#Windows Server 2019 must be configured to audit System - Other System Events successes.
Function SV-205779r569188_rule {
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

#V-205780
#Windows Server 2019 must be configured to audit System - Other System Events failures.
Function SV-205780r569188_rule {
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

#V-205781
#Windows Server 2019 must be configured to audit System - Security State Change successes.
Function SV-205781r569188_rule {
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

#V-205782
#Windows Server 2019 must be configured to audit System - Security System Extension successes.
Function SV-205782r569188_rule {
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

#V-205783
#Windows Server 2019 must be configured to audit System - System Integrity successes.
Function SV-205783r569188_rule {
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

#V-205784
#Windows Server 2019 must be configured to audit System - System Integrity failures.
Function SV-205784r569188_rule {
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

#V-205785
#Windows Server 2019 Active Directory Group Policy objects must be configured with proper audit settings.
Function SV-205785r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205786
#Windows Server 2019 Active Directory Domain object must be configured with proper audit settings.
Function SV-205786r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205787
#Windows Server 2019 Active Directory Infrastructure object must be configured with proper audit settings.
Function SV-205787r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205788
#Windows Server 2019 Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings.
Function SV-205788r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205789
#Windows Server 2019 Active Directory AdminSDHolder object must be configured with proper audit settings.
Function SV-205789r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205790
#Windows Server 2019 Active Directory RID Manager$ object must be configured with proper audit settings.
Function SV-205790r569188_rule {
    #Idk how to check at least inclusive
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        Throw
        }
    }

#V-205791
#Windows Server 2019 must be configured to audit DS Access - Directory Service Access successes.
Function SV-205791r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
    #"Directory Service Access" with "Success" selected.
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if (($Global:auditpol -match "Directory Service Access") -match "Success") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205792
#Windows Server 2019 must be configured to audit DS Access - Directory Service Access failures.
Function SV-205792r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
    #"Directory Service Access" with "Failure" selected. 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if (($Global:auditpol -match "Directory Service Access") -match "Failure") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205793
#Windows Server 2019 must be configured to audit DS Access - Directory Service Changes successes.
Function SV-205793r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
    #"Directory Service Changes" with "Success" selected. 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if (($Global:auditpol -match "Directory Service Changes") -match "Success") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205794
#Windows Server 2019 must be configured to audit DS Access - Directory Service Changes failures.
Function SV-205794r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access
    #"Directory Service Changes" with "Failure" selected. 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if (($Global:auditpol -match "Directory Service Changes") -match "Failure") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205795
#Windows Server 2019 account lockout duration must be configured to 15 minutes or greater.
Function SV-205795r569188_rule {
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

#V-205796
#Windows Server 2019 Application event log size must be configured to 32768 KB or greater.
Function SV-205796r569188_rule {
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

#V-205797
#Windows Server 2019 Security event log size must be configured to 196608 KB or greater.
Function SV-205797r569188_rule {
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

#V-205798
#Windows Server 2019 System event log size must be configured to 32768 KB or greater.
Function SV-205798r569188_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System 
    #"Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater. 
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize"
    if ($Value -ge 32768) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205800
#The Windows Server 2019 time service must synchronize with an appropriate DoD time source.
Function SV-205800r569188_rule {
    #Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers
    #"Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.
    #If PDC and time set to NTP this assumes that the source is correct. If anything else, it should be NT5DS.
    $timeSettings = W32tm /query /configuration
    $type = ($timeSettings -match "Type: ").trim().split(":")[1].trim().split(" ")[0].trim()
    if ($type -eq "NT5DS") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif($type -eq "NTP" -and ((gwmi win32_computersystem).Name -eq ((Get-ADDomain).PDCEmulator).split(".")[0])){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }
            
#V-205801
#Windows Server 2019 must prevent users from changing installation options.
Function SV-205801r569188_rule {
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

#V-205802
#Windows Server 2019 must disable the Windows Installer Always install with elevated privileges option.
Function SV-205802r569188_rule {
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
            
#V-205803
#Windows Server 2019 system files must be monitored for unauthorized changes.
Function SV-205803r569241_rule {
    if($Global:installedprograms.displayname -contains "McAfee Agent"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205804
#Windows Server 2019 Autoplay must be turned off for non-volume devices.
Function SV-205804r569188_rule {
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

#V-205805
#Windows Server 2019 default AutoRun behavior must be configured to prevent AutoRun commands.
Function SV-205805r569188_rule {
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

#V-205806
#Windows Server 2019 AutoPlay must be disabled for all drives.
Function SV-205806r569188_rule {
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

#V-205808
#Windows Server 2019 must not save passwords in the Remote Desktop Client.
Function SV-205808r569188_rule {
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

#V-205809
#Windows Server 2019 Remote Desktop Services must always prompt a client for passwords upon connection.
Function SV-205809r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security 
    #"Always prompt for password upon connection" to "Enabled". 
    $Value = Check-RegKeyValue "hklm\Software\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205810
#Windows Server 2019 Windows Remote Management (WinRM) service must not store RunAs credentials.
Function SV-205810r569188_rule {
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

#V-205811
#Windows Server 2019 User Account Control approval mode for the built-in Administrator must be enabled.
Function SV-205811r569188_rule {
    #Not Applicable if Server Core
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
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

#V-205812
#Windows Server 2019 User Account Control must automatically deny standard user requests for elevation.
Function SV-205812r569188_rule {
    #UAC requirements are NA on Server Core installations.
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests". 
    if ($Global:IsServerCore) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
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

#V-205813
#Windows Server 2019 User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
Function SV-205813r569188_rule {
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

#V-205814
#Windows Server 2019 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone systems.
Function SV-205814r569188_rule {
    #Computer Configuration -> Administrative Templates -> System -> Remote Procedure Call
    #"Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated". 
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" "RestrictRemoteClients"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205815
#Windows Server 2019 computer account password must not be prevented from being reset.
Function SV-205815r569188_rule {
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

#V-205816
#Windows Server 2019 Windows Remote Management (WinRM) client must not allow unencrypted traffic.
Function SV-205816r569188_rule {
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

#V-205817
#Windows Server 2019 Windows Remote Management (WinRM) service must not allow unencrypted traffic.
Function SV-205817r569188_rule {
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

#V-205819
#Windows Server 2019 must be configured to ignore NetBIOS name release requests except from WINS servers.
Function SV-205819r569188_rule {
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

#V-205820
#Windows Server 2019 domain controllers must require LDAP access signing.
Function SV-205820r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain controller: LDAP server signing requirements" to "Require signing". 
    $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\NTDS\Parameters\" "LDAPServerIntegrity"
    if ($Value -eq "2") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205821
#Windows Server 2019 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.
Function SV-205821r569188_rule {
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

#V-205822
#Windows Server 2019 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to enabled.
Function SV-205822r569188_rule {
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

#V-205823
#Windows Server 2019 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.
Function SV-205823r569188_rule {
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

#V-205824
#Windows Server 2019 must be configured to require a strong session key.
Function SV-205824r569188_rule {
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

#V-205825
#Windows Server 2019 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.
Function SV-205825r569188_rule {
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

#V-205826
#Windows Server 2019 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.
Function SV-205826r569188_rule {
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

#V-205827
#Windows Server 2019 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.
Function SV-205827r569188_rule {
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

#V-205828
#Windows Server 2019 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.
Function SV-205828r569188_rule {
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

#V-205830
#Windows Server 2019 Explorer Data Execution Prevention must be enabled.
Function SV-205830r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off Data Execution Prevention for Explorer" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoDataExecutionPrevention"
    if ($Value -eq "0" -or $Value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205831
#Windows Server 2019 Exploit Protection system-level mitigation, Randomize memory allocations (Bottom-Up ASLR), must be on.
Function SV-205831r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:SysProcessMitigation.ASLR.BottomUp -eq "OFF"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205832
#Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes.
Function SV-205832r569188_rule {
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

#V-205833
#Windows Server 2019 must be configured to audit Account Logon - Credential Validation failures.
Function SV-205833r569188_rule {
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

#V-205834
#Windows Server 2019 must be configured to audit Logon/Logoff - Group Membership successes.
Function SV-205834r569188_rule {
    if (($Global:auditpol -match "Group Membership") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Group Membership") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205835
#Windows Server 2019 must be configured to audit Logon/Logoff - Special Logon successes.
Function SV-205835r569188_rule {
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

#V-205836
#Windows Server 2019 must be configured to audit Object Access - Other Object Access Events successes.
Function SV-205836r569188_rule {
    if (($Global:auditpol -match "Other Object Access Events") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Other Object Access Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205837
#Windows Server 2019 must be configured to audit Object Access - Other Object Access Events failures.
Function SV-205837r569188_rule {
    if (($Global:auditpol -match "Other Object Access Events") -match "Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Other Object Access Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205838
#Windows Server 2019 must be configured to audit logoff successes.
Function SV-205838r569188_rule {
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

#V-205839
#Windows Server 2019 must be configured to audit Detailed Tracking - Plug and Play Events successes.
Function SV-205839r569188_rule {
    if (($Global:auditpol -match "Plug and Play Events") -match "Success") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    elseif (($Global:auditpol -match "Plug and Play Events") -match "Success and Failure") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
       
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205840
#Windows Server 2019 must be configured to audit Object Access - Removable Storage successes.
Function SV-205840r569188_rule {
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

#V-205841
#Windows Server 2019 must be configured to audit Object Access - Removable Storage failures.
Function SV-205841r569188_rule {
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

#V-205842
#Windows Server 2019 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
Function SV-205842r569188_rule {
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

#V-205848
#Windows Server 2019 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
Function SV-205848r569188_rule {
    if((get-tpm).tpmready){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details='Unable to find TPM module.'}
        }
    }

#V-205849
#Windows Server 2019 must be maintained at a supported servicing level.
Function SV-205849r569188_rule {
    if ((Get-WmiObject -Class win32_operatingsystem).buildnumber -ge 17763) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205850
#Windows Server 2019 must use an anti-virus program.
Function SV-205850r569245_rule {
    if ($Global:installedprograms.displayname -contains "mcafee agent") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205851
#Windows Server 2019 must have a host-based intrusion detection or prevention system.
Function SV-205851r569188_rule {
    if ($Global:installedprograms.displayname -contains "McAfee Endpoint Security Firewall") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205852
#Windows Server 2019 must have software certificate installation files removed.
Function SV-205852r569188_rule {
    if ($Global:softcerts.count -eq 0) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following files caused this to be a finding: $Global:softcerts"}
        }
    }

#V-205853
#Windows Server 2019 FTP servers must be configured to prevent anonymous logons.
Function SV-205853r569188_rule {
    if($Global:installedFeatures.name -notcontains "web-ftp-server"){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-205854
#Windows Server 2019 FTP servers must be configured to prevent access to the system drive.
Function SV-205854r569188_rule {
    if($Global:installedFeatures.name -notcontains "web-ftp-server"){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-205855
#Windows Server 2019 must have orphaned security identifiers (SIDs) removed from user rights.
Function SV-205855r569188_rule {
    if($Global:UserRights.Accountlist -match "S-\d-\d+-(\d+-){1,14}\d+"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205856
#Windows Server 2019 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.
Function SV-205856r569188_rule {
    if (Test-Path $env:windir\Panther\setupact.log) {
        if ( (Select-String 'Detected boot environment' -Path "$env:windir\Panther\setupact.log"  -AllMatches).line -replace '.*:\s+' -eq "EFI") {
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

#V-205857
#Windows Server 2019 must have Secure Boot enabled.
Function SV-205857r569188_rule {
    try{
        Confirm-SecureBootUEFI -ErrorAction Stop | Out-Null
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    catch{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205858
#Windows Server 2019 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
Function SV-205858r569188_rule {
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

#V-205859
#Windows Server 2019 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
Function SV-205859r569188_rule {
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

#V-205860
#Windows Server 2019 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.
Function SV-205860r569188_rule {
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

#V-205861
#Windows Server 2019 insecure logons to an SMB server must be disabled.
Function SV-205861r569188_rule {
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" "AllowInsecureGuestAuth"
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205862
#Windows Server 2019 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
Function SV-205862r569188_rule {
    $Value1 = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" "\\*\NETLOGON"
    $Value2 = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" "\\*\SYSVOL"
    if ($Value1 -eq "RequireMutualAuthentication=1,RequireIntegrity=1" -and $value2 -eq "RequireMutualAuthentication=1,RequireIntegrity=1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205863
#Windows Server 2019 must be configured to enable Remote host allows delegation of non-exportable credentials.
Function SV-205863r569188_rule {
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" "AllowProtectedCreds"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205864
#Windows Server 2019 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.
Function SV-205864r569188_rule {
    $check=@()
    $deviceguard=gwmi -Class win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    if($deviceguard.RequiredSecurityProperties -notcontains 2){$check+=$false}
    if($deviceguard.RequiredSecurityProperties -notcontains 3){$check+=$false}
    if($deviceguard.VirtualizationBasedSecurityStatus -ne 2){$check+=$false}
    if($check -contains $false){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details='DeviceGuard failed checks.'}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205865
#Windows Server 2019 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.
Function SV-205865r569188_rule {
    #Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware
    #"Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected. 
    $Value = Check-RegKeyValue "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" "DriverLoadPolicy"
    if ($Value -eq "1" -or $value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205866
#Windows Server 2019 group policy objects must be reprocessed even if they have not changed.
Function SV-205866r569188_rule {
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

#V-205867
#Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (on battery).
Function SV-205867r569188_rule {
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

#V-205868
#Windows Server 2019 users must be prompted to authenticate when the system wakes from sleep (plugged in).
Function SV-205868r569188_rule {
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

#V-205869
#Windows Server 2019 Telemetry must be configured to Security or Basic.
Function SV-205869r569188_rule {
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" "AllowTelemetry"
    if ($Value -eq "0" -or $Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205870
#Windows Server 2019 Windows Update must not obtain updates from other PCs on the Internet.
Function SV-205870r569188_rule {
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\" "DODownloadMode"
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205871
#Windows Server 2019 Turning off File Explorer heap termination on corruption must be disabled.
Function SV-205871r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off heap termination on corruption" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Explorer\" "NoHeapTerminationOnCorruption"
    if ($Value -eq "0" -or $Value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205872
#Windows Server 2019 File Explorer shell protocol must run in protected mode.
Function SV-205872r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer
    #"Turn off shell protocol protected mode" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" "PreXPSP2ShellProtocolBehavior"
    if ($Value -eq "0" -or $Value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205873
#Windows Server 2019 must prevent attachments from being downloaded from RSS feeds.
Function SV-205873r569188_rule {
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

#V-205874
#Windows Server 2019 users must be notified if a web-based program attempts to install software.
Function SV-205874r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer
    #"Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled". 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\Installer\" "SafeForScripting"
    if ($Value -eq "0" -or $Value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205876
#Windows Server 2019 domain controllers must be configured to allow reset of machine account passwords.
Function SV-205876r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Domain controller: Refuse machine account password changes" to "Disabled". 
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" "RefusePasswordChange"
        if ($Value -eq "0") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205877
#The password for the krbtgt account on a domain must be reset at least every 180 days.
Function SV-205877r569188_rule {
    if($Global:ServerRole -eq 3){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $OldDate = (Get-Date).AddDays(-180)
        $krbtgtSet = Get-ADUser krbtgt -Property PasswordLastSet | select -ExpandProperty PasswordLastSet
        if ($krbtgtSet -gt $OldDate) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The password was last set $krbtgtSet"}
            }
        }
    }

#V-205878
#Windows Server 2019 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on.
Function SV-205878r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:SysProcessMitigation.Dep.Enable -eq "OFF"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205879
#Windows Server 2019 Exploit Protection system-level mitigation, Control flow guard (CFG), must be on.
Function SV-205879r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:SysProcessMitigation.Cfg.Enable -eq "OFF"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205880
#Windows Server 2019 Exploit Protection system-level mitigation, Validate exception chains (SEHOP), must be on.
Function SV-205880r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:SysProcessMitigation.SEHOP.Enable -eq "OFF"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205881
#Windows Server 2019 Exploit Protection system-level mitigation, Validate heap integrity, must be on.
Function SV-205881r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        if($Global:SysProcessMitigation.Heap.TerminateOnError -eq "OFF"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205882
#Windows Server 2019 Exploit Protection mitigations must be configured for Acrobat.exe.
Function SV-205882r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "Acrobat.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205883
#Windows Server 2019 Exploit Protection mitigations must be configured for AcroRd32.exe.
Function SV-205883r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "AcroRd32.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205884
#Windows Server 2019 Exploit Protection mitigations must be configured for chrome.exe.
Function SV-205884r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "chrome.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205885
#Windows Server 2019 Exploit Protection mitigations must be configured for EXCEL.EXE.
Function SV-205885r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "EXCEL.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205886
#Windows Server 2019 Exploit Protection mitigations must be configured for firefox.exe.
Function SV-205886r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "firefox.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205887
#Windows Server 2019 Exploit Protection mitigations must be configured for FLTLDR.EXE.
Function SV-205887r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "FLTLDR.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205888
#Windows Server 2019 Exploit Protection mitigations must be configured for GROOVE.EXE.
Function SV-205888r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "GROOVE.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205889
#Windows Server 2019 Exploit Protection mitigations must be configured for iexplore.exe.
Function SV-205889r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "iexplore.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205890
#Windows Server 2019 Exploit Protection mitigations must be configured for INFOPATH.EXE.
Function SV-205890r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "INFOPATH.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205891
#Windows Server 2019 Exploit Protection mitigations must be configured for java.exe, javaw.exe, and javaws.exe.
Function SV-205891r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif($Global:ProcessMitigationList -notcontains "java.exe" -and "javaw.exe" -and "javaws.exe"){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $status="NotAFinding"

        $ProcessName = "java.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }
            }

        $ProcessName = "javaw.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }
            }

        $ProcessName = "javaws.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }
            }

        if ($status -eq "Open") {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205892
#Windows Server 2019 Exploit Protection mitigations must be configured for lync.exe.
Function SV-205892r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "lync.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205893
#Windows Server 2019 Exploit Protection mitigations must be configured for MSACCESS.EXE.
Function SV-205893r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "MSACCESS.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205894
#Windows Server 2019 Exploit Protection mitigations must be configured for MSPUB.EXE.
Function SV-205894r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "MSPUB.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205895
#Windows Server 2019 Exploit Protection mitigations must be configured for OIS.EXE.
Function SV-205895r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "OIS.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205896
#Windows Server 2019 Exploit Protection mitigations must be configured for OneDrive.exe.
Function SV-205896r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "OneDrive.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205897
#Windows Server 2019 Exploit Protection mitigations must be configured for OUTLOOK.EXE.
Function SV-205897r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "OUTLOOK.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205898
#Windows Server 2019 Exploit Protection mitigations must be configured for plugin-container.exe.
Function SV-205898r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "plugin-container.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205899
#Windows Server 2019 Exploit Protection mitigations must be configured for POWERPNT.EXE.
Function SV-205899r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "POWERPNT.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205900
#Windows Server 2019 Exploit Protection mitigations must be configured for PPTVIEW.EXE.
Function SV-205900r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "PPTVIEW.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205901
#Windows Server 2019 Exploit Protection mitigations must be configured for VISIO.EXE.
Function SV-205901r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "VISIO.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205902
#Windows Server 2019 Exploit Protection mitigations must be configured for VPREVIEW.EXE.
Function SV-205902r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "VPREVIEW.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205903
#Windows Server 2019 Exploit Protection mitigations must be configured for WINWORD.EXE.
Function SV-205903r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "WINWORD.EXE"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205904
#Windows Server 2019 Exploit Protection mitigations must be configured for wmplayer.exe.
Function SV-205904r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "wmplayer.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205905
#Windows Server 2019 Exploit Protection mitigations must be configured for wordpad.exe.
Function SV-205905r569188_rule {
    if(!($Global:IsNIPR)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $ProcessName = "wordpad.exe"
        if($Global:ProcessMitigationList -match $ProcessName){
            $status="NotAFinding"
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Dep.Enable -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.BottomUp -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).ASLR.ForceRelocateImages -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableExportAddressFilterPlus -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableImportAddressFilter -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopStackPivot -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopCallerCheck -NE "ON" ) { $status="Open" }
            if ( ($Global:ProcessMitigation | where ProcessName -EQ $processName).Payload.EnableRopSimExec -NE "ON" ) { $status="Open" }

            if ($status -eq "Open") {
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            else {
                return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
                }
            }
        else{
            return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
            }
        }
    }

#V-205906
#Windows Server 2019 must limit the caching of logon credentials to four or less on domain-joined member servers.
Function SV-205906r569188_rule {
    #Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options
    #"Interactive Logon: Number of previous logons to cache (in case Domain Controller is not available)" to "4" logons or less. 
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "CachedLogonsCount"
        if ($Value -le 4) {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-205907
#Windows Server 2019 must be running Credential Guard on domain-joined member servers.
Function SV-205907r569188_rule {
    if($Global:ServerRole -eq 2){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        $deviceguard=gwmi -Class win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        if($deviceguard.SecurityServicesRunning -notcontains 1){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else{
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-205908
#Windows Server 2019 must prevent local accounts with blank passwords from being used from the network.
Function SV-205908r569188_rule {
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

#V-205909
#Windows Server 2019 built-in administrator account must be renamed.
Function SV-205909r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Rename administrator account" to a name other than "Administrator". 
    if(($Global:Admin).Name -eq "Administrator"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205910
#Windows Server 2019 built-in guest account must be renamed.
Function SV-205910r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Accounts: Rename guest account" to a name other than "Guest".
    if(($Global:Guest).Name -eq "Guest"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-205911
#Windows Server 2019 maximum age for machine account passwords must be configured to 30 days or less.
Function SV-205911r569188_rule {
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

#V-205912
#Windows Server 2019 Smart Card removal option must be configured to Force Logoff or Lock Workstation.
Function SV-205912r569188_rule {
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

#V-205913
#Windows Server 2019 must not allow anonymous SID/Name translation.
Function SV-205913r569188_rule {
    #Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
    #"Network access: Allow anonymous SID/Name translation" to "Disabled".
    $value = $secsettings | Where-Object {$_.KeyName -eq "LSAAnonymousNameLookup"} | select -ExpandProperty Setting
    if ($Value -eq $false) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205914
#Windows Server 2019 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.
Function SV-205914r569188_rule {
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

#V-205915
#Windows Server 2019 must be configured to prevent anonymous users from having the same permissions as the Everyone group.
Function SV-205915r569188_rule {
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

#V-205916
#Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.
Function SV-205916r569188_rule {
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
            
#V-205917
#Windows Server 2019 must prevent NTLM from falling back to a Null session.
Function SV-205917r569188_rule {
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

#V-205918

#Windows Server 2019 must prevent PKU2U authentication using online identities.
Function SV-205918r569188_rule {
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

#V-205919
#Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.
Function SV-205919r569188_rule {
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

#V-205920
#Windows Server 2019 must be configured to at least negotiate signing for LDAP client signing.
Function SV-205920r569188_rule {
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

#V-205921
#Windows Server 2019 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.
Function SV-205921r569188_rule {
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

#V-205922
#Windows Server 2019 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.
Function SV-205922r569188_rule {
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

#V-205923
#Windows Server 2019 default permissions of global system objects must be strengthened.
Function SV-205923r569188_rule {
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

#V-205924
#Windows Server 2019 must preserve zone information when saving attachments.
Function SV-205924r569188_rule {
    $Value = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" "SaveZoneInformation"
    if ($Value -eq "2" -or $Value -eq $null) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-205925
#Windows Server 2019 must disable automatically signing in the last interactive user after a system-initiated restart.
Function SV-205925r569188_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options
    #"Sign-in last interactive user automatically after a system-initiated restart" to "Disabled". 
        $Value = Check-RegKeyValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" "DisableAutomaticRestartSignOn"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }

#V-214936
#Windows Server 2019 must have a host-based firewall installed and enabled.
Function SV-214936r569188_rule {
    if ($Global:installedprograms.displayname -contains "McAfee Endpoint Security Firewall") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-221930
#The Windows Explorer Preview pane must be disabled for Windows Server 2019.
Function SV-221930r569188_rule {
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

#V-236001
#The Windows Explorer Preview pane must be disabled for Windows Server 2019.
Function SV-236001r641821_rule {
    $Value1 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" NoPreviewPane
    $Value2 = Check-RegKeyValue "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" NoReadingPane
    if ($Value1 -eq 1 -and $value2 -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }