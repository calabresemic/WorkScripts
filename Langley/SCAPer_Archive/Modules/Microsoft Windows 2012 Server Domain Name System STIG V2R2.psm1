<#
Module Created by Michael Calabrese (1468714589)
Designed to be used with SCAPer script v5+

Microsoft Windows 2012 Server Domain Name System Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 23 Apr 2021
#>

#V-215573
#The Windows 2012 DNS Server must prohibit recursion on authoritative name servers for which forwarders have not been configured for external queries.
Function SV-215573r561297_rule { 
    #Not Applicable on SIPR
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    #if forwarders are used, recursion must be enabled, root hints must be disabled
    elseif ( ((Get-DnsServerForwarder).IPAddress).Count -gt 0 ){
        if ( (Get-DnsServerRecursion).enable -and (!(Get-DnsServerForwarder).UseRootHint) ){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    #if forwarders are not used, recursion must be disabled, root hints must be disabled
    elseif ( ((Get-DnsServerForwarder).IPAddress).Count -eq 0 ){
        if ( (!(Get-DnsServerRecursion).enable) -and (!(Get-DnsServerForwarder).UseRootHint) ){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215574
#Forwarders on an authoritative Windows 2012 DNS Server, if enabled for external resolution, must only forward to either an internal, non-AD-integrated DNS server or to the DoD Enterprise Recursive Services (ERS).
Function SV-215574r561297_rule { 
    #Not Applicable on SIPR
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        $forwarders=((Get-DnsServerForwarder).IPAddress).IPAddressToString
        foreach($forwarder in $forwarders){
            try{
                Resolve-DnsName $forwarder -ErrorAction Stop | Out-Null
                }
            catch{
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        }
    }

#V-215575
#The Windows 2012 DNS Server with a caching name server role must restrict recursive query responses to only the IP addresses and IP address ranges of known supported clients.
Function SV-215575r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif (!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215576
#The Windows 2012 DNS Server with a caching name server role must be secured against pollution by ensuring the authenticity and integrity of queried records.
Function SV-215576r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215577
#The Windows 2012 DNS Server must implement cryptographic mechanisms to detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).
Function SV-215577r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215578
#The validity period for the RRSIGs covering a zones DNSKEY RRSet must be no less than two days and no more than one week.
Function SV-215578r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215579
#NSEC3 must be used for all internal DNS zones.
Function SV-215579r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215581
#All authoritative name servers for a zone must be located on different network segments.
Function SV-215581r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215582
#All authoritative name servers for a zone must have the same version of zone information.
Function SV-215582r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215583
#The Windows 2012 DNS Server must be configured to enable DNSSEC Resource Records.
Function SV-215583r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215584
#Digital signature algorithm used for DNSSEC-enabled zones must be FIPS-compatible.
Function SV-215584r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215588
#Primary authoritative name servers must be configured to only receive zone transfer requests from specified secondary name servers.
Function SV-215588r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215589
#The Windows 2012 DNS Servers zone database files must not be accessible for edit/write by users and/or processes other than the Windows 2012 DNS Server service account and/or the DNS database administrator.
Function SV-215589r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215591
#The Windows 2012 DNS Server authoritative for local zones must only point root hints to the DNS servers that host the internal root domain.
Function SV-215591r561297_rule { 
    if(!$Global:IsNIPR){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    #Checks root hints
    elseif ( (Get-DnsServerRootHint -ErrorAction SilentlyContinue).count -ne 0 ){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215592
#The DNS name server software must be at the latest version.
Function SV-215592r561297_rule { 
    #Checks for patches installed within the last month
    #Technically IAVMs don't exist but I believe in the concept of this check
    $hotfix=Get-HotFix
    if((($hotfix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)}).HotFixID).count -gt 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        $hotfixdate=($hotfix | sort installedon).installedon | select -last 1
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The last update was installed: $hotfixdate"}
        }
    }

#V-215594
#The Windows 2012 DNS Servers zone files must not include CNAME records pointing to a zone with lesser security for more than six months.
Function SV-215594r561297_rule { 
    #Checks every zone for CNames
    $oldrecords=@()
    $dnszones=($Global:ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false}).ZoneName
    foreach($dnszone in $dnszones){
    $CNames=@()
    $CNames=Get-DnsServerResourceRecord -RRType CName -ZoneName $dnszone
    $oldrecords+=$CNames | Where-Object {$_.Timestamp -lt ((Get-Date).AddMonths(-6)) -and $_.TimeToLive -gt "180:00:00"}
    }
    if($oldrecords.Count -gt 0){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=$oldrecords}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215595
#Non-routable IPv6 link-local scope addresses must not be configured in any zone.
Function SV-215595r561297_rule { 
    return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
    $dnszones=($Global:ALLDNSZones | where {$_.IsReverseLookupZone -eq $false }).ZoneName
    $AAAA=@()
    foreach($dnszone in $dnszones){
        $AAAA+=Get-DnsServerResourceRecord -RRType AAAA -ZoneName $dnszone
        }
    if ( ($AAAA.RecordData.IPv6Address.IPAddressToString | where {$_ -like "fe8*" -or $_ -like "fe9*" -or $_ -like "fea*" -or $_ -like "feb*"} ).count -gt 0){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215597
#IPv6 protocol must be disabled unless the Windows 2012 DNS server is configured to answer for and hosting IPv6 AAAA records.
Function SV-215597r561297_rule { 
    #Checks for IPV6 records then reg key
    $dnszones=($Global:ALLDNSZones | Where-Object {$_.IsDsIntegrated -eq $true}).ZoneName
    $AAAA=@()
    foreach($dnszone in $dnszones){
        $AAAA+=Get-DnsServerResourceRecord -RRType AAAA -ZoneName $dnszone
        }
    if($AAAA.Count -gt 0){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif((Check-RegKeyValue "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters\" "DisabledComponents" "SilentlyContinue") -eq 255){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215598
#The Windows 2012 DNS Server must be configured to prohibit or restrict unapproved ports and protocols.
Function SV-215598r561297_rule { 
    #Check TCP connections for 53
    if(Get-NetTCPConnection -LocalPort 53){
        #Checks UDP connections for 53
        if(Get-NetUDPEndpoint -LocalPort 53){
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215599
#The Windows 2012 DNS Server must require devices to re-authenticate for each dynamic update request connection attempt.
Function SV-215599r561297_rule { 
    return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
    $dnszones=($Global:ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).ZoneName
    foreach($dnszone in $dnszones){
        if(($Global:ALLDNSZones | where ZONENAME -eq $dnszone).DynamicUpdate -notmatch "Secure"){
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-215600
#The Windows 2012 DNS Server must uniquely identify the other DNS server before responding to a server-to-server transaction.
Function SV-215600r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215601
#The secondary Windows DNS name servers must cryptographically authenticate zone transfers from primary name servers.
Function SV-215601r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215602
#The Windows DNS primary server must only send zone transfers to a specific list of secondary name servers.
Function SV-215602r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215603
#The Windows 2012 DNS Server must provide its identity with returned DNS information by enabling DNSSEC and TSIG/SIG(0).
Function SV-215603r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215604
#The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.
Function SV-215604r561297_rule { 
    $cryptoACL=(Get-ChildItem C:\ProgramData\Microsoft\Crypto | Get-Acl).Access
    if((Test-Path C:\ProgramData\Microsoft\Crypto) -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif($cryptoACL | Where-Object {($_.filesystemrights -eq "FullControl") -and ($_.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM" -and $_.IdentityReference -notmatch "BUILTIN\\Administrators")}){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    elseif($cryptoACL.FileSystemRights -match "Modify"){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215605
#The Windows 2012 DNS Server key file must be owned by the account under which the Windows 2012 DNS Server service is run.
Function SV-215605r561297_rule { 
    #Checks if C:\ProgramData\Microsoft\Crypto exists
    if (!(Test-Path C:\ProgramData\Microsoft\Crypto)) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        $BadFile=@()
        #Checks the account running DNS
        $logonas=(Get-WmiObject Win32_Service -Filter "Name='dns'").StartName
        Switch($logonas){
            "LocalSystem" {$DNSowner="NT AUTHORITY\SYSTEM"}
            default {$DNSowner=$logonas}
            }
        #Check the owner on sub files and folders
        $subfiles=(Get-ChildItem C:\ProgramData\Microsoft\Crypto).FullName
        $subfiles+="C:\ProgramData\Microsoft\Crypto"
        foreach($file in $subfiles){
            if((Get-Acl $file).owner -ne $dnsowner){
                return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following file(s) have the wrong owner: $BadFile"}
                $BadFile+=$file
                }
            }
        }
    }

#V-215606
#The Windows 2012 DNS Server permissions must be set so that the key file can only be read or modified by the account that runs the name server software.
Function SV-215606r561297_rule { 
    #Checks if C:\ProgramData\Microsoft\Crypto exists
    if (!(Test-Path C:\ProgramData\Microsoft\Crypto)) {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        #Check the FullControl on sub files and folders
        $subfiles=(Get-ChildItem C:\ProgramData\Microsoft\Crypto).FullName
        $subfiles+="C:\ProgramData\Microsoft\Crypto"
            foreach($file in $subfiles){
                if((Get-Acl $file).Access | Where-Object {$_.FileSystemRights -eq "FullControl" -and $_.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and $_.IdentityReference -ne "BUILTIN\Administrators"}){
                    return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
                }
            }
        }
    }

#V-215607
#The private key corresponding to the ZSK must only be stored on the name server that does support dynamic updates.
Function SV-215607r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215609
#The salt value for zones signed using NSEC3 RRs must be changed every time the zone is completely re-signed.
Function SV-215609r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215610
#The Windows 2012 DNS Server must include data origin with authoritative data the system returns in response to external name/address resolution queries.
Function SV-215610r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215611
#The Windows 2012 DNS Servers IP address must be statically defined and configured locally on the server.
Function SV-215611r561297_rule { 
    if($Global:NetAdapter.dhcpenabled -eq $false -and $Global:NetAdapter.IPAddress -ne $null -and $Global:NetAdapter.IPSubnet -ne $null -and $Global:NetAdapter.DefaultIPGateway -ne $null){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215612
#The Windows 2012 DNS Server must return data information in responses to internal name/address resolution queries.
Function SV-215612r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215613
#The Windows 2012 DNS Server must use DNSSEC data within queries to confirm data origin to DNS resolvers.
Function SV-215613r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215614
#WINS lookups must be disabled on the Windows 2012 DNS Server.
Function SV-215614r561297_rule { 
    if(($Global:ALLDNSZones).IsWinsEnabled -contains $true){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215615
#The Windows 2012 DNS Server must use DNSSEC data within queries to confirm data integrity to DNS resolvers.
Function SV-215615r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215616
#The Windows 2012 DNS Server must be configured with the DS RR carrying the signature for the RR that contains the public key of the child zone.
Function SV-215616r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215617
#The Windows 2012 DNS Server must enforce approved authorizations between DNS servers through the use of digital signatures in the RRSet.
Function SV-215617r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215618
#The Name Resolution Policy Table (NRPT) must be configured in Group Policy to enforce clients to request DNSSEC validation for a domain.
Function SV-215618r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215619
#The Windows 2012 DNS Server must be configured to validate an authentication chain of parent and child domains via response data.
Function SV-215619r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215620
#Trust anchors must be exported from authoritative Windows 2012 DNS Servers and distributed to validating Windows 2012 DNS Servers.
Function SV-215620r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215621
#Automatic Update of Trust Anchors must be enabled on key rollover.
Function SV-215621r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215622
#The Windows DNS secondary servers must request data origin authentication verification from the primary server when requesting name/address resolution.
Function SV-215622r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215623
#The Windows DNS secondary server must request data integrity verification from the primary server when requesting name/address resolution.
Function SV-215623r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215624
#The Windows DNS secondary server must validate data integrity verification on the name/address resolution responses received from primary name servers.
Function SV-215624r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215625
#The Windows DNS secondary server must validate data origin verification authentication on the name/address resolution responses received from primary name servers.
Function SV-215625r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215626
#The Windows 2012 DNS Server must protect the authenticity of zone transfers via transaction signing.
Function SV-215626r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215627
#The Windows 2012 DNS Server must protect the authenticity of dynamic updates via transaction signing.
Function SV-215627r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215628
#The Windows 2012 DNS Server must protect the authenticity of query responses via DNSSEC.
Function SV-215628r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215629
#The Windows 2012 DNS Server must only allow the use of an approved DoD PKI-established certificate authorities for verification of the establishment of protected transactions.
Function SV-215629r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215631
#The Windows 2012 DNS Server must not contain zone records that have not been validated in over a year.
Function SV-215631r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215632
#The Windows 2012 DNS Server must restrict individuals from using it for launching Denial of Service (DoS) attacks against other information systems.
Function SV-215632r561297_rule { 
    $checks=@()
    if(($Global:UserRights | Where-Object {$_.UserRight -eq "SeRemoteInteractiveLogonRight"} | select -ExpandProperty AccountList) -notmatch "Administrators"){$checks+="Allow log on through Remote Desktop Services"}
    if(($Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyNetworkLogonRight"} | select -ExpandProperty AccountList) -notmatch "Guests"){$checks+="Deny access to this computer from the network"}
    if(($Global:UserRights | Where-Object {$_.UserRight -eq "SeDenyInteractiveLogonRight"} | select -ExpandProperty AccountList) -notmatch "Guests"){$checks+="Deny log on locally"}
    if($checks.Count -eq 0){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details="The following User Rights Assignment is incorrectly configured: `n$checks"}
        }
    }

#V-215633
#The Windows 2012 DNS Server must use DNS Notify to prevent denial of service through increase in workload.
Function SV-215633r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215634
#The Windows 2012 DNS Server must protect the integrity of transmitted information.
Function SV-215634r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215635
#The Windows 2012 DNS Server must maintain the integrity of information during preparation for transmission.
Function SV-215635r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215636
#The Windows 2012 DNS Server must maintain the integrity of information during reception.
Function SV-215636r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215637
#The Windows 2012 DNS Server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.
Function SV-215637r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215639
#The Windows 2012 DNS Server must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.
Function SV-215639r561297_rule { 
    #Not A Finding
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215640
#The DNS Name Server software must be configured to refuse queries for its version information.
Function SV-215640r561297_rule { 
    if ((Get-DnsServerSetting -All -WarningAction SilentlyContinue).EnableVersionQuery -eq 0) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215641
#The HINFO, RP, TXT and LOC RR types must not be used in the zone SOA.
Function SV-215641r561297_rule { 
    $dnszones=($Global:ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false}).ZoneName
    $badRRs=@()
    foreach($dnszone in $dnszones){
    $badRRs+=Get-DnsServerResourceRecord -RRType HInfo -ZoneName $dnszone
    $badRRs+=Get-DnsServerResourceRecord -RRType Rp -ZoneName $dnszone
    $badRRs+=Get-DnsServerResourceRecord -RRType Loc -ZoneName $dnszone
    $badRRs+=Get-DnsServerResourceRecord -RRType Txt -ZoneName $dnszone
    }
    if($badRRs.count -gt 0){
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215643
#The Windows 2012 DNS Server must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.
Function SV-215643r561297_rule { 
    #This really assumes that the agent is installed and therefore the rest of the McAfee suite is also installed.
    if($Global:installedprograms.displayname -contains "McAfee Agent"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215644
#The Windows 2012 DNS Server must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.
Function SV-215644r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215645
#The Windows 2012 DNS Server must be configured to notify the ISSO/ISSM/DNS administrator when functionality of DNSSEC/TSIG has been removed or broken.
Function SV-215645r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215647
#The Windows 2012 DNS Server must restrict incoming dynamic update requests to known clients.
Function SV-215647r561297_rule { 
    return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
    $badzones=@()
    $dnszones=($Global:ALLDNSZones | Where-Object {$_.IsReverseLookupZone -eq $false -and $_.ZoneType -match "Primary"}).ZoneName
    foreach($dnszone in $dnszones){
        if(($Global:ALLDNSZones | Where ZoneName -eq $dnszone).DynamicUpdate -notmatch "Secure"){
            $badzones+=$dnszone
            }
        }
    if ($badzones.count -gt 0) {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215648
#The Windows 2012 DNS Server must be configured to record, and make available to authorized personnel, who added/modified/deleted DNS zone information.
Function SV-215648r561297_rule { 
    if($Global:dnsdiag.EventLogLevel -ge 2){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215649
#The Windows 2012 DNS Server must, in the event of an error validating another DNS servers identity, send notification to the DNS administrator.
Function SV-215649r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215650
#The Windows 2012 DNS Server log must be enabled.
Function SV-215650r561297_rule { 
    if($Global:dnsdiag.EventLogLevel -ge 2){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-215651
#The Windows 2012 DNS Server logging must be enabled to record events from all DNS server functions.
Function SV-215651r684253_rule { 
    $diagnostics= @()
    $diagnostics+=$Global:dnsdiag.Queries
    $diagnostics+=$Global:dnsdiag.Answers
    $diagnostics+=$Global:dnsdiag.Notifications
    $diagnostics+=$Global:dnsdiag.Update
    $diagnostics+=$Global:dnsdiag.QuestionTransactions
    $diagnostics+=$Global:dnsdiag.UnmatchedResponse
    $diagnostics+=$Global:dnsdiag.EnableLoggingForLocalLookupEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForPluginDllEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForRecursiveLookupEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForRemoteServerEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForServerStartStopEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForTombstoneEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForZoneDataWriteEvent
    $diagnostics+=$Global:dnsdiag.EnableLoggingForZoneLoadingEvent

    if( ($diagnostics -notcontains $false) -and ($Global:dnsdiag.UseSystemEventLog -or $Global:dnsdiag.EnableLoggingToFile) ){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    }

#V-215652
#The Windows 2012 DNS Server logging criteria must only be configured by the ISSM or individuals appointed by the ISSM.
Function SV-215652r561297_rule { 
    $badacl=@()
    Switch($Global:DomainName) {
        AREA52        {$auditors="Administrators,AFNOAPPS\\Exchange Servers,AREA52\\Exchange Enterprise Servers,LOCAL SERVICE"}
        AFNOAPPS      {$auditors="Administrators,AFNOAPPS\\Exchange Servers"}
        Default       {$auditors="Administrators"}
        }

    $value=($Global:UserRights | Where-Object {$_.UserRight -eq "SeSecurityPrivilege"} | select -ExpandProperty AccountList) -join ","
    if ($Value -notmatch $auditors) {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    else{
        $DNSACL=(Get-Acl 'C:\Windows\System32\winevt\Logs\DNS Server.evtx').Access
        foreach($acl in $DNSACL){
            if($acl.FileSystemRights -match "FullControl" -and $acl.IdentityReference -notmatch "NT SERVICE\\EventLog" -and $acl.IdentityReference -notmatch "NT AUTHORITY\\SYSTEM" -and $acl.IdentityReference -notmatch "BUILTIN\\Administrators"){
                $badacl+=$acl
                }
            }
        if ($badacl.count -gt 0) {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        }
    }

#V-215661
#The validity period for the RRSIGs covering the DS RR for a zones delegated children must be no less than two days and no more than one week.
Function SV-215661r561297_rule { 
    #Not Applicable
    if($Global:IsNIPR -eq $false){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    elseif(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-228571
#The Windows DNS name servers for a zone must be geographically dispersed.
Function SV-228571r561297_rule { 
    #Not Applicable
    if(!($Global:NonDSZones)){
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    else{
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }