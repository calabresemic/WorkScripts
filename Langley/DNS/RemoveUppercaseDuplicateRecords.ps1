#This script will find the duplicate records in each zone, select the capitalized version and then delete the record.
#If the capitalized record does not have a lowercase counterpart it will not be deleted.
$eventlog=@()

$uppercaserecords=((Get-DnsServerResourceRecord -Name "_gc._tcp" -ZoneName "afnoapps.usaf.mil").RecordData.DomainName | Group-Object | where count -eq 2).Group | Where-Object {$_ -cmatch "[A-Z]"}
get-dnsserverresourcerecord -Name "_gc._tcp" -ZoneName "afnoapps.usaf.mil" | Where-Object {$_.RecordData.DomainName -cin $uppercaserecords} | Remove-DnsServerResourceRecord -ZoneName "afnoapps.usaf.mil" -Force
$eventlog+="Removed $($uppercaserecords.count) record(s) from DC=_gc._tcp,DC=AFNOAPPS.USAF.MIL,CN=MicrosoftDNS,DC=ForestDnsZones,DC=AFNOAPPS,DC=USAF,DC=MIL"

$uppercaserecords=((Get-DnsServerResourceRecord -Name "_ldap._tcp.0f81916b-b9e1-4c27-8ac0-3ce0a601e53c.domains._msdcs" -ZoneName "afnoapps.usaf.mil").RecordData.DomainName | Group-Object | where count -eq 2).Group | Where-Object {$_ -cmatch "[A-Z]"}
get-dnsserverresourcerecord -Name "_ldap._tcp.0f81916b-b9e1-4c27-8ac0-3ce0a601e53c.domains._msdcs" -ZoneName "afnoapps.usaf.mil" | Where-Object {$_.RecordData.DomainName -cin $uppercaserecords} | Remove-DnsServerResourceRecord -ZoneName "afnoapps.usaf.mil" -Force
$eventlog+="Removed $($uppercaserecords.count) record(s) from DC=_ldap._tcp.0f81916b-b9e1-4c27-8ac0-3ce0a601e53c.domains._msdcs,DC=AFNOAPPS.USAF.MIL,CN=MicrosoftDNS,DC=ForestDnsZones,DC=AFNOAPPS,DC=USAF,DC=MIL"

$uppercaserecords=((Get-DnsServerResourceRecord -Name "_ldap._tcp.ForestDnsZones" -ZoneName "afnoapps.usaf.mil").RecordData.DomainName | Group-Object | where count -eq 2).Group | Where-Object {$_ -cmatch "[A-Z]"}
get-dnsserverresourcerecord -Name "_ldap._tcp.ForestDnsZones" -ZoneName "afnoapps.usaf.mil" | Where-Object {$_.RecordData.DomainName -cin $uppercaserecords} | Remove-DnsServerResourceRecord -ZoneName "afnoapps.usaf.mil" -Force
$eventlog+="Removed $($uppercaserecords.count) record(s) from DC=_ldap._tcp.ForestDnsZones,DC=AFNOAPPS.USAF.MIL,CN=MicrosoftDNS,DC=ForestDnsZones,DC=AFNOAPPS,DC=USAF,DC=MIL"

$uppercaserecords=((Get-DnsServerResourceRecord -Name "_ldap._tcp.gc._msdcs" -ZoneName "afnoapps.usaf.mil").RecordData.DomainName | Group-Object | where count -eq 2).Group | Where-Object {$_ -cmatch "[A-Z]"}
get-dnsserverresourcerecord -Name "_ldap._tcp.gc._msdcs" -ZoneName "afnoapps.usaf.mil" | Where-Object {$_.RecordData.DomainName -cin $uppercaserecords} | Remove-DnsServerResourceRecord -ZoneName "afnoapps.usaf.mil" -Force
$eventlog+="Removed $($uppercaserecords.count) record(s) from DC=_ldap._tcp.gc._msdcs,DC=AFNOAPPS.USAF.MIL,CN=MicrosoftDNS,DC=ForestDnsZones,DC=AFNOAPPS,DC=USAF,DC=MIL"

#Needed to make the write-eventlog work
$output=($eventlog | Out-String).Trim()
Write-EventLog -LogName Application -EventId 5300 -Source "RemoveUppercaseDuplicateRecords" -EntryType Information -Message $output