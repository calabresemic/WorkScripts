(get-dnsserverresourcerecord -name "_ldap._tcp.ForestDnsZones" -zonename "afnoapps.usaf.mil").count

get-dnsserverresourcerecord -name "_ldap._tcp.ForestDnsZones" -zonename "afnoapps.usaf.mil" | Where-Object {$_.recorddata.domainname -cmatch "[A-Z]"} | Remove-DnsServerResourceRecord -ZoneName "area52.afnoapps.usaf.mil" -Force

restart-service dns