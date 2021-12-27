Get-DHCPServerV4Scope -ComputerName 52qkkg-hc-002v | ForEach {

    Get-DHCPServerv4Lease -ComputerName 52qkkg-hc-002v -ScopeID $_.ScopeID | where {$_.AddressState -like '*Reservation'}

} | Select-Object ScopeId,IPAddress,HostName,ClientID,AddressState | Export-Csv C:\temp\reservations.csv