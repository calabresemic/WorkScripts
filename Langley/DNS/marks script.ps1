$fdnsz = 'dc=forestdnszones,dc=afnoapps,dc=usaf,dc=mil'
$ddnsz = 'dc=domaindnszones,dc=area52,dc=afnoapps,dc=usaf,dc=mil'

$output = @()

$records = get-adobject -filter {objectclass -eq 'dnsNode'} -searchbase $fdnsz -properties dnsrecord
foreach($record in $records){
    If($record.dnsrecord.count -gt 750){$output += [pscustomobject]@{Distinguishedname = $record.DistinguishedName;recordCount = $record.dnsrecord.count}}
    }


$records = get-adobject -filter {objectclass -eq 'dnsNode'} -searchbase $ddnsz -properties dnsrecord
foreach($record in $records){
    If($record.dnsrecord.count -gt 750){$output += [pscustomobject]@{Distinguishedname = $record.DistinguishedName;recordCount = $record.dnsrecord.count}}
    }


$output | sort recordcount -Descending

$report=@()

Foreach($name in $output.Distinguishedname){
    $recordname=$name.Split(",")[0].trimstart("DC=")
    if($name -like "DC=@*" -or $name -like "DC=area52.afnoapps.usaf.mil.*"){}
    elseif($name -match "AREA52"){
        $servernames=((Get-DnsServerResourceRecord -Name $name.Split(",")[0].trimstart("DC=") -ZoneName "area52.afnoapps.usaf.mil").recorddata.domainname | Group-Object | where count -eq 2).name.TrimEnd(".")
        foreach($server in $servernames){
            $server=Get-ADComputer $server.split(".")[0] -Properties OperatingSystem
            $report+=[pscustomobject]@{"DCName(AD)" = $server.Name;OperatingSystem = $server.OperatingSystem;DNSRecord = $name}
            }
        }
    else{
        $servernames=((Get-DnsServerResourceRecord -Name $name.Split(",")[0].trimstart("DC=") -ZoneName "afnoapps.usaf.mil").recorddata.domainname | Group-Object | where count -eq 2).name.TrimEnd(".")
        foreach($server in $servernames){
            $server=Get-ADComputer $server.split(".")[0] -Properties OperatingSystem
            $report+=[pscustomobject]@{"DCName(AD)" = $server.Name;OperatingSystem = $server.OperatingSystem;DNSRecord = $name}
            }
        }
    }

$report | Export-Csv $env:USERPROFILE\desktop\DNSZoneReport.csv -NoTypeInformation