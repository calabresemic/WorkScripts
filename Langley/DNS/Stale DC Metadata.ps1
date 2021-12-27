#This script will find all the metadata for domain controllers that do not match the DC OU or the Staging OU
#Created by SSgt Calabrese (1468714589)

#Collect DCs in AREA52 and AFNOAPPS
$DCs=@()
$DCs += (Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL").Name
$DCs += (Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers,DC=AFNOAPPS,DC=USAF,DC=MIL" -Server AMUHJ-DC-001v).Name

#Collect DCs in Staging
$Staged = (Get-ADComputer -Filter 'Name -like "*-dc-*"' -SearchBase "OU=Staging,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL").Name

#Sets variables
$afnoDomain = Get-DnsServerZone -Name "afnoapps.usaf.mil"
$52Domain = Get-DnsServerZone -Name "area52.afnoapps.usaf.mil"
$usafdomain = Get-DnsServerZone -Name "usaf.mil"
$Badafnorecords=@()
$Bad52records=@()
$Badusafrecords=@()
$report=@()

#Collects records from the various zones
#The filter at the end will select 52XXX-DC- and XXXX-DC- that way we don't have any false records with printers having the DC name in the host name...
$AfnoSrv=$afnoDomain | Get-DnsServerResourceRecord -RRType SRV | Where {$_.RecordData.DomainName -like "????-DC-*" -or $_.RecordData.DomainName -like "52????-DC-*"}
$AfnoNS=$afnoDomain | Get-DnsServerResourceRecord -RRType NS | Where {$_.RecordData.NameServer -like "????-DC-*" -or $_.RecordData.NameServer -like "52????-DC-*"}
$AfnoCNAME=$afnoDomain | Get-DnsServerResourceRecord -RRType CNAME | Where {$_.RecordData.HostNameAlias -like "????-DC-*" -or $_.RecordData.HostNameAlias -like "52????-DC-*"}
$AfnoA=$afnoDomain | Get-DnsServerResourceRecord -RRType A | Where {$_.HostName -like "????-DC-*" -or $_.HostName -like "52????-DC-*" -and $_.timestamp -eq $null}

$52Srv=$52Domain | Get-DnsServerResourceRecord -RRType SRV | Where {$_.RecordData.DomainName -like "????-DC-*" -or $_.RecordData.DomainName -like "52????-DC-*"}
$52NS=$52Domain | Get-DnsServerResourceRecord -RRType NS | Where {$_.RecordData.NameServer -like "????-DC-*" -or $_.RecordData.NameServer -like "52????-DC-*"}
$52A=$52Domain | Get-DnsServerResourceRecord -RRType A | Where {$_.HostName -like "????-DC-*" -or $_.HostName -like "52????-DC-*" -and $_.timestamp -eq $null}

$usafSrv=$usafDomain | Get-DnsServerResourceRecord -RRType SRV | Where {$_.RecordData.DomainName -like "????-DC-*" -or $_.RecordData.DomainName -like "52????-DC-*"}
$usafNS=$usafDomain | Get-DnsServerResourceRecord -RRType NS | Where {$_.RecordData.NameServer -like "????-DC-*" -or $_.RecordData.NameServer -like "52????-DC-*"}
$usafA=$usafDomain | Get-DnsServerResourceRecord -RRType A | Where {$_.HostName -like "????-DC-*" -or $_.HostName -like "52????-DC-*" -and $_.timestamp -eq $null}

#Compare the records to the DC lists
foreach($record in $AfnoSrv){if($record.RecordData.DomainName.split(".")[0] -notin $DCs -and $record.RecordData.DomainName.split(".")[0] -notin $Staged){$Badafnorecords+=$record}}
foreach($record in $AfnoNS){if($record.RecordData.NameServer.split(".")[0] -notin $DCs -and $record.RecordData.NameServer.split(".")[0] -notin $Staged){$Badafnorecords+=$record}}
foreach($record in $AfnoCNAME){if($record.RecordData.HostNameAlias.split(".")[0] -notin $DCs -and $record.RecordData.HostNameAlias.split(".")[0] -notin $Staged){$Badafnorecords+=$record}}
foreach($record in $AfnoA){if($record.HostName.trimend(".area52") -notin $DCs -and $record.HostName.trimend(".area52") -notin $Staged){$Badafnorecords+=$record}}

foreach($record in $52Srv){if($record.RecordData.DomainName.split(".")[0] -notin $DCs -and $record.RecordData.DomainName.split(".")[0] -notin $Staged){$Bad52records+=$record}}
foreach($record in $52NS){if($record.RecordData.NameServer.split(".")[0] -notin $DCs -and $record.RecordData.NameServer.split(".")[0] -notin $Staged){$Bad52records+=$record}}
foreach($record in $52A){if($record.HostName -notin $DCs -and $record.HostName -notin $Staged){$Bad52records+=$record}}

foreach($record in $usafSrv){if($record.RecordData.DomainName.split(".")[0] -notin $DCs -and $record.RecordData.DomainName.split(".")[0] -notin $Staged){$Badusafrecords+=$record}}
foreach($record in $usafNS){if($record.RecordData.NameServer.split(".")[0] -notin $DCs -and $record.RecordData.NameServer.split(".")[0] -notin $Staged){$Badusafrecords+=$record}}
foreach($record in $usafA){if($record.HostName.split(".")[0] -notin $DCs -and $record.HostName.split(".")[0] -notin $Staged){$Badusafrecords+=$record}}

#Generate the report
foreach($entry in $Badafnorecords){
    if($entry.RecordType -eq 'SRV'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.DomainName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AFNOAPPS.USAF.MIL'}}
    if($entry.RecordType -eq 'NS'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.NameServer;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AFNOAPPS.USAF.MIL'}}
    if($entry.RecordType -eq 'CNAME'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.HostNameAlias;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AFNOAPPS.USAF.MIL'}}
    if($entry.RecordType -eq 'A'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.HostName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AFNOAPPS.USAF.MIL'}}
}
foreach($entry in $Bad52records){
    if($entry.RecordType -eq 'SRV'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.DomainName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AREA52.AFNOAPPS.USAF.MIL'}}
    if($entry.RecordType -eq 'NS'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.NameServer;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AREA52.AFNOAPPS.USAF.MIL'}}
    if($entry.RecordType -eq 'A'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.HostName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'AREA52.AFNOAPPS.USAF.MIL'}}
}
foreach($entry in $Badusafrecords){
    if($entry.RecordType -eq 'SRV'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.DomainName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'USAF.MIL'}}
    if($entry.RecordType -eq 'NS'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.RecordData.NameServer;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'USAF.MIL'}}
    if($entry.RecordType -eq 'A'){$report+=[pscustomobject]@{"DistinguishedName" = $entry.DistinguishedName;HostName = $entry.HostName;RecordData = $entry.HostName;RecordType = $entry.RecordType;TimeStamp = $entry.Timestamp;TimeToLive = $entry.TimeToLive;Zone = 'USAF.MIL'}}
}

#Export report
$report | Export-Csv $env:USERPROFILE\Desktop\StaleDCMetadata.csv -NoTypeInformation