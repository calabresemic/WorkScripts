Remove-Item C:\Working\PatcherNew\Results\StaleComps.csv -ErrorAction SilentlyContinue
$ou = "OU=Misawa AFB Computers,OU=Misawa AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
#standard 60 day filter. Change if you want but A3/6 uses this range.
$DaysInactive = "60"
$time = (Get-Date).Adddays(-($DaysInactive))
Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -SearchBase $ou -ResultPageSize 5000 -resultSetSize $null -Properties * | Select-Object Name,OperatingSystem,lastlogondate | Export-CSV C:\Working\PatcherNew\Results\StaleComps.csv –NoTypeInformation