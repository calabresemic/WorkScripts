#Created by A1C Calabrese, Michael

# Creates list of stale computer objects
$ou = "OU=Misawa AFB Computers,OU=Misawa AFB,OU=AFCONUSWEST,OU=Bases,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL"
$DaysInactive = "60"
$time = (Get-Date).Adddays(-($DaysInactive))
$ComputerList = Get-ADComputer -Filter {(LastLogonTimeStamp -lt $time) -and (OperatingSystem -eq "Windows 7 Enterprise") } -SearchBase $ou -Properties * | Select-Object {$_.CN}

# Removes them from DRA
$DraServer = "misawa.dra.us.af.mil"

Foreach($ComputerName in $ComputerList)
{
Remove-DRAComputer -Domain Area52.afnoapps.usaf.mil –DRARestServer $DraServer -Identifier $ComputerName -force
Write-host "$ComputerName removed"
}