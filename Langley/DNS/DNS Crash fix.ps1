$DCs = @"
zhtx-dc-007v
znre-dc-002v
"@.split("`n") | foreach {$_.trim()}

foreach ($serv in $DCs) {
#$serv = $env:COMPUTERNAME #For testing
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $serv)
    $regKeyServ = $reg.OpenSubKey("SYSTEM\CurrentControlSet\Services\DNS\Parameters".replace("\","\\"),$true)
    $regKeyServ.SetValue("OperationsLogLevel",$regKeyServ.GetValue("OperationsLogLevel") -band -bnot(0x00004000))
    $regKeyServ.SetValue("OperationsLogLevel2",$regKeyServ.GetValue("OperationsLogLevel2") -band -bnot(0x00004000))

    Get-Service -Name dns -ComputerName $serv | Restart-Service
    } 