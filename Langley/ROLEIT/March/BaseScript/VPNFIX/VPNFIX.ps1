#get current directoy
$scriptpath = $MyInvocation.MyCommand.Path
$currentdir = Split-Path $scriptpath

$SettingsTest = $null

$inputloc = $currentdir + "\keyvalue.txt"

$key = "USAF AFNET VPN"
$a = get-content $inputloc

$Processor_Type = (Get-ItemProperty -path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").PROCESSOR_ARCHITECTURE
$SettingsTest = (Get-ItemProperty -path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections").$key

if($Processor_Type -eq "AMD64" -and ($SettingsTest))
{
Write-Output "Test"
set-itemproperty -path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -name $key -value $a
}



