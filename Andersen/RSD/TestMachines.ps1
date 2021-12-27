Param(
    [parameter(Mandatory=$true)]
    [string[]]$ips, $range
)

$ErrorActionPreference = 'silentlycontinue'
$output = foreach($ip in $ips)
{
    $status = $null
    if(!(test-connection -computername $ip -count 1 -quiet))
    {
    "$ip`toffline"
    }
    else
    {
    
    $status = [System.Net.Dns]::GetHostbyAddress(“$ip").hostname
    if ($status -like "" -and $error[0] -like "*The Requested name is valid*")
    {
        "$ip`tvalid IP`tnot Windows OS"
    }
    else
    {
    "$ip`t$status"
    }
    }
    
}
$folder = "C:\RSD\Results_$(Get-Date -f MM_dd_yyyy)"
$output | Out-File $folder\Subnet_$range.txt