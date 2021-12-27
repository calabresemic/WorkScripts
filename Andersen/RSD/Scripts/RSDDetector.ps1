#Created by A1C Calabrese, Michael K. for Andersen AFB

#Imports script to enumerate the IPs in a given subnet with a given mask
Import-Module C:\RSD\Scripts\Get-IPrange.ps1

#Creates a folder with the current date for the results
ni C:\RSD\Results_$(Get-Date -f MM_dd_yyyy) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

#Sets variables needed later
$path = 'C:\RSD\Andersen_Subnet_Coverage.csv'
$pathtmp = "$path.tmp"

#Checks for unwanted formatting then corrects if needed
if((Get-Content $path -first 1) -eq "Number of Detected Subnets,Percentage,"){

$sr = New-Object -TypeName System.IO.StreamReader -ArgumentList $path
$sw = New-Object -TypeName System.IO.StreamWriter -ArgumentList $pathtmp

$i=0

Do{
    $line=$sr.ReadLine()
    $i++
    If(($i -gt 4)){
        $sw.WriteLine($line)
    }
}Until($sr.EndOfStream)

$sr.close()
$sw.close()

Remove-Item $path
Rename-Item $pathtmp $path
}

#Imports the csv file so that it can be made into lists
$results = Import-Csv C:\RSD\Andersen_Subnet_Coverage.csv -Header SubnetAddress, SubnetMask, Covered, ContainsRogue, SubnetName | Where-Object { $_.Covered -eq "No" }
$Address = ($results).SubnetAddress
$Mask = ($results).SubnetMask
Write-Host $results.Count "Subnets Not Covered"

#Enumerates IPs then creates background jobs for each set of subnets
for ($i=0; $i -lt $Address.Length; $i++ )
{
    $ips = @(Get-IPrange -ip $($Address[$i]) -mask $($Mask[$i]))
    $range = $($Address[$i])
    Start-Job C:\RSD\Scripts\TestMachines.ps1 -ArgumentList $ips,$range
}

While(Get-Job -State Running){
    Write-Host "Still running will check again in 30 secs"
    Start-Sleep -Seconds 30
}
Write-Host "Complete"
Pause