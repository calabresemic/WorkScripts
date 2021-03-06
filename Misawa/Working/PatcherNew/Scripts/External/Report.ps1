$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
      Try{$hotfix = Get-WmiObject win32_quickfixengineering -ComputerName $Computer -ErrorAction Stop -WarningAction Stop -InformationAction Stop | Select CSName,Description,HotFixID,InstalledBy,InstalledOn | Where {$_.InstalledOn -gt ((Get-Date).adddays(-30))}
      }

      Catch{$hotfix = New-Object PSObject -Property @{ Description=$_; CSName=$computer }
      }

                do{
             $done = $true
             try{
                $hotfix | Export-Csv -NoTypeInformation -Append C:\Working\PatcherNew\Results\InstallResults.csv
             }
             Catch{
                $done = $false
                Start-Sleep -Milliseconds $(Get-Random -Minimum 1000 -Maximum 10000)
             }
          }until($done)
}