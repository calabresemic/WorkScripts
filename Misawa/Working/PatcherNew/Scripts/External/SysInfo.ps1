$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers){
$SysInfo = Test-Path \\$Computer\c$
If ($SysInfo -eq $True){
            $line1 = PsInfo -d \\$Computer
            $line2 = "----------" 
            $line3 = " "
            $line1, $line2, $line3 | Out-File -Append C:\Working\PatcherNew\Results\SysInfo.txt
          } 
          Else{
            $line1 = " "
            $line2 = "Could not connect to $Computer..."
            $line3 = "----------"
            $line4 = " "
            $line1, $line2, $line3, $line4 | Out-File -Append C:\Working\PatcherNew\Results\SysInfo.txt
}
}
Write-Host "Check the following location for the results: C:\Working\PatcherNew\Results\SysInfo.txt"