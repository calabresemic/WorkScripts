$computers = $args[0..($args.count -1)]
$computers.count
$results = @()
$name = Get-Content C:\Working\PatcherNew\Var\service.txt
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers){
Try{
Set-Service -ComputerName $computer -Name $name -StartupType Automatic -Status Running -WarningAction Stop -ErrorAction Stop -InformationAction Stop
$o = New-Object PSObject -Property @{ Computer=$computer; Result="Started" }
$results += ,$o
}
Catch{
$o = New-Object PSObject -Property @{ Computer=$computer; Result=$_.Exception.message }
$results += ,$o
}}
$results | Export-Csv -NoTypeInformation -Append C:\Working\PatcherNew\Results\ServceResults.csv