$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            $line1 = $Computer
            $line2 = PsExec -accepteula \\$Computer /S "C:\Program Files\Common Files\McAfee\SystemCore\csscan.exe" -Versions 
            $line3 = "----------"
            $line4 = " "
            $line1, $line2, $line3, $line4 | Out-File -Append C:\Working\PatcherNew\Results\McAfeeInfo.txt
}