$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            PsExec -accepteula \\$computer /s /f /c 'C:\Working\PatcherNew\Scripts\External\McUpdate.bat'
            LOG
}  