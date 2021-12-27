$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            xcopy /y /e /i /j C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
            PSUpdate
            LOG
            Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
}