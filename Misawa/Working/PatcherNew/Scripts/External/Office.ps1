$computers = $args[0..($args.count -1)]
Import-Module C:\Working\PatcherNew\Scripts\Internal\Functions.ps1
foreach($computer in $computers)
{
            xcopy /y /e /i C:\Working\PatcherNew\Patches\Updates \\$computer\c$\PatcherNew\Patches\Updates
            PSOffice
            LOG
            Remove-Item -Force -Recurse \\$computer\c$\PatcherNew -ErrorAction SilentlyContinue
}